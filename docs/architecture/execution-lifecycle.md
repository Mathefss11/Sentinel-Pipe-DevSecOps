# Scan execution lifecycle

Applies from Milestone 3, Phase 1 (Flyway `V007`, results and evidence `V008`). Decision
records: [ADR-0007](../adr/0007-database-authoritative-execution-leases.md),
[ADR-0008](../adr/0008-result-integrity-and-evidence.md). Roles and privileges:
[database roles runbook](../runbooks/database-roles.md). Operations:
[execution runbook](../runbooks/execution.md).

## 1. Components and trust boundaries

```text
 user ──HTTPS/JWT──▶ API (sentinel_api_app)                 worker (sentinel_worker_app)
                      │ create scan, plan jobs (INSERT)        │
                      │ cancel ─┐                              │ claim / heartbeat / report
                      │ supervisor pass ─┐                     │
                      ▼          ▼       ▼                     ▼
              ┌──────────────────────────────────────────────────────────┐
              │ PostgreSQL: lifecycle.* (API)      worker.* (worker)      │
              │   SECURITY DEFINER functions owned by sentinel_owner      │
              │   scans, scan_jobs, lifecycle.job_reports,                │
              │   lifecycle.execution_events (append-only)                │
              └──────────────────────────────────────────────────────────┘
```

- **The API** creates scans and plans jobs. It changes execution state only through
  `lifecycle.cancel_scan`, `lifecycle.fail_scan`, `lifecycle.supervise`,
  `lifecycle.complete_evaluation` (INCOMPLETE without a policy only, since V009) and
  `policy.record_evaluation` (ADR-0013), and has no UPDATE privilege on lifecycle columns.
- **Workers** have no table privileges. Their only interface to execution is
  `worker.claim_job`, `worker.heartbeat_job`, `worker.put_evidence` and
  `worker.submit_result` (plus `worker.record_receipt` for message receipts).
- **Evidence** lives in the `evidence` schema, content-addressed per organization. The
  API reads it only through `evidence.list_result_artifacts` and
  `evidence.read_result_artifact` and verifies every byte again (`EvidenceStore`).
- **No HTTP endpoint** exposes claiming, heartbeats, results, recovery or evaluation. The
  only user-facing transition is cancellation.

## 2. State machines

```text
Scan:  QUEUED ──first claim──▶ RUNNING ──all jobs terminal──▶ EVALUATING ──decision──▶ COMPLETED
         │                       │ deadline                     │
         ├─cancel / fail─────────┴─cancel / fail / deadline─────┴─cancel / fail──▶ CANCELLED | FAILED

Job:   QUEUED ──claim──▶ RUNNING ──report COMPLETED──▶ COMPLETED
         ▲                 │ report FAILED (retryable) or lease expired, attempts < 3
         └─────────────────┤ (backoff 10 s, 20 s)
                           ├─ final failure, 3rd attempt, or deadline ──▶ FAILED
         (any unfinished job) ── cancel ──▶ CANCELLED        (deadline ──▶ FAILED)
```

| Scan status | Security decision | `decisionReason` |
|---|---|---|
| QUEUED, RUNNING, EVALUATING | PENDING | null |
| COMPLETED | PASS, FAIL or INCOMPLETE (scan pinned to a policy; an evaluation record explains it) | POLICY_EVALUATED |
| COMPLETED | INCOMPLETE (scan without a policy) | POLICY_EVALUATION_UNAVAILABLE (all jobs completed) or SCANNER_EXECUTION_INCOMPLETE (a job failed or was cancelled) |
| FAILED | INCOMPLETE | EXECUTION_DEADLINE_EXCEEDED or EXECUTION_FAILED |
| CANCELLED | INCOMPLETE | CANCELLED_BY_USER |

`PASS` requires every job `COMPLETED` **and** a recorded policy evaluation of valid,
sufficiently complete evidence (M4 Phase 1, [ADR-0013](../adr/0013-security-policy-engine.md),
[decision semantics](policy-decision-semantics.md)). A scan is pinned to the policy version
in force for its project when it is requested; without one it can never pass.

## 3. Worker protocol

```text
worker                                   PostgreSQL
  │ claim_job(['FIXTURE'])  ───────────▶ lock scan (SKIP LOCKED), lock job
  │                                      attempt+1, epoch+1, owner=session_user,
  │                                      token hash, expiry; scan RUNNING + deadline
  │ ◀──── job, scan, project, org, commit, repository, epoch, token (once), expiry
  │
  │ every lease/4:  heartbeat_job(job, epoch, token)
  │ ◀──── RENEWED (new expiry) | CANCELLED | DEADLINE_EXCEEDED | LEASE_LOST
  │        (anything but RENEWED: stop executing; do not report)
  │
  │ put_evidence(job, epoch, token, name, media type, bytes)   (0..16 times)
  │ ◀──── STORED | DUPLICATE (sha256 and size computed by PostgreSQL) | CONFLICT | REJECTED_*
  │        worker compares the digest with its own; never references a mismatch
  │
  │ submit_result(token, canonical job-result.v1 bytes)
  │ ◀──── ACCEPTED | DUPLICATE | CONFLICT | REJECTED_*
```

Result checks, in order (one transaction):
1. The document is valid job-result.v1 (otherwise SQLSTATE 22023), or answered
   `REJECTED_UNSUPPORTED_SCHEMA_VERSION` for another version.
2. The job exists.
3. The scan id matches.
4. An earlier report for this lease exists. If so, the call is DUPLICATE (identical bytes)
   or CONFLICT, but only when it comes from the same owner with the same token.
5. The epoch is current, the owner is `session_user`, and the token hash matches.
6. The job is RUNNING, the lease has not expired, and the deadline has not passed.
7. The project, organization, commit, scanner type and attempt match the authoritative
   rows (`CONTEXT_MISMATCH` otherwise).
8. Every referenced artifact was uploaded under this job and epoch, with exactly the
   recorded digest, size and media type (`MISSING_ARTIFACT` or `ARTIFACT_MISMATCH`
   otherwise).

Refusals are counted per (job, epoch bucket, login, operation, reason). Only the first
occurrence writes an execution event.

## 4. Failure modes

| Situation | Behavior |
|---|---|
| Duplicate claim attempts | `FOR UPDATE SKIP LOCKED` under the scan lock: exactly one claim per job and epoch |
| Duplicate or replayed report | `DUPLICATE` (same owner, token and outcome), no effect |
| Contradictory report | `CONFLICT`, no effect, audited `REPORT_CONFLICT` |
| Stale worker after reclaim | `REJECTED_STALE_EPOCH`; heartbeat `LEASE_LOST` |
| Stolen token used by another worker login | `REJECTED_NOT_LEASE_OWNER` |
| Forged token or epoch | `REJECTED_TOKEN_MISMATCH` / `REJECTED_UNKNOWN_EPOCH` |
| Lease used for another tenant's scan or job | `REJECTED_SCAN_MISMATCH` / `REJECTED_TOKEN_MISMATCH` |
| Malformed arguments | SQLSTATE `22023` before any row is read or locked |
| Worker crash or hang | No heartbeats; the supervisor reclaims the job after expiry (requeue with backoff, or FAILED `LEASE_EXPIRED` on the 3rd attempt) |
| Database outage during execution | Heartbeats retried; the executor stops half an interval before the lease would expire (`LEASE_UNCERTAIN`); reports retried 5 times while the lease is valid |
| Ambiguous commit of a report | The retry resubmits identical bytes and returns `DUPLICATE` |
| Forged or altered digest in a result | `REJECTED_ARTIFACT_MISMATCH`: only digests computed by the database count |
| Evidence of another tenant, job or attempt referenced | `REJECTED_MISSING_ARTIFACT`: references resolve only within the same job and lease |
| Stored evidence altered | Refused by the integrity CHECK on write; re-verified on every read (`EvidenceIntegrityException`) |
| Evidence storage unavailable or refusing | Uploads retried; then `FAILED EVIDENCE_UNAVAILABLE` (retried on another attempt) |
| Oversized or malformed result or evidence | SQLSTATE `22023` before any row is read; the content is never echoed |
| Repeated refused submissions | Counted in `lifecycle.report_rejections`; one audit event per key |
| Worker shutdown (SIGTERM) | Executor stopped; `FAILED WORKER_SHUTDOWN` (retried elsewhere) |
| Deadline (15 min) passed | Scan FAILED / INCOMPLETE; unfinished jobs FAILED; late heartbeats and reports refused |
| Cancellation while running | Jobs CANCELLED at once; the worker sees `CANCELLED` within one heartbeat; its report is rejected |
| Concurrent supervisors | Rows locked by another pass are skipped and handled by the next pass; each expiry is applied once |
| API host clock ahead of the database | Lifecycle timestamps are raised to the row's `updated_at`; expiry uses only the database clock |

## 5. Sandboxed execution (ADR-0009)

```text
worker (trusted: lease, credentials, Docker CLI)
  │ docker run --network none --read-only --user 65534 --cap-drop ALL
  │            --security-opt no-new-privileges --pids-limit --memory --cpus --pull never
  ▼
sandbox (untrusted, one per attempt) ──stdout: sandbox-output.v1 (bounded)──▶ worker
  └ stop event (cancel / lease lost / deadline / shutdown) or time limit ──▶ docker kill + rm
```

- The lease keeper and the sandbox share one stop event, so a cancelled or lost lease
  kills the container within one heartbeat interval. Its result is never reported, and the
  database would refuse it anyway.
- Evidence leaves the sandbox only as data in the stdout envelope, then goes through the
  verified evidence path (section 3).
- Containers are removed after every outcome. Containers orphaned by a crashed worker are
  reaped once their expiry label passes.
- Threat model: [execution sandbox](../threat-model/execution-sandbox.md).

## 6. Configuration

API (`sentinel.execution.*`, validated at startup):

| Property | Default | Bounds |
|---|---|---|
| `lease-duration` | 60s | 15s–10m, whole seconds |
| `execution-timeout` | 15m | 1m–24h, ≥ 2 × lease |
| `planned-scanners` | `[]` | only `FIXTURE` is executable in this version |
| `fixture-enabled` | false | refused under `prod`/`production` profiles |
| `supervisor.enabled` / `interval` / `batch-size` | true / 5s / 100 | 1s ≤ interval ≤ lease; 1–1000 |

The lease and timeout are copied onto each scan when it is requested.

Worker (`sentinel-worker execute`):
- `SENTINEL_WORKER_DB_*` (its own login);
- `SENTINEL_WORKER_FIXTURE_ENABLED` (refused in `production`), `SENTINEL_WORKER_FIXTURE_SECONDS`
  and `SENTINEL_WORKER_FIXTURE_MODE`;
- `SENTINEL_WORKER_FIXTURE_EXECUTOR` (`sandbox` by default, or `inline`);
- `SENTINEL_WORKER_EXECUTION_POLL_SECONDS`;
- sandbox limits: `SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS`, `_MEMORY_MB`, `_CPUS`,
  `_PIDS` and `_RUNTIME`;
- `SENTINEL_WORKER_DOCKER_CLI`.

## 7. Not yet implemented

- Real scanners and fetching repository content. The sandbox exists (ADR-0009), but with
  runc it does not withstand hostile code that attacks the kernel. A stronger runtime or
  per-job VMs are required before untrusted code runs.
- Proof that evidence came from an honest scanner run (attestation, provenance) and an
  S3-compatible evidence backend for large artifacts. See ADR-0008, "Guarantees and their
  limits".
- Security exceptions and remediation reports (later M4 slices). Policy
  evaluation exists since M4 Phase 1 (ADR-0013), non-gating historical re-evaluation since
  M4 Phase 2 (ADR-0014, proposed).
- Per-attempt execution time limits inside the sandbox. The scan-level hard deadline is
  enforced.

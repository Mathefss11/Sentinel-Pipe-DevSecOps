# Runbook: scan execution (leases, supervisor, cancellation)

Applies from Milestone 3, Phase 1 (Flyway `V007`). Design:
[execution lifecycle](../architecture/execution-lifecycle.md),
[ADR-0007](../adr/0007-database-authoritative-execution-leases.md).

## 1. Running a worker

No real scanner is executable yet. Only the harmless `FIXTURE` executor exists, so
execution is for development and CI only. It runs in a sandbox container by default
(ADR-0009), which needs Docker on the worker host and the pinned sandbox image provisioned
beforehand. Images are never pulled at execution time:

```powershell
docker pull alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
.\.venv\Scripts\sentinel-worker.exe sandbox-check   # verifies 13 isolation controls from inside a sandbox
```

```powershell
# API: allow the fixture and plan it for every new scan (never with a prod profile)
$env:SENTINEL_EXECUTION_FIXTURE_ENABLED = "true"
$env:SENTINEL_EXECUTION_PLANNED_SCANNERS = "FIXTURE"

# Worker: its own database login (see the database roles runbook)
$env:SENTINEL_WORKER_FIXTURE_ENABLED = "true"
Set-Location services\sentinel-worker
.\.venv\Scripts\sentinel-worker.exe execute --idle-timeout 60
```

The worker prints one JSON summary at exit (`claimed`, `reported`, `abandoned`,
`rejected`, `unreported`). It never prints lease tokens or passwords. `Ctrl+C` or
SIGTERM stops the current job and reports `WORKER_SHUTDOWN`, which the control plane
retries on another worker.

## 2. Monitoring

API metrics (Prometheus, see the [observability runbook](observability.md)):

| Metric | Meaning | Look at |
|---|---|---|
| `sentinel_execution_leases_expired_total` | Leases reclaimed from workers that stopped heartbeating | sustained growth: crashing, hung or partitioned workers |
| `sentinel_execution_deadlines_exceeded_total` | Scans failed by the hard deadline | any growth: too few workers, stuck jobs, or a timeout set too low |
| `sentinel_execution_scans_evaluated_total` | Decisions recorded by the supervisor | flat while scans finish: supervisor disabled or failing |
| `sentinel_execution_jobs{status}` | Jobs `queued`, `running`, `retry_pending` | growing queue: too few workers; growing retries: failing executions |
| `sentinel_execution_running_oldest_seconds` | Age of the oldest running attempt | close to the deadline (900 s): stuck jobs |
| `sentinel_execution_rejections_results{reason}`, `sentinel_execution_rejections_evidence{reason}` | Refused results and uploads recorded in the database | any `TOKEN_MISMATCH`, `NOT_LEASE_OWNER`, `CONTEXT_MISMATCH`, `ARTIFACT_MISMATCH` or `MISSING_ARTIFACT`: investigate (section 3) |
| `sentinel_evidence_purged_total` | Evidence contents removed by retention | — |

Worker metrics (`SENTINEL_WORKER_METRICS_PORT`, loopback only):
`sentinel_worker_job_claims_total{outcome}`, `sentinel_worker_heartbeats_total{status}`,
`sentinel_worker_job_results_total{outcome}`, `sentinel_worker_job_runs_total{outcome}`,
`sentinel_worker_evidence_uploads_total{outcome}` and
`sentinel_worker_job_execution_seconds{scanner_type}`. Labels are closed enumerations.
Identifiers, tokens and evidence never appear in metrics or logs.

The supervisor logs `execution.supervised` when a pass changed something, and
`execution.supervisor_failed error_type=...` when a pass failed (for example, the database
was unavailable). The next pass retries, and nothing is lost: expiry and deadlines are
evaluated against the database clock.

## 3. Inspecting a scan

As the administrator (or with the API login, which may read the audit trail):

```sql
-- State of a scan and its jobs (no tokens are stored; only their SHA-256)
SELECT s.execution_status, s.security_decision, s.decision_reason, s.started_at, s.deadline_at,
       j.scanner_type, j.execution_status AS job_status, j.attempt_count, j.lease_epoch,
       j.lease_owner, j.lease_expires_at, j.next_attempt_at, j.failure_reason
FROM scans s LEFT JOIN scan_jobs j ON j.scan_id = s.id
WHERE s.id = '<scan id>';

-- Audit trail (append-only)
SELECT occurred_at, event_type, actor_type, actor, lease_epoch, detail
FROM lifecycle.execution_events WHERE scan_id = '<scan id>' ORDER BY id;

-- Refused results and uploads in the last day, with repeat counts (possible stale or
-- compromised worker). One audit event is written per key; repeats only count here.
SELECT actor, operation, detail, sum(occurrences), min(first_at), max(last_at)
FROM lifecycle.report_rejections WHERE last_at > now() - interval '1 day'
GROUP BY 1, 2, 3 ORDER BY 4 DESC;

-- Evidence of record of a job (digests computed by PostgreSQL; content not shown)
SELECT * FROM evidence.list_result_artifacts('<job id>');
```

| Rejection detail | Usual cause | Action |
|---|---|---|
| `STALE_EPOCH`, `LEASE_EXPIRED`, `JOB_NOT_RUNNING` | Slow or partitioned worker, or a cancelled job | none if occasional; otherwise check worker health and the database latency |
| `DEADLINE_EXCEEDED` | Job ran past the hard deadline | check the timeout and the scanner's duration |
| `TOKEN_MISMATCH`, `UNKNOWN_EPOCH`, `NOT_LEASE_OWNER`, `SCAN_MISMATCH`, `CONTEXT_MISMATCH` | Bug, or forged or stolen credentials | **treat as a security incident**: identify the `actor` login, rotate its password, review its host |
| `ARTIFACT_MISMATCH`, `MISSING_ARTIFACT` | A result referenced evidence the database did not verify for this lease (forged digest, substituted or foreign evidence) | **treat as a security incident**, as above |
| `CONFLICT` (`REPORT_CONFLICT`) | One lease submitted two different results or uploads | worker bug or tampering; investigate the actor |
| `QUOTA_EXCEEDED` | More than 16 artifacts or 8 MiB under one lease | executor bug; the attempt fails with `EVIDENCE_UNAVAILABLE` and is retried |

## 4. Common situations

- **Scan stuck in QUEUED.** No worker supports its scanner types, no worker is running,
  or the scan has no jobs (`planned-scanners` is empty). A scan without jobs is never
  started.
- **Scan stuck in RUNNING.** A worker holds a live lease (heartbeats continue), or a job
  waits for its retry backoff. The hard deadline (15 minutes by default) ends it at the
  latest.
- **Scan stuck in EVALUATING.** The supervisor is disabled (`sentinel.execution.supervisor.enabled`)
  or failing; check its logs. Evaluation is idempotent.
- **Cancelling a scan.** `POST /api/v1/projects/{projectId}/scans/{scanId}/cancel` as a
  MEMBER or above. Running workers stop at their next heartbeat (within 15 s by default).
- **Do not edit lifecycle rows by hand.** No runtime role can, and manual changes bypass the
  fencing and the audit trail. If an incident requires a correction, use
  `lifecycle.fail_scan` or `lifecycle.cancel_scan` as the API login, and record why.

## 5. Sandboxes

| Variable | Default | Bounds | Meaning |
|---|---|---|---|
| `SENTINEL_WORKER_FIXTURE_EXECUTOR` | `sandbox` | `sandbox`, `inline` | `inline` runs the fixture in process (`success` mode only) |
| `SENTINEL_WORKER_FIXTURE_MODE` | `success` | see ADR-0009 | Deterministic failure modes for tests and drills |
| `SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS` | 300 | 1–900 | Per attempt; also capped by the scan's deadline minus 5 s |
| `SENTINEL_WORKER_SANDBOX_MEMORY_MB` | 256 | 16–4096 | No swap |
| `SENTINEL_WORKER_SANDBOX_CPUS` | 1 | 0.1–4 | |
| `SENTINEL_WORKER_SANDBOX_PIDS` | 64 | 16–1024 | |
| `SENTINEL_WORKER_SANDBOX_RUNTIME` | runc | `runsc`, `kata-runtime`, `kata` | Stronger isolation (gVisor, Kata); must be installed on the host |
| `SENTINEL_WORKER_DOCKER_CLI` | `docker` on `PATH` | absolute path | The only executable the worker starts |

- **Inspect sandboxes:**
  `docker ps --all --filter label=sentinelpipe.sandbox=1`. The labels include the job
  (`sentinelpipe.job`) and the expiry (`sentinelpipe.expires-at`, Unix time).
- **Leftovers** come from a crashed worker. They are removed by the next worker on that
  host once they expire (timeout plus 60 s). Removing them by hand
  (`docker rm --force <name>`) is safe: their leases are fenced and expire.
- **`sandbox-check` reports unhealthy:** do not run workers on that host. The report
  names the failing control (for example `no_network`). Typical causes are a modified
  Docker daemon configuration or a runtime without cgroups v2.
- **Failure reasons:**
  - `RESOURCE_LIMIT_EXCEEDED` or `EXECUTION_TIMEOUT` repeating for one scanner: raise the
    limits only after reviewing why.
  - `SANDBOX_ERROR` across all jobs: the runtime or the image is unavailable.
- **Logs** contain sandbox status, exit code, duration, peak PIDs and memory, and stderr
  size. They never contain stdout or evidence.

## 6. Evidence retention

Evidence content is kept for `sentinel.execution.evidence-retention` (default 90 days,
copied onto each scan) after upload, then purged by the supervisor in bounded batches.
Digests, sizes, bindings and accepted results remain; purged artifacts are listed as
`purged` and cannot be read. Evidence cannot be modified or deleted by any runtime role.
A CHECK constraint refuses content that does not match its digest, and the API verifies
bytes again on every read (`EvidenceIntegrityException`, logged as
`evidence.integrity_violation`; treat as an incident).

## 7. Changing limits

`sentinel.execution.lease-duration` (15 s–10 min) and `execution-timeout` (1 min–24 h,
at least twice the lease) apply to scans requested **after** the change. Each scan keeps
the values it was created with. Workers derive their heartbeat interval (a quarter of the
lease) from the claim.

# ADR-0007: Database-authoritative execution lifecycle with fenced leases

- **Status:** Accepted (2026-10-10, after review of the Slice 2 implementation)
- **Date:** 2026-10-10
- **Amended by:** [ADR-0008](0008-result-integrity-and-evidence.md). Results are submitted as
  `job-result.v1` documents with `worker.submit_result`, which replaced
  `worker.report_job`. Evidence is uploaded with `worker.put_evidence`.
- **Milestone:** M3 Phase 1 (Slice 2)
- **Builds on:** [ADR-0005](0005-shared-receipts-tenant-verification-and-least-privilege.md)
  (verified worker receipts), [ADR-0006](0006-database-privilege-separation.md)
  (least-privileged database roles)

## Context

M3 starts executing scan jobs on workers. The control plane must:

- hand each job to exactly one worker at a time, and recover jobs of crashed, hung or
  partitioned workers;
- bound retries and total execution time;
- let users cancel scans;
- accept results only from the worker that legitimately holds the job, never from a stale
  worker or from another tenant's lease, and stay correct under redelivery and retries;
- keep execution status separate from the security decision. Finishing execution must never
  produce `PASS`.

Workers are a separate trust zone: they will execute untrusted repository content in
sandboxes (Slice 4), so a compromised worker must not be able to change jobs it does not
hold. The API is also untrusted with respect to execution evidence: after ADR-0006 it
holds DML privileges, and an API compromise should not be able to fabricate completed
jobs or a `PASS`.

## Decision

1. **PostgreSQL is the single authority for execution state.** All transitions of scans
   and jobs after creation are performed by `SECURITY DEFINER` functions owned by the
   non-superuser `sentinel_owner` (Flyway V007). They implement one documented state machine
   for both the Java control plane and the Python workers, under one locking protocol
   (scan row, then job rows; heartbeats lock only the job row), so there is no deadlock
   between them. The API loses `UPDATE` on every lifecycle column and keeps `INSERT`
   (creation, planning) and the idempotency-key columns.

2. **Leases with fencing.** `worker.claim_job` atomically claims a job (`FOR UPDATE SKIP
   LOCKED`) and returns:
   - a 244-bit random lease token, returned once; only its SHA-256 is stored;
   - a fencing **epoch** that increases with every claim;
   - an expiry. Defaults: 60 s lease, renewed by heartbeats every 15 s (a quarter of
     the lease);
   - the authoritative scan, project, organization, commit and repository.

   Every heartbeat and report must match the lease owner (`session_user`, the worker's own
   database login), the token hash and the epoch. An expired lease is never revived, even
   before the supervisor reclaims it.

3. **Worker authentication is the database login, not the payload.**
   - Each worker deployment uses its own PostgreSQL login, a member of `sentinel_worker`
     (EXECUTE on four functions; no table access). This is separate from the API and
     migration credentials.
   - Identifiers in queue messages are never used for authorization. The worker uses only
     the values returned by `claim_job`.
   - Reports carry the scan id only as a cross-check. A mismatch is rejected and audited.

4. **Idempotent, fenced reports.** `worker.report_job` records at most one accepted report
   per lease (`lifecycle.job_reports`, primary key `(job_id, lease_epoch)`):
   - the same report again returns `DUPLICATE`, including after the job was reclaimed, so
     retrying an ambiguous commit is safe;
   - a different outcome for the same lease returns `CONFLICT`;
   - stale epochs, unknown epochs, foreign tokens, other worker logins, expired leases,
     non-running jobs and passed deadlines are rejected (`REJECTED_*`).

   Rejections and conflicts are audited. The control plane, not the worker, decides
   whether a failure is retried:
   - `SCANNER_ERROR`, `SANDBOX_ERROR`, `WORKER_SHUTDOWN` and expired leases are retried with
     a backoff (10 s, 20 s) while attempts remain (maximum 3);
   - `EXECUTION_TIMEOUT`, `RESOURCE_LIMIT_EXCEEDED` and `UNSUPPORTED_SCANNER` are final.

5. **Supervisor in the API.** A scheduled pass (default every 5 s, safe on several
   instances) calls `lifecycle.supervise`:
   - RUNNING scans past their **hard deadline** (default 15 minutes after the first claim)
     FAIL, decision `INCOMPLETE`, and their unfinished jobs FAIL;
   - expired leases are reclaimed.

   It then evaluates EVALUATING scans.

6. **Explicit evaluation step.** A scan whose jobs are all terminal moves to the new
   `EVALUATING` state; `lifecycle.complete_evaluation` records the decision with a
   mandatory `decision_reason`. Fail closed:
   - `PASS` requires every job `COMPLETED` and an actual policy evaluation
     (`POLICY_EVALUATED`);
   - until the policy engine exists (M4), every evaluation is `COMPLETED` / `INCOMPLETE`,
     with reason `POLICY_EVALUATION_UNAVAILABLE` or `SCANNER_EXECUTION_INCOMPLETE`.

7. **Cancellation.**
   - `POST /api/v1/projects/{projectId}/scans/{scanId}/cancel` (MEMBER and above,
     tenant-checked, idempotent) calls `lifecycle.cancel_scan` with the caller's server-side
     identity.
   - Unfinished jobs are cancelled immediately.
   - A running worker learns this on its next heartbeat, stops, and its report is rejected.

8. **Append-only audit trail.** `lifecycle.execution_events` records every claim, report,
   retry, expiry, failure, cancellation, evaluation and refused report: actor type, actor
   (database login or user identity), epoch and a sanitized code. No role other than the
   owner can write it; the API can read it. Tokens are never stored or logged.

9. **No PLANNING state yet.** Jobs are planned in the scan-creation transaction
   (`sentinel.execution.planned-scanners`). A separate PLANNING state will be added when
   repository discovery becomes asynchronous.

10. **Harmless fixture.**
    - `FIXTURE` is a scanner type that executes nothing and reads no repository content.
      It exercises the lifecycle and, in Slice 4, the sandbox.
    - It is plannable only with `sentinel.execution.fixture-enabled=true`. The API refuses
      to start with that setting under a `prod`/`production` profile, and the worker
      refuses it in the `production` environment.
    - It is the only scanner the worker can execute in this version.

## Consequences

- Stale or compromised workers cannot overwrite newer results, forge results for jobs
  they do not hold, or affect other tenants' jobs. A compromised worker can still report
  false outcomes for jobs it legitimately holds. Evidence integrity (result digests,
  provenance, signed artifacts) is Slice 3/M5 work.
- An API compromise can no longer mark jobs completed or skip execution. It can still
  cancel or fail scans, and call `complete_evaluation`: once a scan is EVALUATING with all
  jobs completed, the API could record `PASS`. Protecting the decision itself requires
  policy evaluation with auditable evidence (M4).
- Correctness does not depend on clocks across hosts: lease expiry and deadlines use the
  database clock only, and timestamps never move backwards across the Java/PostgreSQL
  boundary.
- Recovery time after a worker crash is bounded by the lease (60 s) plus one supervisor
  interval (5 s), plus the retry backoff.
- Cancellation is observed by a running worker within one heartbeat interval (15 s by
  default). The sandbox kill on cancellation arrives with Slice 4.
- The execution state machine lives in PL/pgSQL. This concentrates security-critical
  logic in one reviewed place, but it is less familiar than Java. Every function is covered
  by integration, concurrency and privilege tests against real PostgreSQL. The Java enums
  document the same transition matrix.
- Workers poll `claim_job` (default every 5 s). RabbitMQ delivery remains the verified
  notification and receipt path (ADR-0005). The database, not the queue, decides who
  executes what.
- Existing scans and jobs that were RUNNING before V007 receive a deadline and an
  already-expired placeholder lease, so the supervisor recovers them like crashed jobs.

## Acceptance review

The decision was reviewed against the Slice 2 implementation (Flyway V007, 548 Java, 224
Python and 8 end-to-end tests) before acceptance:

- **Matches the implementation:**
  - every post-creation transition goes through the V007 functions;
  - the API has no UPDATE privilege on lifecycle columns;
  - the locking order, the token hash, the epoch and the database clock are as described;
  - the privilege tests pin which role may execute each function.
- **Why it is accepted:**
  - it gives one auditable authority for execution state shared by Java and Python;
  - it fences stale and forged workers without a new network-exposed endpoint;
  - it keeps least privilege for both the API and the workers;
  - concurrency, crash, cancellation and fencing behavior is verified against real
    PostgreSQL and the real worker process.
- **Accepted trade-offs:**
  - security-critical logic lives in PL/pgSQL;
  - workers poll for jobs;
  - cancellation latency equals the heartbeat interval;
  - a lease holder can still report false outcomes for its own job; ADR-0008 narrows this
    by binding results to database-verified evidence, but does not prove that the scanner
    ran correctly;
  - an API compromise can still record an evaluation (mitigated only by M4).
- **Superseded details:** the worker now has five functions (`record_receipt`,
  `claim_job`, `heartbeat_job`, `put_evidence`, `submit_result`), not four, and
  `report_job` no longer exists (ADR-0008).

## Alternatives considered

- **Java-side state machine with API table privileges.** Rejected: the API would need
  UPDATE on lifecycle columns, which ADR-0006 aimed to remove, and workers would need
  either table privileges or an HTTP callback API.
- **Worker HTTP callbacks with signed tokens.** Rejected for now: it needs a new
  authenticated, network-exposed endpoint and a token issuer. The database already
  authenticates workers per login. GitHub Actions OIDC will be the external identity
  in M5.
- **RabbitMQ as the job queue (ack = completion).** Rejected: broker redelivery cannot
  fence a stale consumer that is still running, and a broker has no notion of deadlines,
  bounded attempts or cancellation of in-flight work.
- **Advisory locks instead of leases.** Rejected: they are tied to a session, so an idle
  connection behind a pooler can hold a job forever, and they leave no audit trail.

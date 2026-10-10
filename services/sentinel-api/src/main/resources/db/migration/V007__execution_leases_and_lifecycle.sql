-- V007: Milestone 3, Phase 1 (Slice 2). Execution lifecycle: job leases, fencing,
-- heartbeats, supervisor, hard deadlines, evaluation hand-off and cancellation.
--
-- PostgreSQL is the single authority for scan and job execution state (ADR-0007):
--
--   * Workers claim jobs with time-bound leases (worker.claim_job), renew them with
--     heartbeats (worker.heartbeat_job) and report outcomes (worker.report_job). Every
--     call is authenticated three ways: the worker's own database login (session_user,
--     recorded as the lease owner), the lease token (random, returned once, stored only as
--     SHA-256) and a monotonic fencing epoch that increases with every claim. A worker
--     whose lease was lost can never change the job again.
--   * The API's supervisor reclaims expired leases and enforces the hard execution
--     deadline (lifecycle.supervise). A scan whose jobs are all terminal moves to
--     EVALUATING; the API's evaluation step records the security decision
--     (lifecycle.complete_evaluation). Completing execution never implies PASS.
--   * User cancellation goes through lifecycle.cancel_scan.
--
-- The API keeps INSERT on scans and jobs (creation and planning) but loses UPDATE on
-- every lifecycle column: it changes execution state only through these functions, which
-- enforce the state machine and write the append-only audit trail.
--
-- Locking protocol: every function that changes a scan or its jobs locks the scan row
-- first, then job rows. Heartbeats lock only their job row. No function waits for a scan
-- lock while holding a job lock, so the protocol cannot deadlock.
--
-- Clock: lifecycle timestamps come from the database clock, raised to the row's
-- updated_at when needed, so they never move backwards if the API host's clock is ahead.

-- ---------------------------------------------------------------------------
-- 1. Scans
-- ---------------------------------------------------------------------------

-- Defaults apply to scans created before V007; the API always supplies its configured values.
ALTER TABLE scans
    ADD COLUMN lease_duration_seconds    INTEGER     NOT NULL DEFAULT 60,
    ADD COLUMN execution_timeout_seconds INTEGER     NOT NULL DEFAULT 900,
    ADD COLUMN deadline_at               TIMESTAMPTZ,
    ADD COLUMN decision_reason           VARCHAR(40);

-- Scans started before V007 (only possible through the internal M2 lifecycle service) are
-- bounded by a deadline from their start, like new ones.
UPDATE scans
SET deadline_at = started_at + make_interval(secs => execution_timeout_seconds), version = version + 1
WHERE execution_status = 'RUNNING';

ALTER TABLE scans
    DROP CONSTRAINT ck_scans_execution_status,
    DROP CONSTRAINT ck_scans_status_decision,
    DROP CONSTRAINT ck_scans_status_timestamps,
    ADD CONSTRAINT ck_scans_execution_status
        CHECK (execution_status IN ('QUEUED', 'RUNNING', 'EVALUATING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    -- A decision is final only once execution is terminal; a scan that did not complete
    -- can never carry PASS or FAIL (fail closed).
    ADD CONSTRAINT ck_scans_status_decision CHECK (
        (execution_status IN ('QUEUED', 'RUNNING', 'EVALUATING') AND security_decision = 'PENDING')
        OR (execution_status = 'COMPLETED' AND security_decision IN ('PASS', 'FAIL', 'INCOMPLETE'))
        OR (execution_status IN ('FAILED', 'CANCELLED') AND security_decision = 'INCOMPLETE')
    ),
    ADD CONSTRAINT ck_scans_status_timestamps CHECK (
        (execution_status = 'QUEUED' AND started_at IS NULL AND completed_at IS NULL AND deadline_at IS NULL)
        OR (execution_status IN ('RUNNING', 'EVALUATING') AND started_at IS NOT NULL AND completed_at IS NULL
            AND deadline_at IS NOT NULL)
        OR (execution_status = 'COMPLETED' AND started_at IS NOT NULL AND completed_at IS NOT NULL)
        OR (execution_status IN ('FAILED', 'CANCELLED') AND completed_at IS NOT NULL)
    ),
    ADD CONSTRAINT ck_scans_lease_duration CHECK (lease_duration_seconds BETWEEN 15 AND 600),
    ADD CONSTRAINT ck_scans_execution_timeout CHECK (execution_timeout_seconds BETWEEN 60 AND 86400),
    ADD CONSTRAINT ck_scans_deadline_order CHECK (deadline_at IS NULL OR deadline_at > started_at),
    ADD CONSTRAINT ck_scans_decision_reason CHECK (
        decision_reason IS NULL
        OR (security_decision <> 'PENDING' AND decision_reason IN ('POLICY_EVALUATED',
            'POLICY_EVALUATION_UNAVAILABLE', 'SCANNER_EXECUTION_INCOMPLETE', 'EXECUTION_DEADLINE_EXCEEDED',
            'EXECUTION_FAILED', 'CANCELLED_BY_USER'))
    );

CREATE INDEX ix_scans_running_deadline ON scans (deadline_at) WHERE execution_status = 'RUNNING';
CREATE INDEX ix_scans_evaluating ON scans (updated_at, id) WHERE execution_status = 'EVALUATING';

COMMENT ON COLUMN scans.deadline_at IS 'Hard execution deadline, set when the first job is claimed.';
COMMENT ON COLUMN scans.decision_reason IS 'Why the security decision was reached (always set by V007+ transitions).';

-- ---------------------------------------------------------------------------
-- 2. Scan jobs
-- ---------------------------------------------------------------------------

ALTER TABLE scan_jobs
    ADD COLUMN lease_epoch        BIGINT      NOT NULL DEFAULT 0,
    ADD COLUMN lease_owner        VARCHAR(63),
    ADD COLUMN lease_token_sha256 CHAR(64),
    ADD COLUMN lease_expires_at   TIMESTAMPTZ,
    ADD COLUMN heartbeat_at       TIMESTAMPTZ,
    ADD COLUMN next_attempt_at    TIMESTAMPTZ,
    ADD COLUMN failure_reason     VARCHAR(40);

-- Jobs RUNNING before V007 had no lease. They receive an already-expired placeholder lease
-- (the all-zero hash matches no token), so the supervisor recovers them exactly like the
-- jobs of a crashed worker.
UPDATE scan_jobs
SET lease_epoch = 1, lease_owner = 'pre-v007', lease_token_sha256 = repeat('0', 64),
    lease_expires_at = updated_at, heartbeat_at = started_at, version = version + 1
WHERE execution_status = 'RUNNING';

ALTER TABLE scan_jobs
    DROP CONSTRAINT ck_scan_jobs_scanner_type,
    -- FIXTURE: harmless execution fixture for isolation and lifecycle tests; the API plans
    -- it only when sentinel.execution.fixture-enabled=true (never under a prod profile).
    ADD CONSTRAINT ck_scan_jobs_scanner_type
        CHECK (scanner_type IN ('SEMGREP', 'GITLEAKS', 'TRIVY', 'CHECKOV', 'SYFT', 'ZAP', 'FIXTURE')),
    ADD CONSTRAINT ck_scan_jobs_lease_epoch CHECK (lease_epoch >= 0),
    ADD CONSTRAINT ck_scan_jobs_lease CHECK (
        execution_status <> 'RUNNING'
        OR (lease_owner IS NOT NULL AND lease_token_sha256 IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_epoch >= 1)
    ),
    ADD CONSTRAINT ck_scan_jobs_lease_token
        CHECK (lease_token_sha256 IS NULL OR lease_token_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT ck_scan_jobs_next_attempt CHECK (next_attempt_at IS NULL OR execution_status = 'QUEUED'),
    -- Reason of the FAILED status, or of the last failed attempt of a requeued job.
    ADD CONSTRAINT ck_scan_jobs_failure_reason CHECK (
        failure_reason IS NULL OR failure_reason IN ('LEASE_EXPIRED', 'SCANNER_ERROR', 'SANDBOX_ERROR',
            'EXECUTION_TIMEOUT', 'RESOURCE_LIMIT_EXCEEDED', 'UNSUPPORTED_SCANNER', 'WORKER_SHUTDOWN',
            'EXECUTION_DEADLINE_EXCEEDED')
    );

CREATE INDEX ix_scan_jobs_queued ON scan_jobs (scan_id) WHERE execution_status = 'QUEUED';
CREATE INDEX ix_scan_jobs_running_lease ON scan_jobs (lease_expires_at) WHERE execution_status = 'RUNNING';

COMMENT ON COLUMN scan_jobs.lease_epoch IS 'Fencing token: incremented by every claim; stale epochs are rejected.';
COMMENT ON COLUMN scan_jobs.lease_owner IS 'Database login (session_user) of the worker holding or last holding the lease.';
COMMENT ON COLUMN scan_jobs.lease_token_sha256 IS 'SHA-256 of the lease token; the token itself is never stored.';

-- ---------------------------------------------------------------------------
-- 3. Lifecycle schema: audit trail, report idempotency, internal helpers
-- ---------------------------------------------------------------------------

CREATE SCHEMA lifecycle;
REVOKE ALL ON SCHEMA lifecycle FROM PUBLIC;

-- Correction to V005/V006: a per-schema ALTER DEFAULT PRIVILEGES ... REVOKE cannot remove
-- PostgreSQL's built-in EXECUTE-to-PUBLIC default for functions; only the global form can.
-- Every function below is also revoked explicitly.
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Append-only audit trail of execution state changes and refused worker reports. Written
-- only by the functions in this migration (no role has INSERT, UPDATE or DELETE).
-- Identifiers come from authoritative rows; detail is a sanitized code.
CREATE TABLE lifecycle.execution_events (
    id          BIGINT       GENERATED ALWAYS AS IDENTITY,
    scan_id     UUID         NOT NULL,
    job_id      UUID,
    event_type  VARCHAR(40)  NOT NULL,
    actor_type  VARCHAR(20)  NOT NULL,
    actor       VARCHAR(100),
    lease_epoch BIGINT,
    detail      VARCHAR(40),
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_execution_events PRIMARY KEY (id),
    CONSTRAINT fk_execution_events_scan FOREIGN KEY (scan_id) REFERENCES public.scans (id) ON DELETE RESTRICT,
    CONSTRAINT fk_execution_events_job FOREIGN KEY (job_id) REFERENCES public.scan_jobs (id) ON DELETE RESTRICT,
    CONSTRAINT ck_execution_events_type CHECK (event_type IN ('SCAN_STARTED', 'SCAN_EVALUATING',
        'SCAN_COMPLETED', 'SCAN_FAILED', 'SCAN_CANCELLED', 'JOB_CLAIMED', 'JOB_COMPLETED', 'JOB_RETRY_SCHEDULED',
        'JOB_FAILED', 'JOB_CANCELLED', 'JOB_LEASE_EXPIRED', 'REPORT_REJECTED', 'REPORT_CONFLICT')),
    CONSTRAINT ck_execution_events_actor_type CHECK (actor_type IN ('WORKER', 'SUPERVISOR', 'USER', 'SYSTEM')),
    CONSTRAINT ck_execution_events_detail CHECK (detail IS NULL OR detail ~ '^[A-Z0-9_]{1,40}$')
);

CREATE INDEX ix_execution_events_scan ON lifecycle.execution_events (scan_id, id);

COMMENT ON TABLE lifecycle.execution_events IS 'Append-only audit trail of scan and job execution.';

-- At most one accepted report per lease: the idempotency record for worker.report_job.
CREATE TABLE lifecycle.job_reports (
    job_id             UUID        NOT NULL,
    lease_epoch        BIGINT      NOT NULL,
    lease_owner        VARCHAR(63) NOT NULL,
    lease_token_sha256 CHAR(64)    NOT NULL,
    outcome            VARCHAR(20) NOT NULL,
    failure_reason     VARCHAR(40),
    reported_at        TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_job_reports PRIMARY KEY (job_id, lease_epoch),
    CONSTRAINT fk_job_reports_job FOREIGN KEY (job_id) REFERENCES public.scan_jobs (id) ON DELETE RESTRICT,
    CONSTRAINT ck_job_reports_outcome CHECK (outcome IN ('COMPLETED', 'FAILED')),
    CONSTRAINT ck_job_reports_failure CHECK ((outcome = 'COMPLETED') = (failure_reason IS NULL))
);

COMMENT ON TABLE lifecycle.job_reports IS 'Accepted worker reports, one per lease epoch (idempotency).';

CREATE FUNCTION lifecycle.log_event(p_scan_id UUID, p_job_id UUID, p_event_type TEXT, p_actor_type TEXT,
    p_actor TEXT, p_lease_epoch BIGINT, p_detail TEXT)
RETURNS VOID
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $fn$
    INSERT INTO lifecycle.execution_events (scan_id, job_id, event_type, actor_type, actor, lease_epoch, detail)
    VALUES (p_scan_id, p_job_id, p_event_type, p_actor_type, left(p_actor, 100), p_lease_epoch, p_detail);
$fn$;

-- Delay before a failed attempt is retried: 10 s after the first attempt, 20 s after the second.
CREATE FUNCTION lifecycle.retry_delay(p_attempt INTEGER)
RETURNS INTERVAL
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT make_interval(secs => 10 * power(2, greatest(p_attempt, 1) - 1));
$fn$;

-- Moves a RUNNING scan whose jobs are all terminal to EVALUATING. The caller holds the
-- scan row lock. Evaluation (the security decision) is a separate step.
CREATE FUNCTION lifecycle.settle_scan(p_scan_id UUID, p_now TIMESTAMPTZ, p_actor_type TEXT, p_actor TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    UPDATE public.scans s
       SET execution_status = 'EVALUATING', updated_at = greatest(p_now, s.updated_at), version = s.version + 1
     WHERE s.id = p_scan_id
       AND s.execution_status = 'RUNNING'
       AND EXISTS (SELECT 1 FROM public.scan_jobs j WHERE j.scan_id = s.id)
       AND NOT EXISTS (SELECT 1 FROM public.scan_jobs j
                       WHERE j.scan_id = s.id AND j.execution_status IN ('QUEUED', 'RUNNING'));
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    PERFORM lifecycle.log_event(p_scan_id, NULL, 'SCAN_EVALUATING', p_actor_type, p_actor, NULL, NULL);
    RETURN TRUE;
END
$fn$;

-- Ends every unfinished job of a scan (QUEUED or RUNNING) with the given status. The
-- caller holds the scan row lock.
CREATE FUNCTION lifecycle.end_unfinished_jobs(p_scan_id UUID, p_now TIMESTAMPTZ, p_status TEXT,
    p_failure_reason TEXT, p_actor_type TEXT, p_actor TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_job   RECORD;
    v_count INTEGER := 0;
BEGIN
    FOR v_job IN
        SELECT j.id, j.lease_epoch FROM public.scan_jobs j
        WHERE j.scan_id = p_scan_id AND j.execution_status IN ('QUEUED', 'RUNNING')
        ORDER BY j.id
        FOR UPDATE
    LOOP
        UPDATE public.scan_jobs j
           SET execution_status = p_status, completed_at = greatest(p_now, j.updated_at),
               failure_reason = coalesce(p_failure_reason, j.failure_reason), next_attempt_at = NULL,
               updated_at = greatest(p_now, j.updated_at), version = j.version + 1
         WHERE j.id = v_job.id;
        PERFORM lifecycle.log_event(p_scan_id, v_job.id, 'JOB_' || p_status, p_actor_type, p_actor,
            v_job.lease_epoch, p_failure_reason);
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 4. Worker protocol (EXECUTE: sentinel_worker)
-- ---------------------------------------------------------------------------

-- Claims the oldest claimable job of one of the given scanner types, optionally of one
-- scan, and returns it with the authoritative scan, project and repository context. Zero
-- rows: nothing to claim (or the candidate scan is locked; retry later).
--
-- The lease token is returned exactly once. Workers must use the returned identifiers,
-- commit and repository, never values from queue messages.
CREATE FUNCTION worker.claim_job(p_scanner_types TEXT[], p_scan_id UUID DEFAULT NULL)
RETURNS TABLE (job_id UUID, scan_id UUID, project_id UUID, organization_id UUID, commit_sha VARCHAR,
    branch VARCHAR, repository_provider VARCHAR, repository_owner VARCHAR, repository_name VARCHAR,
    scanner_type VARCHAR, attempt INTEGER, max_attempts INTEGER, lease_epoch BIGINT, lease_token TEXT,
    lease_expires_at TIMESTAMPTZ, lease_duration_seconds INTEGER, deadline_at TIMESTAMPTZ)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_scan  public.scans%ROWTYPE;
    v_job   public.scan_jobs%ROWTYPE;
    v_now   TIMESTAMPTZ;
    v_token TEXT;
    v_try   INTEGER := 0;
BEGIN
    IF p_scanner_types IS NULL OR cardinality(p_scanner_types) NOT BETWEEN 1 AND 16
            OR array_position(p_scanner_types, NULL) IS NOT NULL
            OR NOT p_scanner_types <@ ARRAY['SEMGREP', 'GITLEAKS', 'TRIVY', 'CHECKOV', 'SYFT', 'ZAP', 'FIXTURE'] THEN
        RAISE EXCEPTION 'invalid scanner types' USING ERRCODE = '22023';
    END IF;

    LOOP
        v_try := v_try + 1;
        -- Lock order: scan first. SKIP LOCKED: a scan being changed by someone else is
        -- skipped rather than waited for.
        SELECT s.* INTO v_scan
          FROM public.scans s
         WHERE (p_scan_id IS NULL OR s.id = p_scan_id)
           AND s.execution_status IN ('QUEUED', 'RUNNING')
           AND (s.deadline_at IS NULL OR s.deadline_at > now())
           AND EXISTS (SELECT 1 FROM public.scan_jobs j
                       WHERE j.scan_id = s.id AND j.execution_status = 'QUEUED' AND j.attempt_count < 3
                         AND j.scanner_type = ANY (p_scanner_types)
                         AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= now()))
         ORDER BY s.requested_at, s.id
         LIMIT 1
         FOR UPDATE OF s SKIP LOCKED;
        IF NOT FOUND THEN
            RETURN;
        END IF;

        SELECT j.* INTO v_job
          FROM public.scan_jobs j
         WHERE j.scan_id = v_scan.id AND j.execution_status = 'QUEUED' AND j.attempt_count < 3
           AND j.scanner_type = ANY (p_scanner_types)
           AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= now())
         ORDER BY j.created_at, j.scanner_type
         LIMIT 1
         FOR UPDATE;
        EXIT WHEN FOUND;
        IF v_try >= 3 THEN
            RETURN;
        END IF;
    END LOOP;

    v_now := greatest(now(), v_scan.updated_at, v_job.updated_at);
    -- 244 bits from the server's strong random source; only the hash is stored.
    v_token := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');

    IF v_scan.execution_status = 'QUEUED' THEN
        UPDATE public.scans s
           SET execution_status = 'RUNNING', started_at = v_now,
               deadline_at = v_now + make_interval(secs => s.execution_timeout_seconds),
               updated_at = v_now, version = s.version + 1
         WHERE s.id = v_scan.id
        RETURNING s.* INTO v_scan;
        PERFORM lifecycle.log_event(v_scan.id, NULL, 'SCAN_STARTED', 'WORKER', session_user, NULL, NULL);
    END IF;

    UPDATE public.scan_jobs j
       SET execution_status = 'RUNNING', attempt_count = j.attempt_count + 1, lease_epoch = j.lease_epoch + 1,
           lease_owner = session_user, lease_token_sha256 = encode(sha256(convert_to(v_token, 'UTF8')), 'hex'),
           lease_expires_at = v_now + make_interval(secs => v_scan.lease_duration_seconds),
           heartbeat_at = v_now, started_at = v_now, next_attempt_at = NULL,
           updated_at = v_now, version = j.version + 1
     WHERE j.id = v_job.id
    RETURNING j.* INTO v_job;
    PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_CLAIMED', 'WORKER', session_user, v_job.lease_epoch,
        'ATTEMPT_' || v_job.attempt_count);

    RETURN QUERY
    SELECT v_job.id, v_scan.id, p.id, p.organization_id, v_scan.commit_sha, v_scan.branch, p.repository_provider,
           p.repository_owner, p.repository_name, v_job.scanner_type, v_job.attempt_count, 3, v_job.lease_epoch,
           v_token, v_job.lease_expires_at, v_scan.lease_duration_seconds, v_scan.deadline_at
      FROM public.projects p
     WHERE p.id = v_scan.project_id;
END
$fn$;

-- Renews a lease. Returns:
--   RENEWED            the lease now expires at lease_expires_at;
--   CANCELLED          the job was cancelled: stop and discard all work;
--   DEADLINE_EXCEEDED  the scan passed its hard deadline: stop;
--   LEASE_LOST         wrong job, epoch, owner or token, the lease expired, or the job is no
--                      longer RUNNING: stop; any later report will be rejected.
-- An expired lease is never revived, even if the supervisor has not reclaimed it yet.
CREATE FUNCTION worker.heartbeat_job(p_job_id UUID, p_lease_epoch BIGINT, p_lease_token TEXT)
RETURNS TABLE (status TEXT, lease_expires_at TIMESTAMPTZ)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_job      public.scan_jobs%ROWTYPE;
    v_deadline TIMESTAMPTZ;
    v_lease    INTEGER;
    v_now      TIMESTAMPTZ;
    v_expires  TIMESTAMPTZ;
BEGIN
    IF p_job_id IS NULL OR p_lease_epoch IS NULL OR p_lease_epoch < 1
            OR p_lease_token IS NULL OR p_lease_token !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid lease arguments' USING ERRCODE = '22023';
    END IF;
    -- Only the job row is locked (see the locking protocol above).
    SELECT j.* INTO v_job FROM public.scan_jobs j WHERE j.id = p_job_id FOR UPDATE;
    IF NOT FOUND OR v_job.lease_epoch <> p_lease_epoch OR v_job.lease_owner IS DISTINCT FROM session_user
            OR v_job.lease_token_sha256 IS DISTINCT FROM encode(sha256(convert_to(p_lease_token, 'UTF8')), 'hex') THEN
        RETURN QUERY SELECT 'LEASE_LOST'::text, NULL::timestamptz;
        RETURN;
    END IF;
    IF v_job.execution_status = 'CANCELLED' THEN
        RETURN QUERY SELECT 'CANCELLED'::text, NULL::timestamptz;
        RETURN;
    END IF;
    IF v_job.execution_status <> 'RUNNING' OR v_job.lease_expires_at <= now() THEN
        RETURN QUERY SELECT 'LEASE_LOST'::text, NULL::timestamptz;
        RETURN;
    END IF;
    SELECT s.deadline_at, s.lease_duration_seconds INTO v_deadline, v_lease
      FROM public.scans s WHERE s.id = v_job.scan_id;
    IF v_deadline <= now() THEN
        RETURN QUERY SELECT 'DEADLINE_EXCEEDED'::text, NULL::timestamptz;
        RETURN;
    END IF;
    v_now := greatest(now(), v_job.updated_at);
    UPDATE public.scan_jobs j
       SET lease_expires_at = v_now + make_interval(secs => v_lease), heartbeat_at = v_now,
           updated_at = v_now, version = j.version + 1
     WHERE j.id = v_job.id
    RETURNING j.lease_expires_at INTO v_expires;
    RETURN QUERY SELECT 'RENEWED'::text, v_expires;
END
$fn$;

-- Reports the outcome of the caller's lease. p_outcome is COMPLETED (the scanner ran and
-- produced its output; this says nothing about findings) or FAILED with a failure reason.
-- Whether a failure is retried is decided here, not by the worker: SCANNER_ERROR,
-- SANDBOX_ERROR and WORKER_SHUTDOWN are retried while attempts remain; the others are final.
--
-- Returns:
--   ACCEPTED   the report changed the job (and possibly moved the scan to EVALUATING);
--   DUPLICATE  this lease already reported exactly this outcome (redelivery, retry after
--              an ambiguous commit): no effect;
--   CONFLICT   this lease already reported a different outcome: no effect, audited;
--   REJECTED_UNKNOWN_JOB, REJECTED_SCAN_MISMATCH, REJECTED_STALE_EPOCH,
--   REJECTED_UNKNOWN_EPOCH, REJECTED_NOT_LEASE_OWNER, REJECTED_TOKEN_MISMATCH,
--   REJECTED_JOB_NOT_RUNNING, REJECTED_LEASE_EXPIRED, REJECTED_DEADLINE_EXCEEDED:
--              no effect, audited (except for an unknown job). The caller must discard
--              its work.
-- The scan id is a cross-check only: authorization comes from the lease, and every
-- identifier written is taken from the authoritative rows.
CREATE FUNCTION worker.report_job(p_job_id UUID, p_scan_id UUID, p_lease_epoch BIGINT, p_lease_token TEXT,
    p_outcome TEXT, p_failure_reason TEXT DEFAULT NULL)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_hash      TEXT;
    v_scan_id   UUID;
    v_scan      public.scans%ROWTYPE;
    v_job       public.scan_jobs%ROWTYPE;
    v_report    lifecycle.job_reports%ROWTYPE;
    v_rejection TEXT;
    v_now       TIMESTAMPTZ;
BEGIN
    IF p_job_id IS NULL OR p_scan_id IS NULL OR p_lease_epoch IS NULL OR p_lease_epoch < 1
            OR p_lease_token IS NULL OR p_lease_token !~ '^[0-9a-f]{64}$'
            OR p_outcome IS NULL OR p_outcome NOT IN ('COMPLETED', 'FAILED')
            OR (p_outcome = 'COMPLETED') <> (p_failure_reason IS NULL)
            OR (p_failure_reason IS NOT NULL AND p_failure_reason NOT IN ('SCANNER_ERROR', 'SANDBOX_ERROR',
                'EXECUTION_TIMEOUT', 'RESOURCE_LIMIT_EXCEEDED', 'UNSUPPORTED_SCANNER', 'WORKER_SHUTDOWN')) THEN
        RAISE EXCEPTION 'invalid job report' USING ERRCODE = '22023';
    END IF;
    v_hash := encode(sha256(convert_to(p_lease_token, 'UTF8')), 'hex');

    SELECT j.scan_id INTO v_scan_id FROM public.scan_jobs j WHERE j.id = p_job_id;
    IF NOT FOUND THEN
        RETURN 'REJECTED_UNKNOWN_JOB';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = v_scan_id FOR UPDATE;
    SELECT j.* INTO v_job FROM public.scan_jobs j WHERE j.id = p_job_id FOR UPDATE;

    IF v_scan_id <> p_scan_id THEN
        v_rejection := 'SCAN_MISMATCH';
    ELSE
        SELECT r.* INTO v_report FROM lifecycle.job_reports r
         WHERE r.job_id = p_job_id AND r.lease_epoch = p_lease_epoch;
        IF FOUND AND v_report.lease_owner = session_user AND v_report.lease_token_sha256 = v_hash THEN
            IF v_report.outcome = p_outcome AND v_report.failure_reason IS NOT DISTINCT FROM p_failure_reason THEN
                RETURN 'DUPLICATE';
            END IF;
            PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'REPORT_CONFLICT', 'WORKER', session_user,
                p_lease_epoch, coalesce(p_failure_reason, p_outcome));
            RETURN 'CONFLICT';
        ELSIF p_lease_epoch < v_job.lease_epoch THEN
            v_rejection := 'STALE_EPOCH';
        ELSIF p_lease_epoch > v_job.lease_epoch THEN
            v_rejection := 'UNKNOWN_EPOCH';
        ELSIF v_job.lease_owner IS DISTINCT FROM session_user THEN
            v_rejection := 'NOT_LEASE_OWNER';
        ELSIF v_job.lease_token_sha256 IS DISTINCT FROM v_hash THEN
            v_rejection := 'TOKEN_MISMATCH';
        ELSIF v_job.execution_status <> 'RUNNING' THEN
            v_rejection := 'JOB_NOT_RUNNING';
        ELSIF v_job.lease_expires_at <= now() THEN
            v_rejection := 'LEASE_EXPIRED';
        ELSIF v_scan.deadline_at <= now() THEN
            v_rejection := 'DEADLINE_EXCEEDED';
        END IF;
    END IF;
    IF v_rejection IS NOT NULL THEN
        PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'REPORT_REJECTED', 'WORKER', session_user,
            p_lease_epoch, v_rejection);
        RETURN 'REJECTED_' || v_rejection;
    END IF;

    v_now := greatest(now(), v_scan.updated_at, v_job.updated_at);
    INSERT INTO lifecycle.job_reports (job_id, lease_epoch, lease_owner, lease_token_sha256, outcome,
        failure_reason, reported_at)
    VALUES (v_job.id, p_lease_epoch, session_user, v_hash, p_outcome, p_failure_reason, v_now);

    IF p_outcome = 'COMPLETED' THEN
        UPDATE public.scan_jobs j
           SET execution_status = 'COMPLETED', completed_at = v_now, updated_at = v_now, version = j.version + 1
         WHERE j.id = v_job.id;
        PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_COMPLETED', 'WORKER', session_user,
            p_lease_epoch, NULL);
    ELSIF p_failure_reason IN ('SCANNER_ERROR', 'SANDBOX_ERROR', 'WORKER_SHUTDOWN') AND v_job.attempt_count < 3 THEN
        UPDATE public.scan_jobs j
           SET execution_status = 'QUEUED', started_at = NULL, failure_reason = p_failure_reason,
               next_attempt_at = v_now + lifecycle.retry_delay(j.attempt_count),
               updated_at = v_now, version = j.version + 1
         WHERE j.id = v_job.id;
        PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_RETRY_SCHEDULED', 'WORKER', session_user,
            p_lease_epoch, p_failure_reason);
    ELSE
        UPDATE public.scan_jobs j
           SET execution_status = 'FAILED', completed_at = v_now, failure_reason = p_failure_reason,
               updated_at = v_now, version = j.version + 1
         WHERE j.id = v_job.id;
        PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_FAILED', 'WORKER', session_user,
            p_lease_epoch, p_failure_reason);
    END IF;
    PERFORM lifecycle.settle_scan(v_scan.id, v_now, 'WORKER', session_user);
    RETURN 'ACCEPTED';
END
$fn$;

-- ---------------------------------------------------------------------------
-- 5. Control-plane operations (EXECUTE: sentinel_api)
-- ---------------------------------------------------------------------------

-- One supervisor pass, safe to run concurrently on several API instances (rows locked by
-- another pass or by a worker are skipped until the next pass):
--   1. RUNNING scans past their hard deadline FAIL (decision INCOMPLETE); their unfinished
--      jobs FAIL with EXECUTION_DEADLINE_EXCEEDED;
--   2. expired leases (crashed, hung or partitioned workers) are reclaimed: the job is
--      requeued with a backoff while attempts remain, otherwise it FAILS. The previous
--      holder's epoch is now stale, so its late reports are rejected.
CREATE FUNCTION lifecycle.supervise(p_limit INTEGER DEFAULT 100)
RETURNS TABLE (deadlines_exceeded INTEGER, leases_expired INTEGER)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_candidate RECORD;
    v_scan      public.scans%ROWTYPE;
    v_job       public.scan_jobs%ROWTYPE;
    v_now       TIMESTAMPTZ;
    v_deadlines INTEGER := 0;
    v_expired   INTEGER := 0;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'limit must be between 1 and 1000' USING ERRCODE = '22023';
    END IF;

    FOR v_candidate IN
        SELECT s.id FROM public.scans s
        WHERE s.execution_status = 'RUNNING' AND s.deadline_at <= now()
        ORDER BY s.deadline_at, s.id
        LIMIT p_limit
    LOOP
        SELECT s.* INTO v_scan FROM public.scans s
         WHERE s.id = v_candidate.id AND s.execution_status = 'RUNNING' AND s.deadline_at <= now()
         FOR UPDATE SKIP LOCKED;
        CONTINUE WHEN NOT FOUND;
        v_now := greatest(now(), v_scan.updated_at);
        PERFORM lifecycle.end_unfinished_jobs(v_scan.id, v_now, 'FAILED', 'EXECUTION_DEADLINE_EXCEEDED',
            'SUPERVISOR', session_user);
        UPDATE public.scans s
           SET execution_status = 'FAILED', security_decision = 'INCOMPLETE',
               decision_reason = 'EXECUTION_DEADLINE_EXCEEDED', completed_at = v_now, updated_at = v_now,
               version = s.version + 1
         WHERE s.id = v_scan.id;
        PERFORM lifecycle.log_event(v_scan.id, NULL, 'SCAN_FAILED', 'SUPERVISOR', session_user, NULL,
            'EXECUTION_DEADLINE_EXCEEDED');
        v_deadlines := v_deadlines + 1;
    END LOOP;

    FOR v_candidate IN
        SELECT j.id, j.scan_id FROM public.scan_jobs j
        WHERE j.execution_status = 'RUNNING' AND j.lease_expires_at <= now()
        ORDER BY j.lease_expires_at, j.id
        LIMIT p_limit
    LOOP
        SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = v_candidate.scan_id FOR UPDATE SKIP LOCKED;
        CONTINUE WHEN NOT FOUND;
        SELECT j.* INTO v_job FROM public.scan_jobs j
         WHERE j.id = v_candidate.id AND j.execution_status = 'RUNNING' AND j.lease_expires_at <= now()
         FOR UPDATE;
        CONTINUE WHEN NOT FOUND;
        v_now := greatest(now(), v_scan.updated_at, v_job.updated_at);
        PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_LEASE_EXPIRED', 'SUPERVISOR', session_user,
            v_job.lease_epoch, NULL);
        IF v_job.attempt_count < 3 AND v_scan.execution_status = 'RUNNING' THEN
            UPDATE public.scan_jobs j
               SET execution_status = 'QUEUED', started_at = NULL, failure_reason = 'LEASE_EXPIRED',
                   next_attempt_at = v_now + lifecycle.retry_delay(j.attempt_count),
                   updated_at = v_now, version = j.version + 1
             WHERE j.id = v_job.id;
            PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_RETRY_SCHEDULED', 'SUPERVISOR', session_user,
                v_job.lease_epoch, 'LEASE_EXPIRED');
        ELSE
            UPDATE public.scan_jobs j
               SET execution_status = 'FAILED', completed_at = v_now, failure_reason = 'LEASE_EXPIRED',
                   updated_at = v_now, version = j.version + 1
             WHERE j.id = v_job.id;
            PERFORM lifecycle.log_event(v_scan.id, v_job.id, 'JOB_FAILED', 'SUPERVISOR', session_user,
                v_job.lease_epoch, 'LEASE_EXPIRED');
        END IF;
        PERFORM lifecycle.settle_scan(v_scan.id, v_now, 'SUPERVISOR', session_user);
        v_expired := v_expired + 1;
    END LOOP;

    RETURN QUERY SELECT v_deadlines, v_expired;
END
$fn$;

-- Records the security decision of an EVALUATING scan. Fail closed: PASS requires at
-- least one job and every job COMPLETED, and PASS or FAIL require an actual policy
-- evaluation (reason POLICY_EVALUATED). Returns COMPLETED, NOT_FOUND, NOT_EVALUATING
-- or REJECTED_PASS_NOT_JUSTIFIED.
CREATE FUNCTION lifecycle.complete_evaluation(p_scan_id UUID, p_decision TEXT, p_reason TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan public.scans%ROWTYPE;
    v_now  TIMESTAMPTZ;
BEGIN
    IF p_scan_id IS NULL OR p_decision IS NULL OR p_decision NOT IN ('PASS', 'FAIL', 'INCOMPLETE')
            OR p_reason IS NULL
            OR p_reason NOT IN ('POLICY_EVALUATED', 'POLICY_EVALUATION_UNAVAILABLE', 'SCANNER_EXECUTION_INCOMPLETE')
            OR (p_decision IN ('PASS', 'FAIL')) <> (p_reason = 'POLICY_EVALUATED') THEN
        RAISE EXCEPTION 'invalid evaluation result' USING ERRCODE = '22023';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    IF v_scan.execution_status <> 'EVALUATING' THEN
        RETURN 'NOT_EVALUATING';
    END IF;
    IF p_decision = 'PASS' AND (NOT EXISTS (SELECT 1 FROM public.scan_jobs j WHERE j.scan_id = p_scan_id)
            OR EXISTS (SELECT 1 FROM public.scan_jobs j
                       WHERE j.scan_id = p_scan_id AND j.execution_status <> 'COMPLETED')) THEN
        RETURN 'REJECTED_PASS_NOT_JUSTIFIED';
    END IF;
    v_now := greatest(now(), v_scan.updated_at);
    UPDATE public.scans s
       SET execution_status = 'COMPLETED', security_decision = p_decision, decision_reason = p_reason,
           completed_at = v_now, updated_at = v_now, version = s.version + 1
     WHERE s.id = p_scan_id;
    PERFORM lifecycle.log_event(p_scan_id, NULL, 'SCAN_COMPLETED', 'SUPERVISOR', session_user, NULL, p_decision);
    RETURN 'COMPLETED';
END
$fn$;

-- Cancels a non-terminal scan (decision INCOMPLETE) and its unfinished jobs. A running
-- worker learns about it on its next heartbeat (CANCELLED) and its report is rejected.
-- p_actor identifies the requesting user (audited); the caller has already authorized
-- the request. Returns CANCELLED, ALREADY_CANCELLED, NOT_CANCELLABLE or NOT_FOUND.
CREATE FUNCTION lifecycle.cancel_scan(p_scan_id UUID, p_actor TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan public.scans%ROWTYPE;
    v_now  TIMESTAMPTZ;
BEGIN
    IF p_scan_id IS NULL OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'invalid cancellation' USING ERRCODE = '22023';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    IF v_scan.execution_status = 'CANCELLED' THEN
        RETURN 'ALREADY_CANCELLED';
    END IF;
    IF v_scan.execution_status IN ('COMPLETED', 'FAILED') THEN
        RETURN 'NOT_CANCELLABLE';
    END IF;
    v_now := greatest(now(), v_scan.updated_at);
    PERFORM lifecycle.end_unfinished_jobs(p_scan_id, v_now, 'CANCELLED', NULL, 'USER', p_actor);
    UPDATE public.scans s
       SET execution_status = 'CANCELLED', security_decision = 'INCOMPLETE', decision_reason = 'CANCELLED_BY_USER',
           completed_at = v_now, updated_at = v_now, version = s.version + 1
     WHERE s.id = p_scan_id;
    PERFORM lifecycle.log_event(p_scan_id, NULL, 'SCAN_CANCELLED', 'USER', p_actor, NULL, NULL);
    RETURN 'CANCELLED';
END
$fn$;

-- Marks a non-terminal scan FAILED (decision INCOMPLETE, reason EXECUTION_FAILED) and
-- cancels its unfinished jobs. Returns FAILED, NOT_FOUND or TERMINAL.
CREATE FUNCTION lifecycle.fail_scan(p_scan_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan public.scans%ROWTYPE;
    v_now  TIMESTAMPTZ;
BEGIN
    IF p_scan_id IS NULL THEN
        RAISE EXCEPTION 'invalid scan' USING ERRCODE = '22023';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    IF v_scan.execution_status IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN
        RETURN 'TERMINAL';
    END IF;
    v_now := greatest(now(), v_scan.updated_at);
    PERFORM lifecycle.end_unfinished_jobs(p_scan_id, v_now, 'CANCELLED', NULL, 'SYSTEM', session_user);
    UPDATE public.scans s
       SET execution_status = 'FAILED', security_decision = 'INCOMPLETE', decision_reason = 'EXECUTION_FAILED',
           completed_at = v_now, updated_at = v_now, version = s.version + 1
     WHERE s.id = p_scan_id;
    PERFORM lifecycle.log_event(p_scan_id, NULL, 'SCAN_FAILED', 'SYSTEM', session_user, NULL, 'EXECUTION_FAILED');
    RETURN 'FAILED';
END
$fn$;

-- ---------------------------------------------------------------------------
-- 6. Privileges
-- ---------------------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA lifecycle FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.log_event(UUID, UUID, TEXT, TEXT, TEXT, BIGINT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.retry_delay(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.settle_scan(UUID, TIMESTAMPTZ, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.end_unfinished_jobs(UUID, TIMESTAMPTZ, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION worker.claim_job(TEXT[], UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION worker.heartbeat_job(UUID, BIGINT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION worker.report_job(UUID, UUID, BIGINT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.supervise(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.complete_evaluation(UUID, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.cancel_scan(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.fail_scan(UUID) FROM PUBLIC;

-- Worker: the execution protocol, nothing else (in addition to worker.record_receipt).
GRANT EXECUTE ON FUNCTION worker.claim_job(TEXT[], UUID) TO sentinel_worker;
GRANT EXECUTE ON FUNCTION worker.heartbeat_job(UUID, BIGINT, TEXT) TO sentinel_worker;
GRANT EXECUTE ON FUNCTION worker.report_job(UUID, UUID, BIGINT, TEXT, TEXT, TEXT) TO sentinel_worker;

-- API: lifecycle changes only through the functions above. It keeps INSERT (creation and
-- planning) and UPDATE of the idempotency columns (key expiry), which also allows the row
-- lock (SELECT ... FOR UPDATE) that serializes planning with claims.
REVOKE UPDATE (execution_status, security_decision, version, started_at, completed_at, updated_at)
    ON scans FROM sentinel_api;
REVOKE UPDATE ON scan_jobs FROM sentinel_api;
GRANT USAGE ON SCHEMA lifecycle TO sentinel_api;
GRANT SELECT ON lifecycle.execution_events TO sentinel_api;
GRANT EXECUTE ON FUNCTION lifecycle.supervise(INTEGER) TO sentinel_api;
GRANT EXECUTE ON FUNCTION lifecycle.complete_evaluation(UUID, TEXT, TEXT) TO sentinel_api;
GRANT EXECUTE ON FUNCTION lifecycle.cancel_scan(UUID, TEXT) TO sentinel_api;
GRANT EXECUTE ON FUNCTION lifecycle.fail_scan(UUID) TO sentinel_api;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.execution_lifecycle', 'm3-phase1');

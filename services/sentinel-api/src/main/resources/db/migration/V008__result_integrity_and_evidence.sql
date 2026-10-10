-- V008: Milestone 3, Phase 1 (Slice 3). Result integrity: the job-result.v1 contract,
-- database-verified evidence, deduplicated rejection audit and evidence retention.
-- Design: ADR-0008.
--
-- 1. Evidence is uploaded under a valid lease with worker.put_evidence. PostgreSQL computes
--    the SHA-256 of the received bytes itself; a worker-supplied digest is never trusted.
--    Objects are content-addressed per organization (organization_id, sha256): a reference
--    can only resolve inside the job's own tenant. Each upload is bound to
--    (job, lease epoch, artifact name). Artifact names are restricted identifiers, never
--    paths, URLs or SQL identifiers.
-- 2. Results are submitted as one job-result.v1 document with worker.submit_result, which
--    replaces V007's worker.report_job. In one transaction it validates the document
--    (size, strict structure, no duplicate keys), authenticates the lease (login, token,
--    epoch), checks the claimed scan, project, organization, commit, scanner type and
--    attempt against the authoritative rows, and verifies that every referenced artifact
--    was uploaded under the same lease with exactly the recorded digest, size and media
--    type. The accepted document and its SHA-256 are kept. Retries of the identical
--    document are DUPLICATE; a different document for the same lease is CONFLICT.
-- 3. Repeated rejections are counted per (job, epoch bucket, worker login, operation,
--    reason) in lifecycle.report_rejections. Only the first occurrence writes an
--    execution event, so the audit trail stays bounded without losing evidence.
-- 4. Evidence content is kept for the scan's evidence_retention_days, then purged by
--    the supervisor. The digest, size and timestamps are retained, never deleted.

-- ---------------------------------------------------------------------------
-- 1. Columns and constraints
-- ---------------------------------------------------------------------------

ALTER TABLE scans
    ADD COLUMN evidence_retention_days INTEGER NOT NULL DEFAULT 90,
    ADD CONSTRAINT ck_scans_evidence_retention CHECK (evidence_retention_days BETWEEN 1 AND 3650);

ALTER TABLE scan_jobs
    DROP CONSTRAINT ck_scan_jobs_failure_reason,
    ADD CONSTRAINT ck_scan_jobs_failure_reason CHECK (
        failure_reason IS NULL OR failure_reason IN ('LEASE_EXPIRED', 'SCANNER_ERROR', 'SANDBOX_ERROR',
            'EXECUTION_TIMEOUT', 'RESOURCE_LIMIT_EXCEEDED', 'UNSUPPORTED_SCANNER', 'WORKER_SHUTDOWN',
            'EXECUTION_DEADLINE_EXCEEDED', 'EVIDENCE_UNAVAILABLE')
    );

ALTER TABLE lifecycle.execution_events
    DROP CONSTRAINT ck_execution_events_type,
    ADD CONSTRAINT ck_execution_events_type CHECK (event_type IN ('SCAN_STARTED', 'SCAN_EVALUATING',
        'SCAN_COMPLETED', 'SCAN_FAILED', 'SCAN_CANCELLED', 'JOB_CLAIMED', 'JOB_COMPLETED', 'JOB_RETRY_SCHEDULED',
        'JOB_FAILED', 'JOB_CANCELLED', 'JOB_LEASE_EXPIRED', 'REPORT_REJECTED', 'REPORT_CONFLICT',
        'EVIDENCE_REJECTED'));

-- Accepted job-result.v1 documents (NULL for reports accepted by V007's report_job).
ALTER TABLE lifecycle.job_reports
    ADD COLUMN result_sha256 CHAR(64),
    ADD COLUMN result JSONB,
    ADD CONSTRAINT ck_job_reports_result CHECK ((result IS NULL) = (result_sha256 IS NULL)
        AND (result_sha256 IS NULL OR result_sha256 ~ '^[0-9a-f]{64}$'));

-- Deduplicated record of refused worker operations. The epoch is bucketed (claimed epochs
-- above the current one share one bucket), so keys per job are bounded.
CREATE TABLE lifecycle.report_rejections (
    job_id      UUID        NOT NULL,
    lease_epoch BIGINT      NOT NULL,
    actor       VARCHAR(63) NOT NULL,
    operation   VARCHAR(20) NOT NULL,
    detail      VARCHAR(40) NOT NULL,
    occurrences INTEGER     NOT NULL DEFAULT 1,
    first_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_report_rejections PRIMARY KEY (job_id, lease_epoch, actor, operation, detail),
    CONSTRAINT fk_report_rejections_job FOREIGN KEY (job_id) REFERENCES public.scan_jobs (id) ON DELETE RESTRICT,
    CONSTRAINT ck_report_rejections_operation CHECK (operation IN ('RESULT', 'EVIDENCE')),
    CONSTRAINT ck_report_rejections_detail CHECK (detail ~ '^[A-Z0-9_]{1,40}$'),
    CONSTRAINT ck_report_rejections_occurrences CHECK (occurrences >= 1)
);

COMMENT ON TABLE lifecycle.report_rejections IS
    'Refused result and evidence operations, deduplicated with occurrence counts.';

-- ---------------------------------------------------------------------------
-- 2. Evidence storage (schema evidence)
-- ---------------------------------------------------------------------------

CREATE SCHEMA evidence;
REVOKE ALL ON SCHEMA evidence FROM PUBLIC;

-- Content-addressed, tenant-scoped, immutable evidence. The CHECK recomputes the digest
-- from the stored bytes, so no write (by any role) can store content that does not match
-- its address. Content is removed only by retention (purged_at); the address remains.
CREATE TABLE evidence.objects (
    organization_id UUID        NOT NULL,
    sha256          CHAR(64)    NOT NULL,
    size_bytes      INTEGER     NOT NULL,
    content         BYTEA,
    stored_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    retain_until    TIMESTAMPTZ NOT NULL,
    purged_at       TIMESTAMPTZ,
    CONSTRAINT pk_evidence_objects PRIMARY KEY (organization_id, sha256),
    CONSTRAINT fk_evidence_objects_organization FOREIGN KEY (organization_id)
        REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT ck_evidence_objects_sha CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_evidence_objects_size CHECK (size_bytes BETWEEN 0 AND 1048576),
    CONSTRAINT ck_evidence_objects_purge CHECK ((content IS NULL) = (purged_at IS NOT NULL)),
    CONSTRAINT ck_evidence_objects_integrity CHECK (content IS NULL
        OR (octet_length(content) = size_bytes AND encode(sha256(content), 'hex') = sha256))
);

CREATE INDEX ix_evidence_objects_retention ON evidence.objects (retain_until) WHERE content IS NOT NULL;

COMMENT ON TABLE evidence.objects IS 'Tenant-scoped, content-addressed evidence; digests computed by the database.';

-- An upload under one lease. Names are restricted identifiers (no paths).
CREATE TABLE evidence.job_artifacts (
    job_id          UUID        NOT NULL,
    lease_epoch     BIGINT      NOT NULL,
    name            VARCHAR(64) NOT NULL,
    organization_id UUID        NOT NULL,
    sha256          CHAR(64)    NOT NULL,
    media_type      VARCHAR(40) NOT NULL,
    size_bytes      INTEGER     NOT NULL,
    uploaded_by     VARCHAR(63) NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_job_artifacts PRIMARY KEY (job_id, lease_epoch, name),
    CONSTRAINT fk_job_artifacts_job FOREIGN KEY (job_id) REFERENCES public.scan_jobs (id) ON DELETE RESTRICT,
    CONSTRAINT fk_job_artifacts_object FOREIGN KEY (organization_id, sha256)
        REFERENCES evidence.objects (organization_id, sha256) ON DELETE RESTRICT,
    CONSTRAINT ck_job_artifacts_name CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$' AND name NOT LIKE '%..%'),
    CONSTRAINT ck_job_artifacts_media_type
        CHECK (media_type IN ('application/json', 'application/sarif+json', 'text/plain')),
    CONSTRAINT ck_job_artifacts_size CHECK (size_bytes BETWEEN 0 AND 1048576)
);

-- Artifacts referenced by an accepted result (the evidence of record).
CREATE TABLE evidence.result_artifacts (
    job_id      UUID        NOT NULL,
    lease_epoch BIGINT      NOT NULL,
    name        VARCHAR(64) NOT NULL,
    CONSTRAINT pk_result_artifacts PRIMARY KEY (job_id, lease_epoch, name),
    CONSTRAINT fk_result_artifacts_upload FOREIGN KEY (job_id, lease_epoch, name)
        REFERENCES evidence.job_artifacts (job_id, lease_epoch, name) ON DELETE RESTRICT,
    CONSTRAINT fk_result_artifacts_report FOREIGN KEY (job_id, lease_epoch)
        REFERENCES lifecycle.job_reports (job_id, lease_epoch) ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------------
-- 3. Internal helpers (owner only)
-- ---------------------------------------------------------------------------

-- Counts a refused operation; the first occurrence per key also writes an execution event.
CREATE FUNCTION lifecycle.note_rejection(p_scan_id UUID, p_job_id UUID, p_claimed_epoch BIGINT,
    p_current_epoch BIGINT, p_operation TEXT, p_detail TEXT)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_first BOOLEAN;
    v_epoch BIGINT := least(greatest(coalesce(p_claimed_epoch, 0), 0), p_current_epoch + 1);
BEGIN
    INSERT INTO lifecycle.report_rejections AS r (job_id, lease_epoch, actor, operation, detail)
    VALUES (p_job_id, v_epoch, session_user, p_operation, p_detail)
    ON CONFLICT (job_id, lease_epoch, actor, operation, detail) DO UPDATE
        SET occurrences = least(r.occurrences, 2147483646) + 1, last_at = now()
    RETURNING (xmax = 0) INTO v_first;
    IF v_first THEN
        PERFORM lifecycle.log_event(p_scan_id, p_job_id,
            CASE WHEN p_operation = 'EVIDENCE' THEN 'EVIDENCE_REJECTED'
                 WHEN p_detail = 'CONFLICT' THEN 'REPORT_CONFLICT'
                 ELSE 'REPORT_REJECTED' END,
            'WORKER', session_user, v_epoch, p_detail);
    END IF;
END
$fn$;

-- Authenticates a lease for a write: NULL if valid, otherwise the rejection reason. The
-- caller holds the job row lock.
CREATE FUNCTION lifecycle.lease_rejection(p_job public.scan_jobs, p_deadline TIMESTAMPTZ, p_epoch BIGINT,
    p_token_sha256 TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT CASE
        WHEN p_epoch < p_job.lease_epoch THEN 'STALE_EPOCH'
        WHEN p_epoch > p_job.lease_epoch THEN 'UNKNOWN_EPOCH'
        WHEN p_job.lease_owner IS DISTINCT FROM session_user THEN 'NOT_LEASE_OWNER'
        WHEN p_job.lease_token_sha256 IS DISTINCT FROM p_token_sha256 THEN 'TOKEN_MISMATCH'
        WHEN p_job.execution_status <> 'RUNNING' THEN 'JOB_NOT_RUNNING'
        WHEN p_job.lease_expires_at <= now() THEN 'LEASE_EXPIRED'
        WHEN p_deadline <= now() THEN 'DEADLINE_EXCEEDED'
    END;
$fn$;

-- Applies an accepted outcome to a RUNNING job (the caller holds the scan and job locks).
-- Retry decisions belong to the control plane.
CREATE FUNCTION lifecycle.apply_job_outcome(p_scan_id UUID, p_job_id UUID, p_epoch BIGINT, p_attempt INTEGER,
    p_outcome TEXT, p_failure_reason TEXT, p_now TIMESTAMPTZ)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF p_outcome = 'COMPLETED' THEN
        UPDATE public.scan_jobs j
           SET execution_status = 'COMPLETED', completed_at = p_now, updated_at = p_now, version = j.version + 1
         WHERE j.id = p_job_id;
        PERFORM lifecycle.log_event(p_scan_id, p_job_id, 'JOB_COMPLETED', 'WORKER', session_user, p_epoch, NULL);
    ELSIF p_failure_reason IN ('SCANNER_ERROR', 'SANDBOX_ERROR', 'WORKER_SHUTDOWN', 'EVIDENCE_UNAVAILABLE')
            AND p_attempt < 3 THEN
        UPDATE public.scan_jobs j
           SET execution_status = 'QUEUED', started_at = NULL, failure_reason = p_failure_reason,
               next_attempt_at = p_now + lifecycle.retry_delay(j.attempt_count),
               updated_at = p_now, version = j.version + 1
         WHERE j.id = p_job_id;
        PERFORM lifecycle.log_event(p_scan_id, p_job_id, 'JOB_RETRY_SCHEDULED', 'WORKER', session_user, p_epoch,
            p_failure_reason);
    ELSE
        UPDATE public.scan_jobs j
           SET execution_status = 'FAILED', completed_at = p_now, failure_reason = p_failure_reason,
               updated_at = p_now, version = j.version + 1
         WHERE j.id = p_job_id;
        PERFORM lifecycle.log_event(p_scan_id, p_job_id, 'JOB_FAILED', 'WORKER', session_user, p_epoch,
            p_failure_reason);
    END IF;
    PERFORM lifecycle.settle_scan(p_scan_id, p_now, 'WORKER', session_user);
END
$fn$;

-- Strict structural validation of a job-result.v1 document (packages/contracts). Raises
-- SQLSTATE 22023 with a fixed message: the document is never echoed.
CREATE FUNCTION lifecycle.validate_job_result(p_document JSON)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_keys      TEXT[];
    v_artifact  JSON;
    v_previous  TEXT := '';
    v_started   TIMESTAMPTZ;
    v_finished  TIMESTAMPTZ;
    v_ts        CONSTANT TEXT := '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$';
    v_uuid      CONSTANT TEXT := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
BEGIN
    -- Exactly the contract's keys, each once (the json type preserves duplicates).
    SELECT array_agg(k ORDER BY k) INTO v_keys FROM json_object_keys(p_document) k;
    IF v_keys IS DISTINCT FROM ARRAY['artifacts', 'attempt', 'commit_sha', 'failure_reason', 'finished_at',
            'job_id', 'lease_epoch', 'organization_id', 'outcome', 'project_id', 'scan_id', 'scanner_type',
            'schema_version', 'started_at'] THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END IF;
    IF json_typeof(p_document -> 'job_id') <> 'string' OR (p_document ->> 'job_id') !~ v_uuid
            OR json_typeof(p_document -> 'scan_id') <> 'string' OR (p_document ->> 'scan_id') !~ v_uuid
            OR json_typeof(p_document -> 'project_id') <> 'string' OR (p_document ->> 'project_id') !~ v_uuid
            OR json_typeof(p_document -> 'organization_id') <> 'string'
            OR (p_document ->> 'organization_id') !~ v_uuid
            OR json_typeof(p_document -> 'commit_sha') <> 'string'
            OR (p_document ->> 'commit_sha') !~ '^[0-9a-f]{40}([0-9a-f]{24})?$'
            OR json_typeof(p_document -> 'scanner_type') <> 'string'
            OR (p_document ->> 'scanner_type') NOT IN ('SEMGREP', 'GITLEAKS', 'TRIVY', 'CHECKOV', 'SYFT', 'ZAP',
                'FIXTURE')
            OR json_typeof(p_document -> 'attempt') <> 'number' OR (p_document ->> 'attempt') !~ '^[1-3]$'
            OR json_typeof(p_document -> 'lease_epoch') <> 'number'
            OR (p_document ->> 'lease_epoch') !~ '^[1-9][0-9]{0,8}$'
            OR json_typeof(p_document -> 'outcome') <> 'string'
            OR (p_document ->> 'outcome') NOT IN ('COMPLETED', 'FAILED')
            OR json_typeof(p_document -> 'failure_reason') NOT IN ('string', 'null')
            OR ((p_document ->> 'outcome') = 'COMPLETED') <> (json_typeof(p_document -> 'failure_reason') = 'null')
            OR (json_typeof(p_document -> 'failure_reason') = 'string'
                AND (p_document ->> 'failure_reason') NOT IN ('SCANNER_ERROR', 'SANDBOX_ERROR',
                    'EXECUTION_TIMEOUT', 'RESOURCE_LIMIT_EXCEEDED', 'UNSUPPORTED_SCANNER', 'WORKER_SHUTDOWN',
                    'EVIDENCE_UNAVAILABLE'))
            OR json_typeof(p_document -> 'started_at') <> 'string' OR (p_document ->> 'started_at') !~ v_ts
            OR json_typeof(p_document -> 'finished_at') <> 'string' OR (p_document ->> 'finished_at') !~ v_ts
            OR json_typeof(p_document -> 'artifacts') <> 'array'
            OR json_array_length(p_document -> 'artifacts') > 16 THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END IF;
    BEGIN
        v_started := (p_document ->> 'started_at')::timestamptz;
        v_finished := (p_document ->> 'finished_at')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END;
    IF v_finished < v_started THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END IF;
    FOR v_artifact IN SELECT a FROM json_array_elements(p_document -> 'artifacts') a LOOP
        IF json_typeof(v_artifact) <> 'object' THEN
            RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
        END IF;
        SELECT array_agg(k ORDER BY k) INTO v_keys FROM json_object_keys(v_artifact) k;
        -- Names are strictly ascending: sorted and unique.
        IF v_keys IS DISTINCT FROM ARRAY['media_type', 'name', 'sha256', 'size_bytes']
                OR json_typeof(v_artifact -> 'name') <> 'string'
                OR (v_artifact ->> 'name') !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
                OR (v_artifact ->> 'name') LIKE '%..%'
                OR (v_artifact ->> 'name') COLLATE "C" <= v_previous COLLATE "C"
                OR json_typeof(v_artifact -> 'media_type') <> 'string'
                OR (v_artifact ->> 'media_type') NOT IN ('application/json', 'application/sarif+json', 'text/plain')
                OR json_typeof(v_artifact -> 'sha256') <> 'string'
                OR (v_artifact ->> 'sha256') !~ '^[0-9a-f]{64}$'
                OR json_typeof(v_artifact -> 'size_bytes') <> 'number'
                OR (v_artifact ->> 'size_bytes') !~ '^(0|[1-9][0-9]{0,6})$'
                OR (v_artifact ->> 'size_bytes')::integer > 1048576 THEN
            RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
        END IF;
        v_previous := v_artifact ->> 'name';
    END LOOP;
    RETURN p_document::jsonb;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 4. Worker protocol (EXECUTE: sentinel_worker)
-- ---------------------------------------------------------------------------

-- Stores one evidence artifact under the caller's lease. The database computes the
-- SHA-256 and size from the received bytes and returns them; the worker compares them
-- with its own computation. Returns (status, sha256, size_bytes) with status:
--   STORED     stored and bound to (job, epoch, name);
--   DUPLICATE  the same bytes were already stored under this name and lease;
--   CONFLICT   different bytes were already stored under this name and lease (audited);
--   REJECTED_<reason>  lease not valid (see worker.submit_result) or QUOTA_EXCEEDED (more
--              than 16 artifacts or 8 MiB per lease) or UNKNOWN_JOB; audited.
-- Malformed arguments (name, media type, more than 1 MiB) raise SQLSTATE 22023.
CREATE FUNCTION worker.put_evidence(p_job_id UUID, p_lease_epoch BIGINT, p_lease_token TEXT, p_name TEXT,
    p_media_type TEXT, p_content BYTEA)
RETURNS TABLE (status TEXT, sha256 TEXT, size_bytes INTEGER)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_job       public.scan_jobs%ROWTYPE;
    v_scan      public.scans%ROWTYPE;
    v_org       UUID;
    v_sha       TEXT;
    v_size      INTEGER;
    v_existing  TEXT;
    v_rejection TEXT;
BEGIN
    IF p_job_id IS NULL OR p_lease_epoch IS NULL OR p_lease_epoch < 1
            OR p_lease_token IS NULL OR p_lease_token !~ '^[0-9a-f]{64}$'
            OR p_name IS NULL OR p_name !~ '^[a-z0-9][a-z0-9._-]{0,63}$' OR p_name LIKE '%..%'
            OR p_media_type IS NULL OR p_media_type NOT IN ('application/json', 'application/sarif+json', 'text/plain')
            OR p_content IS NULL OR octet_length(p_content) > 1048576 THEN
        RAISE EXCEPTION 'invalid evidence' USING ERRCODE = '22023';
    END IF;
    -- Only the job row is locked: uploads do not change the scan.
    SELECT j.* INTO v_job FROM public.scan_jobs j WHERE j.id = p_job_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'REJECTED_UNKNOWN_JOB'::text, NULL::text, NULL::integer;
        RETURN;
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = v_job.scan_id;
    v_rejection := lifecycle.lease_rejection(v_job, v_scan.deadline_at, p_lease_epoch,
        encode(sha256(convert_to(p_lease_token, 'UTF8')), 'hex'));
    IF v_rejection IS NULL AND (
            (SELECT count(*) FROM evidence.job_artifacts a
             WHERE a.job_id = p_job_id AND a.lease_epoch = p_lease_epoch AND a.name <> p_name) >= 16
            OR (SELECT coalesce(sum(a.size_bytes), 0) FROM evidence.job_artifacts a
                WHERE a.job_id = p_job_id AND a.lease_epoch = p_lease_epoch AND a.name <> p_name)
               + octet_length(p_content) > 8388608) THEN
        v_rejection := 'QUOTA_EXCEEDED';
    END IF;
    IF v_rejection IS NOT NULL THEN
        PERFORM lifecycle.note_rejection(v_job.scan_id, v_job.id, p_lease_epoch, v_job.lease_epoch, 'EVIDENCE',
            v_rejection);
        RETURN QUERY SELECT 'REJECTED_' || v_rejection, NULL::text, NULL::integer;
        RETURN;
    END IF;

    v_sha := encode(sha256(p_content), 'hex');
    v_size := octet_length(p_content);
    SELECT a.sha256 INTO v_existing FROM evidence.job_artifacts a
     WHERE a.job_id = p_job_id AND a.lease_epoch = p_lease_epoch AND a.name = p_name;
    IF FOUND THEN
        IF v_existing = v_sha THEN
            RETURN QUERY SELECT 'DUPLICATE'::text, v_sha, v_size;
            RETURN;
        END IF;
        PERFORM lifecycle.note_rejection(v_job.scan_id, v_job.id, p_lease_epoch, v_job.lease_epoch, 'EVIDENCE',
            'CONFLICT');
        RETURN QUERY SELECT 'CONFLICT'::text, NULL::text, NULL::integer;
        RETURN;
    END IF;

    SELECT p.organization_id INTO v_org FROM public.projects p WHERE p.id = v_scan.project_id;
    INSERT INTO evidence.objects AS o (organization_id, sha256, size_bytes, content, retain_until)
    VALUES (v_org, v_sha, v_size, p_content, now() + make_interval(days => v_scan.evidence_retention_days))
    ON CONFLICT (organization_id, sha256) DO UPDATE
        SET retain_until = greatest(o.retain_until, excluded.retain_until),
            -- Re-uploading purged content restores it (the CHECK verifies the bytes).
            content = coalesce(o.content, excluded.content),
            purged_at = CASE WHEN o.content IS NULL THEN NULL ELSE o.purged_at END;
    INSERT INTO evidence.job_artifacts (job_id, lease_epoch, name, organization_id, sha256, media_type, size_bytes,
        uploaded_by)
    VALUES (p_job_id, p_lease_epoch, p_name, v_org, v_sha, p_media_type, v_size, session_user);
    RETURN QUERY SELECT 'STORED'::text, v_sha, v_size;
END
$fn$;

-- Submits the result of the caller's lease as one job-result.v1 document. Atomic: the
-- validation, the report record, the evidence binding and the state change commit
-- together or not at all. Returns:
--   ACCEPTED, DUPLICATE (identical document already accepted for this lease),
--   CONFLICT (a different document was accepted for this lease; audited),
--   REJECTED_UNSUPPORTED_SCHEMA_VERSION (schema_version is not 1),
--   REJECTED_UNKNOWN_JOB, REJECTED_SCAN_MISMATCH, REJECTED_STALE_EPOCH,
--   REJECTED_UNKNOWN_EPOCH, REJECTED_NOT_LEASE_OWNER, REJECTED_TOKEN_MISMATCH,
--   REJECTED_JOB_NOT_RUNNING, REJECTED_LEASE_EXPIRED, REJECTED_DEADLINE_EXCEEDED,
--   REJECTED_CONTEXT_MISMATCH (project, organization, commit, scanner type or attempt
--   differ from the authoritative rows), REJECTED_MISSING_ARTIFACT (not uploaded under this
--   lease, e.g. another tenant's or another job's object), REJECTED_ARTIFACT_MISMATCH
--   (digest, size or media type differ from what the database computed at upload).
-- Malformed or oversized documents (more than 16 KiB) raise SQLSTATE 22023.
CREATE FUNCTION worker.submit_result(p_lease_token TEXT, p_result TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_json       JSON;
    v_doc        JSONB;
    v_hash       TEXT;
    v_result_sha TEXT;
    v_job_id     UUID;
    v_scan_id    UUID;
    v_epoch      BIGINT;
    v_scan       public.scans%ROWTYPE;
    v_job        public.scan_jobs%ROWTYPE;
    v_project    public.projects%ROWTYPE;
    v_report     lifecycle.job_reports%ROWTYPE;
    v_artifact   JSONB;
    v_upload     evidence.job_artifacts%ROWTYPE;
    v_rejection  TEXT;
    v_now        TIMESTAMPTZ;
BEGIN
    IF p_lease_token IS NULL OR p_lease_token !~ '^[0-9a-f]{64}$'
            OR p_result IS NULL OR octet_length(p_result) > 16384 THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END IF;
    BEGIN
        v_json := p_result::json;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END;
    IF json_typeof(v_json) <> 'object' THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END IF;
    IF json_typeof(v_json -> 'schema_version') = 'number' AND (v_json ->> 'schema_version') ~ '^[1-9][0-9]{0,8}$'
            AND (v_json ->> 'schema_version') <> '1' THEN
        RETURN 'REJECTED_UNSUPPORTED_SCHEMA_VERSION';
    END IF;
    IF json_typeof(v_json -> 'schema_version') IS DISTINCT FROM 'number' OR (v_json ->> 'schema_version') <> '1' THEN
        RAISE EXCEPTION 'invalid job result' USING ERRCODE = '22023';
    END IF;
    v_doc := lifecycle.validate_job_result(v_json);

    v_hash := encode(sha256(convert_to(p_lease_token, 'UTF8')), 'hex');
    -- Identity of the result: the exact bytes received (canonical serialization).
    v_result_sha := encode(sha256(convert_to(p_result, 'UTF8')), 'hex');
    v_job_id := (v_doc ->> 'job_id')::uuid;
    v_epoch := (v_doc ->> 'lease_epoch')::bigint;

    SELECT j.scan_id INTO v_scan_id FROM public.scan_jobs j WHERE j.id = v_job_id;
    IF NOT FOUND THEN
        RETURN 'REJECTED_UNKNOWN_JOB';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = v_scan_id FOR UPDATE;
    SELECT j.* INTO v_job FROM public.scan_jobs j WHERE j.id = v_job_id FOR UPDATE;

    IF v_scan_id <> (v_doc ->> 'scan_id')::uuid THEN
        v_rejection := 'SCAN_MISMATCH';
    ELSE
        SELECT r.* INTO v_report FROM lifecycle.job_reports r WHERE r.job_id = v_job_id AND r.lease_epoch = v_epoch;
        IF FOUND AND v_report.lease_owner = session_user AND v_report.lease_token_sha256 = v_hash THEN
            IF v_report.result_sha256 = v_result_sha THEN
                RETURN 'DUPLICATE';
            END IF;
            PERFORM lifecycle.note_rejection(v_scan.id, v_job.id, v_epoch, v_job.lease_epoch, 'RESULT', 'CONFLICT');
            RETURN 'CONFLICT';
        END IF;
        v_rejection := lifecycle.lease_rejection(v_job, v_scan.deadline_at, v_epoch, v_hash);
    END IF;

    IF v_rejection IS NULL THEN
        SELECT p.* INTO v_project FROM public.projects p WHERE p.id = v_scan.project_id;
        IF v_project.id <> (v_doc ->> 'project_id')::uuid
                OR v_project.organization_id <> (v_doc ->> 'organization_id')::uuid
                OR v_scan.commit_sha <> (v_doc ->> 'commit_sha')
                OR v_job.scanner_type <> (v_doc ->> 'scanner_type')
                OR v_job.attempt_count <> (v_doc ->> 'attempt')::integer THEN
            v_rejection := 'CONTEXT_MISMATCH';
        END IF;
    END IF;

    IF v_rejection IS NULL THEN
        FOR v_artifact IN SELECT a FROM jsonb_array_elements(v_doc -> 'artifacts') a LOOP
            -- Only uploads bound to this job and lease resolve: another tenant's or another
            -- job's object with the same digest is never found here.
            SELECT u.* INTO v_upload FROM evidence.job_artifacts u
             WHERE u.job_id = v_job_id AND u.lease_epoch = v_epoch AND u.name = v_artifact ->> 'name';
            IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM evidence.objects o
                    WHERE o.organization_id = v_upload.organization_id AND o.sha256 = v_upload.sha256
                      AND o.content IS NOT NULL) THEN
                v_rejection := 'MISSING_ARTIFACT';
                EXIT;
            END IF;
            IF v_upload.organization_id <> v_project.organization_id
                    OR v_upload.sha256 <> v_artifact ->> 'sha256'
                    OR v_upload.size_bytes <> (v_artifact ->> 'size_bytes')::integer
                    OR v_upload.media_type <> v_artifact ->> 'media_type' THEN
                v_rejection := 'ARTIFACT_MISMATCH';
                EXIT;
            END IF;
        END LOOP;
    END IF;

    IF v_rejection IS NOT NULL THEN
        PERFORM lifecycle.note_rejection(v_scan.id, v_job.id, v_epoch, v_job.lease_epoch, 'RESULT', v_rejection);
        RETURN 'REJECTED_' || v_rejection;
    END IF;

    v_now := greatest(now(), v_scan.updated_at, v_job.updated_at);
    INSERT INTO lifecycle.job_reports (job_id, lease_epoch, lease_owner, lease_token_sha256, outcome,
        failure_reason, reported_at, result_sha256, result)
    VALUES (v_job_id, v_epoch, session_user, v_hash, v_doc ->> 'outcome', v_doc ->> 'failure_reason', v_now,
        v_result_sha, v_doc);
    INSERT INTO evidence.result_artifacts (job_id, lease_epoch, name)
    SELECT v_job_id, v_epoch, a ->> 'name' FROM jsonb_array_elements(v_doc -> 'artifacts') a;
    PERFORM lifecycle.apply_job_outcome(v_scan.id, v_job.id, v_epoch, v_job.attempt_count, v_doc ->> 'outcome',
        v_doc ->> 'failure_reason', v_now);
    RETURN 'ACCEPTED';
END
$fn$;

-- V007's report_job accepted outcomes without a result document or evidence binding.
DROP FUNCTION worker.report_job(UUID, UUID, BIGINT, TEXT, TEXT, TEXT);

-- ---------------------------------------------------------------------------
-- 5. Control-plane evidence access and retention (EXECUTE: sentinel_api)
-- ---------------------------------------------------------------------------

-- Evidence of record of a job: the artifacts referenced by its accepted results, with
-- metadata only. The API authorizes the caller for the job's organization first.
CREATE FUNCTION evidence.list_result_artifacts(p_job_id UUID)
RETURNS TABLE (lease_epoch BIGINT, name VARCHAR, media_type VARCHAR, sha256 CHAR, size_bytes INTEGER,
    stored_at TIMESTAMPTZ, purged BOOLEAN)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT u.lease_epoch, u.name, u.media_type, u.sha256, u.size_bytes, u.uploaded_at, o.content IS NULL
    FROM evidence.result_artifacts r
    JOIN evidence.job_artifacts u ON u.job_id = r.job_id AND u.lease_epoch = r.lease_epoch AND u.name = r.name
    JOIN evidence.objects o ON o.organization_id = u.organization_id AND o.sha256 = u.sha256
    WHERE r.job_id = p_job_id
    ORDER BY u.lease_epoch, u.name;
$fn$;

-- The bytes of one artifact of record, with the digest recorded at upload. Callers verify
-- the bytes against the digest before use (defense in depth for future external storage).
CREATE FUNCTION evidence.read_result_artifact(p_job_id UUID, p_lease_epoch BIGINT, p_name TEXT)
RETURNS TABLE (media_type VARCHAR, sha256 CHAR, size_bytes INTEGER, content BYTEA)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT u.media_type, u.sha256, u.size_bytes, o.content
    FROM evidence.result_artifacts r
    JOIN evidence.job_artifacts u ON u.job_id = r.job_id AND u.lease_epoch = r.lease_epoch AND u.name = r.name
    JOIN evidence.objects o ON o.organization_id = u.organization_id AND o.sha256 = u.sha256
    WHERE r.job_id = p_job_id AND r.lease_epoch = p_lease_epoch AND r.name = p_name;
$fn$;

-- Removes the content of objects past their retention, in a bounded batch. Digests, sizes,
-- bindings and results remain. Safe on several instances (SKIP LOCKED).
CREATE FUNCTION evidence.purge_expired(p_limit INTEGER DEFAULT 100)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'limit must be between 1 and 1000' USING ERRCODE = '22023';
    END IF;
    WITH expired AS (
        SELECT o.organization_id, o.sha256 FROM evidence.objects o
        WHERE o.content IS NOT NULL AND o.retain_until <= now()
        ORDER BY o.retain_until
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    UPDATE evidence.objects o SET content = NULL, purged_at = now()
    FROM expired e
    WHERE o.organization_id = e.organization_id AND o.sha256 = e.sha256;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END
$fn$;

-- Low-cardinality execution gauges for the API's metrics.
CREATE FUNCTION lifecycle.execution_summary()
RETURNS TABLE (queued_jobs BIGINT, running_jobs BIGINT, retry_pending_jobs BIGINT, evaluating_scans BIGINT,
    oldest_running_seconds DOUBLE PRECISION)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT (SELECT count(*) FROM public.scan_jobs WHERE execution_status = 'QUEUED'),
           (SELECT count(*) FROM public.scan_jobs WHERE execution_status = 'RUNNING'),
           (SELECT count(*) FROM public.scan_jobs WHERE execution_status = 'QUEUED' AND attempt_count > 0),
           (SELECT count(*) FROM public.scans WHERE execution_status = 'EVALUATING'),
           coalesce((SELECT extract(epoch FROM now() - min(started_at)) FROM public.scan_jobs
                     WHERE execution_status = 'RUNNING'), 0)::double precision;
$fn$;

-- Refused operations by sanitized reason (fixed enumeration), for the API's metrics.
CREATE FUNCTION lifecycle.rejection_summary()
RETURNS TABLE (operation VARCHAR, detail VARCHAR, occurrences BIGINT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT r.operation, r.detail, sum(r.occurrences)::bigint
    FROM lifecycle.report_rejections r
    GROUP BY r.operation, r.detail;
$fn$;

-- ---------------------------------------------------------------------------
-- 6. Privileges
-- ---------------------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA evidence FROM PUBLIC;
REVOKE ALL ON lifecycle.report_rejections FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.note_rejection(UUID, UUID, BIGINT, BIGINT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.lease_rejection(public.scan_jobs, TIMESTAMPTZ, BIGINT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.apply_job_outcome(UUID, UUID, BIGINT, INTEGER, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.validate_job_result(JSON) FROM PUBLIC;
REVOKE ALL ON FUNCTION worker.put_evidence(UUID, BIGINT, TEXT, TEXT, TEXT, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION worker.submit_result(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION evidence.list_result_artifacts(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION evidence.read_result_artifact(UUID, BIGINT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION evidence.purge_expired(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.execution_summary() FROM PUBLIC;
REVOKE ALL ON FUNCTION lifecycle.rejection_summary() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION worker.put_evidence(UUID, BIGINT, TEXT, TEXT, TEXT, BYTEA) TO sentinel_worker;
GRANT EXECUTE ON FUNCTION worker.submit_result(TEXT, TEXT) TO sentinel_worker;

-- The API reads evidence and audit data only through these functions (no table access).
GRANT USAGE ON SCHEMA evidence TO sentinel_api;
GRANT EXECUTE ON FUNCTION evidence.list_result_artifacts(UUID) TO sentinel_api;
GRANT EXECUTE ON FUNCTION evidence.read_result_artifact(UUID, BIGINT, TEXT) TO sentinel_api;
GRANT EXECUTE ON FUNCTION evidence.purge_expired(INTEGER) TO sentinel_api;
GRANT EXECUTE ON FUNCTION lifecycle.execution_summary() TO sentinel_api;
GRANT EXECUTE ON FUNCTION lifecycle.rejection_summary() TO sentinel_api;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.result_integrity', 'm3-phase1');

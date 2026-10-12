-- V010: Milestone 4, Phase 2. Historical policy re-evaluation (ADR-0014).
--
-- A historical re-evaluation answers: "given the evidence of record persisted for scan S,
-- what decision would policy version P produce?" It is a new, immutable, non-gating record
-- next to the scan's original evaluation; it never changes the scan, its decision, its
-- pinned policy, its jobs, the active project policy or the original evaluation.
--
-- 1. Records live in their own append-only tables. policy.evaluations keeps its V009
--    invariants untouched: one gating record per scan, bound to the pinned version, and
--    the only kind of record policy.require_evaluation_record accepts for a scan decision.
-- 2. Inputs are the same as the original evaluation's: the evidence of record read by
--    policy.job_evidence, measured at the original decision time (the original
--    evaluation's evaluated_as_of, or the scan's completion time when it has none), never
--    at the wall clock. Only COMPLETED scans are eligible: every job is terminal and no
--    worker can change the evidence.
-- 3. policy.historical_inputs_sha256 fingerprints those inputs. The API reads the inputs and
--    the fingerprint in one snapshot; policy.record_historical_evaluation recomputes it
--    under the scan row lock and refuses a record whose inputs changed in between
--    (INPUTS_CHANGED), for example by evidence retention.
-- 4. Identity: (scan, policy version, engine version, inputs fingerprint). Repeating a
--    request returns the existing record (EXISTING) and never writes a second one; a
--    different result for the same identity is refused (NONDETERMINISTIC). Changed inputs
--    or a new engine version produce a new, distinguishable record.
-- 5. The database re-checks every record like policy.record_evaluation: decision
--    precedence, evidence of record of this scan, violations backed by referenced
--    evidence, PASS only with complete evidence for exactly the policy's scanners. The
--    policy version must belong to the scan's organization and carry the recorded digest
--    (composite foreign keys, also for direct SQL).
-- 6. At most 100 historical records per scan (LIMIT_REACHED), serialized by the scan row
--    lock (FOR NO KEY UPDATE: re-evaluations of one scan wait for each other; foreign-key
--    checks of rows that reference the scan never wait for them).

-- ---------------------------------------------------------------------------
-- 1. Keys
-- ---------------------------------------------------------------------------

-- Lets a record prove declaratively that its digest is the digest of its policy version.
ALTER TABLE policy.policy_versions
    ADD CONSTRAINT uq_policy_versions_id_sha256 UNIQUE (id, definition_sha256);

-- ---------------------------------------------------------------------------
-- 2. Tables
-- ---------------------------------------------------------------------------

CREATE TABLE policy.historical_evaluations (
    id                UUID         NOT NULL DEFAULT gen_random_uuid(),
    scan_id           UUID         NOT NULL,
    project_id        UUID         NOT NULL,
    organization_id   UUID         NOT NULL,
    policy_version_id UUID         NOT NULL,
    policy_sha256     CHAR(64)     NOT NULL,
    engine_version    VARCHAR(40)  NOT NULL,
    decision          VARCHAR(20)  NOT NULL,
    violation_count   INTEGER      NOT NULL,
    incomplete_count  INTEGER      NOT NULL,
    reasons           TEXT         NOT NULL,
    reasons_sha256    CHAR(64)     NOT NULL,
    inputs_sha256     CHAR(64)     NOT NULL,
    evaluated_as_of   TIMESTAMPTZ  NOT NULL,
    requested_by      VARCHAR(100) NOT NULL,
    recorded_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    recorded_by       VARCHAR(63)  NOT NULL DEFAULT session_user,
    CONSTRAINT pk_historical_evaluations PRIMARY KEY (id),
    CONSTRAINT uq_historical_evaluations_identity UNIQUE (scan_id, policy_version_id, engine_version, inputs_sha256),
    CONSTRAINT uq_historical_evaluations_id_scan UNIQUE (id, scan_id),
    CONSTRAINT fk_historical_evaluations_scan FOREIGN KEY (scan_id, project_id)
        REFERENCES public.scans (id, project_id) ON DELETE RESTRICT,
    CONSTRAINT fk_historical_evaluations_project FOREIGN KEY (project_id, organization_id)
        REFERENCES public.projects (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_historical_evaluations_version FOREIGN KEY (policy_version_id, organization_id)
        REFERENCES policy.policy_versions (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_historical_evaluations_digest FOREIGN KEY (policy_version_id, policy_sha256)
        REFERENCES policy.policy_versions (id, definition_sha256) ON DELETE RESTRICT,
    CONSTRAINT ck_historical_evaluations_digests CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'
        AND inputs_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_historical_evaluations_engine CHECK (engine_version ~ '^[a-z0-9][a-z0-9./-]{0,39}$'),
    CONSTRAINT ck_historical_evaluations_decision CHECK (decision IN ('PASS', 'FAIL', 'INCOMPLETE')),
    CONSTRAINT ck_historical_evaluations_counts CHECK (violation_count BETWEEN 0 AND 512
        AND incomplete_count BETWEEN 0 AND 512),
    -- Same precedence as policy.evaluations (ADR-0013).
    CONSTRAINT ck_historical_evaluations_precedence CHECK (
        (decision = 'FAIL') = (violation_count > 0)
        AND (decision = 'PASS') = (violation_count = 0 AND incomplete_count = 0)
    ),
    CONSTRAINT ck_historical_evaluations_reasons CHECK (octet_length(reasons) BETWEEN 2 AND 131072
        AND reasons ~ '^[\x20-\x7e]+$'),
    CONSTRAINT ck_historical_evaluations_reasons_integrity
        CHECK (reasons_sha256 = encode(sha256(convert_to(reasons, 'UTF8')), 'hex')),
    -- The requester is an internal identity reference, never a name, e-mail or token subject.
    CONSTRAINT ck_historical_evaluations_requested_by
        CHECK (requested_by ~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
);

CREATE INDEX ix_historical_evaluations_scan ON policy.historical_evaluations (scan_id, recorded_at, id);

COMMENT ON TABLE policy.historical_evaluations IS
    'Immutable, non-gating re-evaluations of a completed scan''s evidence of record under an explicit policy version.';

CREATE TABLE policy.historical_evaluation_evidence (
    evaluation_id UUID        NOT NULL,
    scan_id       UUID        NOT NULL,
    job_id        UUID        NOT NULL,
    scanner_type  VARCHAR(20) NOT NULL,
    lease_epoch   BIGINT      NOT NULL,
    name          VARCHAR(64) NOT NULL,
    sha256        CHAR(64)    NOT NULL,
    result_sha256 CHAR(64)    NOT NULL,
    CONSTRAINT pk_historical_evaluation_evidence PRIMARY KEY (evaluation_id, job_id),
    CONSTRAINT fk_historical_evaluation_evidence_evaluation FOREIGN KEY (evaluation_id, scan_id)
        REFERENCES policy.historical_evaluations (id, scan_id) ON DELETE RESTRICT,
    CONSTRAINT fk_historical_evaluation_evidence_job FOREIGN KEY (job_id, scan_id)
        REFERENCES public.scan_jobs (id, scan_id) ON DELETE RESTRICT,
    CONSTRAINT fk_historical_evaluation_evidence_report FOREIGN KEY (job_id, lease_epoch)
        REFERENCES lifecycle.job_reports (job_id, lease_epoch) ON DELETE RESTRICT,
    CONSTRAINT fk_historical_evaluation_evidence_artifact FOREIGN KEY (job_id, lease_epoch, name)
        REFERENCES evidence.result_artifacts (job_id, lease_epoch, name) ON DELETE RESTRICT,
    CONSTRAINT ck_historical_evaluation_evidence_digests
        CHECK (sha256 ~ '^[0-9a-f]{64}$' AND result_sha256 ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE policy.historical_evaluation_evidence IS
    'Evidence of record referenced by a historical re-evaluation (digests at re-evaluation time).';

-- ---------------------------------------------------------------------------
-- 3. Immutability (as for every policy record, V009)
-- ---------------------------------------------------------------------------

CREATE TRIGGER tr_historical_evaluations_immutable BEFORE UPDATE OR DELETE ON policy.historical_evaluations
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_historical_evaluation_evidence_immutable
    BEFORE UPDATE OR DELETE ON policy.historical_evaluation_evidence
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_historical_evaluations_no_truncate BEFORE TRUNCATE ON policy.historical_evaluations
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_historical_evaluation_evidence_no_truncate BEFORE TRUNCATE ON policy.historical_evaluation_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();

-- ---------------------------------------------------------------------------
-- 4. Inputs
-- ---------------------------------------------------------------------------

-- Fingerprint of everything the engine reads about a scan's jobs (policy.job_evidence),
-- plus the as-of instant. Owner-only helper. Content bytes are bound to their digest by
-- evidence.objects' integrity CHECK, so only their presence is fingerprinted.
CREATE FUNCTION policy.historical_inputs_sha256(p_scan_id UUID, p_as_of TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT encode(sha256(convert_to(
        'sentinelpipe-historical-inputs/1|' || p_scan_id::text || '|'
            || to_char(p_as_of AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || E'\n'
            || coalesce(string_agg(concat_ws('|',
                   e.job_id::text, e.scanner_type, e.job_status, coalesce(e.failure_reason, '-'),
                   coalesce(e.lease_epoch::text, '-'),
                   coalesce(to_char(e.job_completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), '-'),
                   coalesce(e.result_sha256, '-'),
                   coalesce(encode(sha256(convert_to(e.result, 'UTF8')), 'hex'), '-'),
                   coalesce(e.artifact_name, '-'), coalesce(e.artifact_media_type, '-'),
                   coalesce(e.artifact_sha256, '-'), coalesce(e.artifact_size::text, '-'),
                   CASE WHEN e.artifact_name IS NULL THEN '-'
                        WHEN e.artifact_content IS NULL THEN 'purged' ELSE 'present' END),
               E'\n' ORDER BY e.job_id, e.artifact_name), ''),
        'UTF8')), 'hex')
    FROM policy.job_evidence(p_scan_id) e;
$fn$;

-- The scan context of a re-evaluation: its tenant binding, its execution status, the
-- historical as-of instant and the inputs fingerprint (only for a COMPLETED scan). Zero
-- rows: unknown scan.
CREATE FUNCTION policy.historical_context(p_scan_id UUID)
RETURNS TABLE (scan_id UUID, project_id UUID, organization_id UUID, commit_sha VARCHAR, execution_status VARCHAR,
    evaluated_as_of TIMESTAMPTZ, inputs_sha256 TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT s.id, s.project_id, p.organization_id, s.commit_sha, s.execution_status, a.as_of,
           CASE WHEN s.execution_status = 'COMPLETED' AND a.as_of IS NOT NULL
                THEN policy.historical_inputs_sha256(s.id, a.as_of) END
    FROM public.scans s
    JOIN public.projects p ON p.id = s.project_id
    CROSS JOIN LATERAL (
        SELECT coalesce((SELECT e.evaluated_as_of FROM policy.evaluations e WHERE e.scan_id = s.id),
                        s.completed_at) AS as_of) a
    WHERE s.id = p_scan_id;
$fn$;

-- ---------------------------------------------------------------------------
-- 5. Recording a historical re-evaluation (EXECUTE: sentinel_api)
-- ---------------------------------------------------------------------------

-- Records a re-evaluation of a COMPLETED scan under p_policy_version_id. Returns one row
-- (outcome, evaluation_id): RECORDED (new record), EXISTING (the same identity was
-- recorded before: its id), NOT_FOUND, NOT_COMPLETED, POLICY_VERSION_NOT_FOUND (also for a
-- version of another organization) or LIMIT_REACHED. Nothing about the scan, its jobs,
-- its pin or its original evaluation changes. An inconsistent record raises SQLSTATE 22023
-- with a fixed 'evaluation rejected: <CODE>' message and changes nothing.
--
-- p_evidence: canonical JSON array of {job_id, lease_epoch, name, result_sha256,
-- scanner_type, sha256}, at most one entry per job (as for policy.record_evaluation).
CREATE FUNCTION policy.record_historical_evaluation(p_scan_id UUID, p_policy_version_id UUID, p_policy_sha256 TEXT,
    p_engine_version TEXT, p_decision TEXT, p_reasons TEXT, p_evidence TEXT, p_as_of TIMESTAMPTZ,
    p_inputs_sha256 TEXT, p_actor TEXT)
RETURNS TABLE (outcome TEXT, evaluation_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_scan       public.scans%ROWTYPE;
    v_org        UUID;
    v_version    policy.policy_versions%ROWTYPE;
    v_counts     RECORD;
    v_expected   TEXT;
    v_as_of      TIMESTAMPTZ;
    v_evidence   JSON;
    v_entry      JSON;
    v_keys       TEXT[];
    v_job        public.scan_jobs%ROWTYPE;
    v_jobs_seen  UUID[] := ARRAY[]::UUID[];
    v_scanners   TEXT[] := ARRAY[]::TEXT[];
    v_policy_set TEXT[];
    v_job_set    TEXT[];
    v_reasons_sha TEXT;
    v_existing   policy.historical_evaluations%ROWTYPE;
    v_eval_id    UUID;
BEGIN
    IF p_scan_id IS NULL OR p_policy_version_id IS NULL
            OR p_policy_sha256 IS NULL OR p_policy_sha256 !~ '^[0-9a-f]{64}$'
            OR p_engine_version IS NULL OR p_engine_version !~ '^[a-z0-9][a-z0-9./-]{0,39}$'
            OR p_decision IS NULL OR p_decision NOT IN ('PASS', 'FAIL', 'INCOMPLETE')
            OR p_evidence IS NULL OR octet_length(p_evidence) > 16384 OR p_evidence !~ '^[\x20-\x7e]+$'
            OR p_as_of IS NULL
            OR p_inputs_sha256 IS NULL OR p_inputs_sha256 !~ '^[0-9a-f]{64}$'
            OR p_actor IS NULL
            OR p_actor !~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_ARGUMENTS' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_counts FROM policy.validate_reasons(p_reasons);

    -- Serializes re-evaluations of one scan (identity, limit) without affecting its state.
    -- NO KEY UPDATE conflicts with itself but not with the KEY SHARE locks of foreign-key
    -- checks, so inserting rows that reference the scan never waits for a re-evaluation.
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'NOT_FOUND'::text, NULL::uuid;
        RETURN;
    END IF;
    IF v_scan.execution_status <> 'COMPLETED' THEN
        RETURN QUERY SELECT 'NOT_COMPLETED'::text, NULL::uuid;
        RETURN;
    END IF;
    SELECT p.organization_id INTO v_org FROM public.projects p WHERE p.id = v_scan.project_id;

    -- The policy version must belong to the scan's organization, with the recorded digest.
    SELECT v.* INTO v_version FROM policy.policy_versions v
     WHERE v.id = p_policy_version_id AND v.organization_id = v_org;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'POLICY_VERSION_NOT_FOUND'::text, NULL::uuid;
        RETURN;
    END IF;
    IF v_version.definition_sha256 <> p_policy_sha256 THEN
        RAISE EXCEPTION 'evaluation rejected: POLICY_MISMATCH' USING ERRCODE = '22023';
    END IF;

    -- Same inputs as read by the API: the historical as-of instant and the evidence.
    SELECT coalesce((SELECT e.evaluated_as_of FROM policy.evaluations e WHERE e.scan_id = p_scan_id),
                    v_scan.completed_at) INTO v_as_of;
    IF v_as_of IS NULL OR v_as_of <> p_as_of THEN
        RAISE EXCEPTION 'evaluation rejected: AS_OF_MISMATCH' USING ERRCODE = '22023';
    END IF;
    IF policy.historical_inputs_sha256(p_scan_id, v_as_of) <> p_inputs_sha256 THEN
        RAISE EXCEPTION 'evaluation rejected: INPUTS_CHANGED' USING ERRCODE = '22023';
    END IF;

    -- The decision must follow from the reasons (precedence: FAIL, INCOMPLETE, PASS).
    v_expected := CASE WHEN v_counts.violations > 0 THEN 'FAIL'
                       WHEN v_counts.incompletes > 0 THEN 'INCOMPLETE'
                       ELSE 'PASS' END;
    IF v_expected <> p_decision THEN
        RAISE EXCEPTION 'evaluation rejected: DECISION_INCONSISTENT' USING ERRCODE = '22023';
    END IF;

    -- Every evidence reference must be evidence of record of one of this scan's jobs.
    BEGIN
        v_evidence := p_evidence::json;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_EVIDENCE' USING ERRCODE = '22023';
    END;
    IF json_typeof(v_evidence) <> 'array' OR json_array_length(v_evidence) > 16 THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_EVIDENCE' USING ERRCODE = '22023';
    END IF;
    FOR v_entry IN SELECT e FROM json_array_elements(v_evidence) e LOOP
        IF json_typeof(v_entry) <> 'object' THEN
            RAISE EXCEPTION 'evaluation rejected: INVALID_EVIDENCE' USING ERRCODE = '22023';
        END IF;
        SELECT array_agg(k ORDER BY k) INTO v_keys FROM json_object_keys(v_entry) k;
        IF v_keys IS DISTINCT FROM ARRAY['job_id', 'lease_epoch', 'name', 'result_sha256', 'scanner_type', 'sha256']
                OR json_typeof(v_entry -> 'job_id') <> 'string'
                OR (v_entry ->> 'job_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                OR json_typeof(v_entry -> 'lease_epoch') <> 'number'
                OR (v_entry ->> 'lease_epoch') !~ '^[1-9][0-9]{0,8}$'
                OR json_typeof(v_entry -> 'name') <> 'string'
                OR (v_entry ->> 'name') !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
                OR json_typeof(v_entry -> 'result_sha256') <> 'string'
                OR (v_entry ->> 'result_sha256') !~ '^[0-9a-f]{64}$'
                OR json_typeof(v_entry -> 'scanner_type') <> 'string'
                OR json_typeof(v_entry -> 'sha256') <> 'string'
                OR (v_entry ->> 'sha256') !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'evaluation rejected: INVALID_EVIDENCE' USING ERRCODE = '22023';
        END IF;
        SELECT j.* INTO v_job FROM public.scan_jobs j
         WHERE j.id = (v_entry ->> 'job_id')::uuid AND j.scan_id = p_scan_id;
        IF NOT FOUND OR (v_entry ->> 'job_id')::uuid = ANY (v_jobs_seen)
                OR v_job.execution_status <> 'COMPLETED'
                OR v_job.scanner_type <> (v_entry ->> 'scanner_type')
                OR v_job.lease_epoch <> (v_entry ->> 'lease_epoch')::bigint
                OR NOT EXISTS (SELECT 1 FROM lifecycle.job_reports r
                               WHERE r.job_id = v_job.id AND r.lease_epoch = v_job.lease_epoch
                                 AND r.outcome = 'COMPLETED' AND r.result_sha256 = (v_entry ->> 'result_sha256'))
                OR NOT EXISTS (SELECT 1 FROM evidence.result_artifacts ra
                               JOIN evidence.job_artifacts u ON u.job_id = ra.job_id
                                    AND u.lease_epoch = ra.lease_epoch AND u.name = ra.name
                               WHERE ra.job_id = v_job.id AND ra.lease_epoch = v_job.lease_epoch
                                 AND ra.name = (v_entry ->> 'name') AND u.sha256 = (v_entry ->> 'sha256')) THEN
            RAISE EXCEPTION 'evaluation rejected: EVIDENCE_NOT_OF_RECORD' USING ERRCODE = '22023';
        END IF;
        v_jobs_seen := v_jobs_seen || v_job.id;
        v_scanners := v_scanners || v_job.scanner_type::text;
    END LOOP;

    -- A violation must come from evidence this record references.
    IF NOT v_counts.scanners <@ v_scanners THEN
        RAISE EXCEPTION 'evaluation rejected: VIOLATION_WITHOUT_EVIDENCE' USING ERRCODE = '22023';
    END IF;

    -- PASS backstop: complete evidence for every job, exactly the requested policy's scanners.
    IF p_decision = 'PASS' THEN
        SELECT array_agg(k ORDER BY k) INTO v_policy_set
          FROM jsonb_object_keys(v_version.definition::jsonb -> 'scanners') k;
        SELECT array_agg(j.scanner_type::text ORDER BY j.scanner_type) INTO v_job_set
          FROM public.scan_jobs j WHERE j.scan_id = p_scan_id;
        IF v_job_set IS NULL
                OR EXISTS (SELECT 1 FROM public.scan_jobs j
                           WHERE j.scan_id = p_scan_id AND j.execution_status <> 'COMPLETED')
                OR cardinality(v_jobs_seen) <> cardinality(v_job_set)
                OR v_job_set IS DISTINCT FROM v_policy_set THEN
            RAISE EXCEPTION 'evaluation rejected: PASS_NOT_JUSTIFIED' USING ERRCODE = '22023';
        END IF;
    END IF;

    -- Idempotency: the same identity yields the same record, never a second or different one.
    v_reasons_sha := encode(sha256(convert_to(p_reasons, 'UTF8')), 'hex');
    SELECT h.* INTO v_existing FROM policy.historical_evaluations h
     WHERE h.scan_id = p_scan_id AND h.policy_version_id = p_policy_version_id
       AND h.engine_version = p_engine_version AND h.inputs_sha256 = p_inputs_sha256;
    IF FOUND THEN
        IF v_existing.decision <> p_decision OR v_existing.reasons_sha256 <> v_reasons_sha THEN
            RAISE EXCEPTION 'evaluation rejected: NONDETERMINISTIC' USING ERRCODE = '22023';
        END IF;
        RETURN QUERY SELECT 'EXISTING'::text, v_existing.id;
        RETURN;
    END IF;
    IF (SELECT count(*) FROM policy.historical_evaluations h WHERE h.scan_id = p_scan_id) >= 100 THEN
        RETURN QUERY SELECT 'LIMIT_REACHED'::text, NULL::uuid;
        RETURN;
    END IF;

    INSERT INTO policy.historical_evaluations (scan_id, project_id, organization_id, policy_version_id, policy_sha256,
        engine_version, decision, violation_count, incomplete_count, reasons, reasons_sha256, inputs_sha256,
        evaluated_as_of, requested_by)
    VALUES (p_scan_id, v_scan.project_id, v_org, p_policy_version_id, p_policy_sha256, p_engine_version, p_decision,
        v_counts.violations, v_counts.incompletes, p_reasons, v_reasons_sha, p_inputs_sha256, v_as_of, p_actor)
    RETURNING id INTO v_eval_id;
    INSERT INTO policy.historical_evaluation_evidence (evaluation_id, scan_id, job_id, scanner_type, lease_epoch, name,
        sha256, result_sha256)
    SELECT v_eval_id, p_scan_id, (e ->> 'job_id')::uuid, e ->> 'scanner_type', (e ->> 'lease_epoch')::bigint,
           e ->> 'name', e ->> 'sha256', e ->> 'result_sha256'
    FROM json_array_elements(v_evidence) e;
    RETURN QUERY SELECT 'RECORDED'::text, v_eval_id;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 6. Privileges
-- ---------------------------------------------------------------------------

REVOKE ALL ON policy.historical_evaluations, policy.historical_evaluation_evidence FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.historical_inputs_sha256(UUID, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.historical_context(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.record_historical_evaluation(UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ,
    TEXT, TEXT) FROM PUBLIC;

-- The API reads the records directly and writes them only through the function.
GRANT SELECT ON policy.historical_evaluations, policy.historical_evaluation_evidence TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.historical_context(UUID) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.record_historical_evaluation(UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ,
    TEXT, TEXT) TO sentinel_api;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.historical_evaluation', 'm4-phase2');

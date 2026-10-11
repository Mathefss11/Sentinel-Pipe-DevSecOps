-- V009: Milestone 4, Phase 1. Security policy engine (ADR-0013).
--
-- 1. Policies are immutable, versioned, tenant-owned documents (policy.v1). The API
--    validates a definition strictly and canonicalizes it; the database stores the
--    canonical text and recomputes its SHA-256 in a CHECK, so a stored definition can
--    never disagree with its digest.
-- 2. Activation is an append-only assignment of one policy version to one project. Composite
--    foreign keys make a cross-tenant assignment impossible: the project and the policy
--    version must belong to the same organization.
-- 3. A scan is pinned to the policy version assigned to its project when it is requested
--    (policy.pin_scan_policy, in the scan's creating transaction). Later activations never
--    change how an existing scan is evaluated.
-- 4. Evaluations are recorded with policy.record_evaluation, which completes the scan in
--    the same transaction. The database does not evaluate findings itself, but it refuses
--    any record that is not internally consistent:
--      * the decision must follow from the recorded reasons (any violation: FAIL; else any
--        incomplete reason: INCOMPLETE; else PASS);
--      * every evidence reference must be evidence of record: the accepted COMPLETED
--        result of the job's current lease epoch, and an artifact that result references;
--      * PASS additionally requires every job COMPLETED with evidence, and exactly the
--        policy's scanners;
--      * the policy must be the scan's pinned version, with the recorded digest.
--    lifecycle.complete_evaluation can no longer record PASS or FAIL at all, and cannot
--    complete a scan that has a pinned policy: such a scan's decision always comes with an
--    evaluation record.
-- 5. Policy records are append-only for every runtime role (no UPDATE or DELETE grants) and
--    guarded by triggers against changes by the owner through ordinary statements.
-- 6. Scans and jobs inserted by any role but a superuser must be born in their initial
--    state, and a policy decision can never exist without a matching evaluation record
--    (final review, defect M4-5).

CREATE SCHEMA policy;
REVOKE ALL ON SCHEMA policy FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 1. Keys that let policy tables prove tenant consistency declaratively
-- ---------------------------------------------------------------------------

ALTER TABLE projects ADD CONSTRAINT uq_projects_id_organization UNIQUE (id, organization_id);
ALTER TABLE scans ADD CONSTRAINT uq_scans_id_project UNIQUE (id, project_id);
ALTER TABLE scan_jobs ADD CONSTRAINT uq_scan_jobs_id_scan UNIQUE (id, scan_id);

-- ---------------------------------------------------------------------------
-- 2. Tables
-- ---------------------------------------------------------------------------

CREATE TABLE policy.policies (
    id              UUID         NOT NULL DEFAULT gen_random_uuid(),
    organization_id UUID         NOT NULL,
    name            VARCHAR(63)  NOT NULL,
    created_by      VARCHAR(100) NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_policies PRIMARY KEY (id),
    CONSTRAINT fk_policies_organization FOREIGN KEY (organization_id)
        REFERENCES public.organizations (id) ON DELETE RESTRICT,
    CONSTRAINT uq_policies_organization_name UNIQUE (organization_id, name),
    CONSTRAINT uq_policies_id_organization UNIQUE (id, organization_id),
    CONSTRAINT ck_policies_name CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);

COMMENT ON TABLE policy.policies IS 'Named, tenant-owned security policies; their content lives in policy_versions.';

CREATE TABLE policy.policy_versions (
    id                UUID         NOT NULL DEFAULT gen_random_uuid(),
    policy_id         UUID         NOT NULL,
    organization_id   UUID         NOT NULL,
    version           INTEGER      NOT NULL,
    schema_version    INTEGER      NOT NULL,
    definition        TEXT         NOT NULL,
    definition_sha256 CHAR(64)     NOT NULL,
    created_by        VARCHAR(100) NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_policy_versions PRIMARY KEY (id),
    CONSTRAINT fk_policy_versions_policy FOREIGN KEY (policy_id, organization_id)
        REFERENCES policy.policies (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT uq_policy_versions_policy_version UNIQUE (policy_id, version),
    CONSTRAINT uq_policy_versions_id_organization UNIQUE (id, organization_id),
    CONSTRAINT ck_policy_versions_version CHECK (version BETWEEN 1 AND 100000),
    CONSTRAINT ck_policy_versions_schema_version CHECK (schema_version = 1),
    -- Canonical policy.v1 text: printable ASCII only, bounded.
    CONSTRAINT ck_policy_versions_definition CHECK (octet_length(definition) BETWEEN 2 AND 16384
        AND definition ~ '^[\x20-\x7e]+$'),
    CONSTRAINT ck_policy_versions_integrity
        CHECK (definition_sha256 = encode(sha256(convert_to(definition, 'UTF8')), 'hex'))
);

COMMENT ON TABLE policy.policy_versions IS
    'Immutable policy.v1 definitions (canonical JSON); the digest is recomputed by a CHECK.';

-- Append-only activation history: the latest row per project is the active assignment.
CREATE TABLE policy.project_assignments (
    id                BIGINT       GENERATED ALWAYS AS IDENTITY,
    project_id        UUID         NOT NULL,
    organization_id   UUID         NOT NULL,
    policy_version_id UUID         NOT NULL,
    assigned_by       VARCHAR(100) NOT NULL,
    assigned_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_project_assignments PRIMARY KEY (id),
    CONSTRAINT fk_project_assignments_project FOREIGN KEY (project_id, organization_id)
        REFERENCES public.projects (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_project_assignments_version FOREIGN KEY (policy_version_id, organization_id)
        REFERENCES policy.policy_versions (id, organization_id) ON DELETE RESTRICT
);

CREATE INDEX ix_project_assignments_project ON policy.project_assignments (project_id, id DESC);

COMMENT ON TABLE policy.project_assignments IS
    'Policy activation history per project (append-only); the latest row is in force.';

-- The policy version in force when the scan was requested.
CREATE TABLE policy.scan_policies (
    scan_id           UUID        NOT NULL,
    project_id        UUID        NOT NULL,
    organization_id   UUID        NOT NULL,
    policy_version_id UUID        NOT NULL,
    assignment_id     BIGINT      NOT NULL,
    pinned_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_scan_policies PRIMARY KEY (scan_id),
    CONSTRAINT uq_scan_policies_scan_version UNIQUE (scan_id, policy_version_id),
    CONSTRAINT fk_scan_policies_scan FOREIGN KEY (scan_id, project_id)
        REFERENCES public.scans (id, project_id) ON DELETE RESTRICT,
    CONSTRAINT fk_scan_policies_project FOREIGN KEY (project_id, organization_id)
        REFERENCES public.projects (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_scan_policies_version FOREIGN KEY (policy_version_id, organization_id)
        REFERENCES policy.policy_versions (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_scan_policies_assignment FOREIGN KEY (assignment_id)
        REFERENCES policy.project_assignments (id) ON DELETE RESTRICT
);

COMMENT ON TABLE policy.scan_policies IS 'The policy version each scan is evaluated against (pinned at request).';

-- One gate evaluation per scan (re-evaluation is a later slice). The reasons are kept as
-- canonical JSON text with a CHECK-recomputed digest.
CREATE TABLE policy.evaluations (
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
    evaluated_as_of   TIMESTAMPTZ  NOT NULL,
    recorded_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    recorded_by       VARCHAR(63)  NOT NULL DEFAULT session_user,
    CONSTRAINT pk_evaluations PRIMARY KEY (id),
    CONSTRAINT uq_evaluations_scan UNIQUE (scan_id),
    CONSTRAINT uq_evaluations_id_scan UNIQUE (id, scan_id),
    CONSTRAINT fk_evaluations_scan_policy FOREIGN KEY (scan_id, policy_version_id)
        REFERENCES policy.scan_policies (scan_id, policy_version_id) ON DELETE RESTRICT,
    CONSTRAINT fk_evaluations_scan FOREIGN KEY (scan_id, project_id)
        REFERENCES public.scans (id, project_id) ON DELETE RESTRICT,
    CONSTRAINT fk_evaluations_project FOREIGN KEY (project_id, organization_id)
        REFERENCES public.projects (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_evaluations_version FOREIGN KEY (policy_version_id, organization_id)
        REFERENCES policy.policy_versions (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT ck_evaluations_policy_sha CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_evaluations_engine CHECK (engine_version ~ '^[a-z0-9][a-z0-9./-]{0,39}$'),
    CONSTRAINT ck_evaluations_decision CHECK (decision IN ('PASS', 'FAIL', 'INCOMPLETE')),
    CONSTRAINT ck_evaluations_counts CHECK (violation_count BETWEEN 0 AND 512 AND incomplete_count BETWEEN 0 AND 512),
    -- Decision precedence (ADR-0013): a confirmed violation is FAIL even when evidence is
    -- also incomplete; PASS only without any violation or incomplete reason.
    CONSTRAINT ck_evaluations_precedence CHECK (
        (decision = 'FAIL') = (violation_count > 0)
        AND (decision = 'PASS') = (violation_count = 0 AND incomplete_count = 0)
    ),
    CONSTRAINT ck_evaluations_reasons CHECK (octet_length(reasons) BETWEEN 2 AND 131072
        AND reasons ~ '^[\x20-\x7e]+$'),
    CONSTRAINT ck_evaluations_reasons_integrity
        CHECK (reasons_sha256 = encode(sha256(convert_to(reasons, 'UTF8')), 'hex'))
);

COMMENT ON TABLE policy.evaluations IS 'Immutable policy evaluation records; each completed one policy-pinned scan.';

-- The evidence of record an evaluation considered, one row per job.
CREATE TABLE policy.evaluation_evidence (
    evaluation_id UUID        NOT NULL,
    scan_id       UUID        NOT NULL,
    job_id        UUID        NOT NULL,
    scanner_type  VARCHAR(20) NOT NULL,
    lease_epoch   BIGINT      NOT NULL,
    name          VARCHAR(64) NOT NULL,
    sha256        CHAR(64)    NOT NULL,
    result_sha256 CHAR(64)    NOT NULL,
    CONSTRAINT pk_evaluation_evidence PRIMARY KEY (evaluation_id, job_id),
    CONSTRAINT fk_evaluation_evidence_evaluation FOREIGN KEY (evaluation_id, scan_id)
        REFERENCES policy.evaluations (id, scan_id) ON DELETE RESTRICT,
    CONSTRAINT fk_evaluation_evidence_job FOREIGN KEY (job_id, scan_id)
        REFERENCES public.scan_jobs (id, scan_id) ON DELETE RESTRICT,
    CONSTRAINT fk_evaluation_evidence_report FOREIGN KEY (job_id, lease_epoch)
        REFERENCES lifecycle.job_reports (job_id, lease_epoch) ON DELETE RESTRICT,
    CONSTRAINT fk_evaluation_evidence_artifact FOREIGN KEY (job_id, lease_epoch, name)
        REFERENCES evidence.result_artifacts (job_id, lease_epoch, name) ON DELETE RESTRICT,
    CONSTRAINT ck_evaluation_evidence_digests CHECK (sha256 ~ '^[0-9a-f]{64}$' AND result_sha256 ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE policy.evaluation_evidence IS 'Evidence of record referenced by an evaluation (digests at evaluation time).';

-- ---------------------------------------------------------------------------
-- 3. Immutability
-- ---------------------------------------------------------------------------

CREATE FUNCTION policy.refuse_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    RAISE EXCEPTION 'policy records are immutable' USING ERRCODE = '55000';
END
$fn$;

CREATE TRIGGER tr_policies_immutable BEFORE UPDATE OR DELETE ON policy.policies
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_policy_versions_immutable BEFORE UPDATE OR DELETE ON policy.policy_versions
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_project_assignments_immutable BEFORE UPDATE OR DELETE ON policy.project_assignments
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_scan_policies_immutable BEFORE UPDATE OR DELETE ON policy.scan_policies
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_evaluations_immutable BEFORE UPDATE OR DELETE ON policy.evaluations
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_evaluation_evidence_immutable BEFORE UPDATE OR DELETE ON policy.evaluation_evidence
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_policies_no_truncate BEFORE TRUNCATE ON policy.policies
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_policy_versions_no_truncate BEFORE TRUNCATE ON policy.policy_versions
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_project_assignments_no_truncate BEFORE TRUNCATE ON policy.project_assignments
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_scan_policies_no_truncate BEFORE TRUNCATE ON policy.scan_policies
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_evaluations_no_truncate BEFORE TRUNCATE ON policy.evaluations
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_evaluation_evidence_no_truncate BEFORE TRUNCATE ON policy.evaluation_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();

-- ---------------------------------------------------------------------------
-- 4. Policy management (EXECUTE: sentinel_api; the API authorizes the caller first)
-- ---------------------------------------------------------------------------

-- Stores a new version of the organization's policy p_name. p_definition is the canonical
-- policy.v1 text produced by the API's validator; the checks here are a structural
-- backstop. Versions are numbered per policy without gaps under a row lock.
CREATE FUNCTION policy.create_policy_version(p_organization_id UUID, p_name TEXT, p_definition TEXT, p_actor TEXT)
RETURNS TABLE (policy_version_id UUID, policy_id UUID, version INTEGER, definition_sha256 TEXT, created_at TIMESTAMPTZ)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_doc     JSONB;
    v_keys    TEXT[];
    v_policy  UUID;
    v_version INTEGER;
    v_row     policy.policy_versions%ROWTYPE;
BEGIN
    IF p_organization_id IS NULL OR p_name IS NULL OR p_name !~ '^[a-z0-9][a-z0-9-]{0,62}$'
            OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 100
            OR p_definition IS NULL OR octet_length(p_definition) NOT BETWEEN 2 AND 16384
            OR p_definition !~ '^[\x20-\x7e]+$' THEN
        RAISE EXCEPTION 'invalid policy definition' USING ERRCODE = '22023';
    END IF;
    BEGIN
        v_doc := p_definition::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid policy definition' USING ERRCODE = '22023';
    END;
    IF jsonb_typeof(v_doc) <> 'object' THEN
        RAISE EXCEPTION 'invalid policy definition' USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(k ORDER BY k) INTO v_keys FROM jsonb_object_keys(v_doc) k;
    IF v_keys IS DISTINCT FROM ARRAY['evidence', 'name', 'scanners', 'schema_version']
            OR v_doc -> 'schema_version' <> '1'::jsonb
            OR v_doc ->> 'name' IS DISTINCT FROM p_name
            OR jsonb_typeof(v_doc -> 'scanners') <> 'object'
            OR NOT EXISTS (SELECT 1 FROM jsonb_object_keys(v_doc -> 'scanners'))
            OR EXISTS (SELECT 1 FROM jsonb_object_keys(v_doc -> 'scanners') k
                       WHERE k NOT IN ('GITLEAKS', 'SEMGREP', 'TRIVY')) THEN
        RAISE EXCEPTION 'invalid policy definition' USING ERRCODE = '22023';
    END IF;

    INSERT INTO policy.policies (organization_id, name, created_by)
    VALUES (p_organization_id, p_name, p_actor)
    ON CONFLICT (organization_id, name) DO NOTHING;
    -- Serializes version numbering per policy.
    SELECT p.id INTO v_policy FROM policy.policies p
     WHERE p.organization_id = p_organization_id AND p.name = p_name
     FOR UPDATE;
    SELECT coalesce(max(v.version), 0) + 1 INTO v_version FROM policy.policy_versions v WHERE v.policy_id = v_policy;

    INSERT INTO policy.policy_versions (policy_id, organization_id, version, schema_version, definition,
        definition_sha256, created_by)
    VALUES (v_policy, p_organization_id, v_version, 1, p_definition,
        encode(sha256(convert_to(p_definition, 'UTF8')), 'hex'), p_actor)
    RETURNING * INTO v_row;
    RETURN QUERY SELECT v_row.id, v_row.policy_id, v_row.version, v_row.definition_sha256::text, v_row.created_at;
END
$fn$;

-- Activates a policy version for a project. A version of another organization is
-- reported exactly like a version that does not exist. Returns ASSIGNED, UNCHANGED (the
-- version is already active), PROJECT_NOT_FOUND or POLICY_VERSION_NOT_FOUND.
CREATE FUNCTION policy.assign_project_policy(p_project_id UUID, p_policy_version_id UUID, p_actor TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_org     UUID;
    v_current UUID;
BEGIN
    IF p_project_id IS NULL OR p_policy_version_id IS NULL OR p_actor IS NULL
            OR length(p_actor) NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'invalid policy assignment' USING ERRCODE = '22023';
    END IF;
    -- Serializes activations per project.
    SELECT p.organization_id INTO v_org FROM public.projects p WHERE p.id = p_project_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'PROJECT_NOT_FOUND';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM policy.policy_versions v
                   WHERE v.id = p_policy_version_id AND v.organization_id = v_org) THEN
        RETURN 'POLICY_VERSION_NOT_FOUND';
    END IF;
    SELECT a.policy_version_id INTO v_current FROM policy.project_assignments a
     WHERE a.project_id = p_project_id ORDER BY a.id DESC LIMIT 1;
    IF v_current = p_policy_version_id THEN
        RETURN 'UNCHANGED';
    END IF;
    INSERT INTO policy.project_assignments (project_id, organization_id, policy_version_id, assigned_by)
    VALUES (p_project_id, v_org, p_policy_version_id, p_actor);
    RETURN 'ASSIGNED';
END
$fn$;

-- Pins the project's active policy version to a new scan; called in the transaction that
-- creates the scan. Returns the pinned version, or NULL when the project has no active
-- policy (the scan is then never PASS or FAIL: INCOMPLETE, POLICY_EVALUATION_UNAVAILABLE).
CREATE FUNCTION policy.pin_scan_policy(p_scan_id UUID)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan       public.scans%ROWTYPE;
    v_org        UUID;
    v_assignment policy.project_assignments%ROWTYPE;
BEGIN
    IF p_scan_id IS NULL THEN
        RAISE EXCEPTION 'invalid scan' USING ERRCODE = '22023';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR UPDATE;
    IF NOT FOUND OR v_scan.execution_status <> 'QUEUED'
            OR EXISTS (SELECT 1 FROM policy.scan_policies sp WHERE sp.scan_id = p_scan_id) THEN
        RAISE EXCEPTION 'scan cannot be pinned' USING ERRCODE = '22023';
    END IF;
    SELECT p.organization_id INTO v_org FROM public.projects p WHERE p.id = v_scan.project_id;
    SELECT a.* INTO v_assignment FROM policy.project_assignments a
     WHERE a.project_id = v_scan.project_id ORDER BY a.id DESC LIMIT 1;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    INSERT INTO policy.scan_policies (scan_id, project_id, organization_id, policy_version_id, assignment_id)
    VALUES (p_scan_id, v_scan.project_id, v_org, v_assignment.policy_version_id, v_assignment.id);
    RETURN v_assignment.policy_version_id;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 5. Evaluation inputs (EXECUTE: sentinel_api)
-- ---------------------------------------------------------------------------

-- The scan, its pinned policy and the database clock. Zero rows: unknown scan.
CREATE FUNCTION policy.evaluation_context(p_scan_id UUID)
RETURNS TABLE (scan_id UUID, project_id UUID, organization_id UUID, commit_sha VARCHAR, execution_status VARCHAR,
    policy_version_id UUID, policy_definition TEXT, policy_sha256 CHAR, database_now TIMESTAMPTZ)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT s.id, s.project_id, p.organization_id, s.commit_sha, s.execution_status, sp.policy_version_id,
           v.definition, v.definition_sha256, now()
    FROM public.scans s
    JOIN public.projects p ON p.id = s.project_id
    LEFT JOIN policy.scan_policies sp ON sp.scan_id = s.id
    LEFT JOIN policy.policy_versions v ON v.id = sp.policy_version_id
    WHERE s.id = p_scan_id;
$fn$;

-- Every job of the scan with its evidence of record: the accepted COMPLETED result of the
-- job's current lease epoch and the artifacts it references (one row per artifact; one
-- row with NULL artifact columns when there is none). Jobs that did not complete have no
-- evidence of record. Content is NULL when purged by retention.
CREATE FUNCTION policy.job_evidence(p_scan_id UUID)
RETURNS TABLE (job_id UUID, scanner_type VARCHAR, job_status VARCHAR, failure_reason VARCHAR, lease_epoch BIGINT,
    job_completed_at TIMESTAMPTZ, result_sha256 CHAR, result TEXT, artifact_name VARCHAR, artifact_media_type VARCHAR,
    artifact_sha256 CHAR, artifact_size INTEGER, artifact_content BYTEA)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT j.id, j.scanner_type, j.execution_status, j.failure_reason, j.lease_epoch, j.completed_at,
           r.result_sha256, r.result::text, u.name, u.media_type, u.sha256, u.size_bytes, o.content
    FROM public.scan_jobs j
    LEFT JOIN lifecycle.job_reports r
           ON j.execution_status = 'COMPLETED' AND r.job_id = j.id AND r.lease_epoch = j.lease_epoch
          AND r.outcome = 'COMPLETED'
    LEFT JOIN evidence.result_artifacts ra ON ra.job_id = r.job_id AND ra.lease_epoch = r.lease_epoch
    LEFT JOIN evidence.job_artifacts u ON u.job_id = ra.job_id AND u.lease_epoch = ra.lease_epoch AND u.name = ra.name
    LEFT JOIN evidence.objects o ON o.organization_id = u.organization_id AND o.sha256 = u.sha256
    WHERE j.scan_id = p_scan_id
    ORDER BY j.scanner_type, j.id, u.name;
$fn$;

-- ---------------------------------------------------------------------------
-- 6. Recording an evaluation (EXECUTE: sentinel_api)
-- ---------------------------------------------------------------------------

-- Strict validation of the canonical reasons array. Returns (violations, incompletes).
CREATE FUNCTION policy.validate_reasons(p_reasons TEXT)
RETURNS TABLE (violations INTEGER, incompletes INTEGER, scanners TEXT[])
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_json   JSON;
    v_reason JSON;
    v_keys   TEXT[];
    v_v      INTEGER := 0;
    v_i      INTEGER := 0;
    v_s      TEXT[] := ARRAY[]::TEXT[];
BEGIN
    IF p_reasons IS NULL OR octet_length(p_reasons) > 131072 OR p_reasons !~ '^[\x20-\x7e]+$' THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_REASONS' USING ERRCODE = '22023';
    END IF;
    BEGIN
        v_json := p_reasons::json;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_REASONS' USING ERRCODE = '22023';
    END;
    IF json_typeof(v_json) <> 'array' OR json_array_length(v_json) > 512 THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_REASONS' USING ERRCODE = '22023';
    END IF;
    FOR v_reason IN SELECT r FROM json_array_elements(v_json) r LOOP
        IF json_typeof(v_reason) <> 'object' THEN
            RAISE EXCEPTION 'evaluation rejected: INVALID_REASONS' USING ERRCODE = '22023';
        END IF;
        SELECT array_agg(k ORDER BY k) INTO v_keys FROM json_object_keys(v_reason) k;
        IF v_keys IS DISTINCT FROM ARRAY['code', 'effect', 'limit', 'observed', 'scanner', 'subject']
                OR json_typeof(v_reason -> 'code') <> 'string'
                OR (v_reason ->> 'code') !~ '^[A-Z][A-Z0-9_]{0,63}$'
                OR json_typeof(v_reason -> 'effect') <> 'string'
                OR (v_reason ->> 'effect') NOT IN ('VIOLATION', 'INCOMPLETE')
                OR json_typeof(v_reason -> 'scanner') NOT IN ('string', 'null')
                OR (json_typeof(v_reason -> 'scanner') = 'string'
                    AND (v_reason ->> 'scanner') NOT IN ('SEMGREP', 'GITLEAKS', 'TRIVY', 'CHECKOV', 'SYFT', 'ZAP',
                        'FIXTURE'))
                OR json_typeof(v_reason -> 'subject') NOT IN ('string', 'null')
                OR (json_typeof(v_reason -> 'subject') = 'string'
                    AND (v_reason ->> 'subject') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$')
                OR json_typeof(v_reason -> 'observed') NOT IN ('number', 'null')
                OR (json_typeof(v_reason -> 'observed') = 'number'
                    AND (v_reason ->> 'observed') !~ '^(0|[1-9][0-9]{0,11})$')
                OR json_typeof(v_reason -> 'limit') NOT IN ('number', 'null')
                OR (json_typeof(v_reason -> 'limit') = 'number'
                    AND (v_reason ->> 'limit') !~ '^(0|[1-9][0-9]{0,11})$') THEN
            RAISE EXCEPTION 'evaluation rejected: INVALID_REASONS' USING ERRCODE = '22023';
        END IF;
        IF (v_reason ->> 'effect') = 'VIOLATION' THEN
            -- A violation is always attributed to one scanner's evidence.
            IF json_typeof(v_reason -> 'scanner') <> 'string' THEN
                RAISE EXCEPTION 'evaluation rejected: INVALID_REASONS' USING ERRCODE = '22023';
            END IF;
            v_v := v_v + 1;
            v_s := v_s || (v_reason ->> 'scanner');
        ELSE
            v_i := v_i + 1;
        END IF;
    END LOOP;
    RETURN QUERY SELECT v_v, v_i, v_s;
END
$fn$;

-- Records the evaluation of an EVALUATING, policy-pinned scan and completes the scan with
-- its decision (reason POLICY_EVALUATED), atomically. Returns COMPLETED, NOT_FOUND or
-- NOT_EVALUATING (evaluated or cancelled concurrently: no effect). A record that is not
-- internally consistent raises SQLSTATE 22023 with a fixed 'evaluation rejected: <CODE>'
-- message and changes nothing.
--
-- p_evidence: canonical JSON array of {job_id, lease_epoch, name, result_sha256,
-- scanner_type, sha256}, at most one entry per job.
CREATE FUNCTION policy.record_evaluation(p_scan_id UUID, p_policy_version_id UUID, p_policy_sha256 TEXT,
    p_engine_version TEXT, p_decision TEXT, p_reasons TEXT, p_evidence TEXT, p_as_of TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan       public.scans%ROWTYPE;
    v_pinned     policy.scan_policies%ROWTYPE;
    v_version    policy.policy_versions%ROWTYPE;
    v_counts     RECORD;
    v_expected   TEXT;
    v_evidence   JSON;
    v_entry      JSON;
    v_keys       TEXT[];
    v_job        public.scan_jobs%ROWTYPE;
    v_jobs_seen  UUID[] := ARRAY[]::UUID[];
    v_scanners   TEXT[] := ARRAY[]::TEXT[];
    v_policy_set TEXT[];
    v_job_set    TEXT[];
    v_eval_id    UUID;
    v_now        TIMESTAMPTZ;
BEGIN
    IF p_scan_id IS NULL OR p_policy_version_id IS NULL
            OR p_policy_sha256 IS NULL OR p_policy_sha256 !~ '^[0-9a-f]{64}$'
            OR p_engine_version IS NULL OR p_engine_version !~ '^[a-z0-9][a-z0-9./-]{0,39}$'
            OR p_decision IS NULL OR p_decision NOT IN ('PASS', 'FAIL', 'INCOMPLETE')
            OR p_evidence IS NULL OR octet_length(p_evidence) > 16384 OR p_evidence !~ '^[\x20-\x7e]+$'
            OR p_as_of IS NULL OR p_as_of > now() + interval '1 second' OR p_as_of < now() - interval '15 minutes' THEN
        RAISE EXCEPTION 'evaluation rejected: INVALID_ARGUMENTS' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_counts FROM policy.validate_reasons(p_reasons);

    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    IF v_scan.execution_status <> 'EVALUATING' THEN
        RETURN 'NOT_EVALUATING';
    END IF;

    -- The policy must be the version pinned to this scan, with its recorded digest.
    SELECT sp.* INTO v_pinned FROM policy.scan_policies sp WHERE sp.scan_id = p_scan_id;
    IF NOT FOUND OR v_pinned.policy_version_id <> p_policy_version_id THEN
        RAISE EXCEPTION 'evaluation rejected: POLICY_MISMATCH' USING ERRCODE = '22023';
    END IF;
    SELECT v.* INTO v_version FROM policy.policy_versions v WHERE v.id = p_policy_version_id;
    IF v_version.definition_sha256 <> p_policy_sha256 THEN
        RAISE EXCEPTION 'evaluation rejected: POLICY_MISMATCH' USING ERRCODE = '22023';
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

    -- PASS backstop: complete, policy-exact evidence for every job (fail closed).
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

    v_now := greatest(now(), v_scan.updated_at);
    INSERT INTO policy.evaluations (scan_id, project_id, organization_id, policy_version_id, policy_sha256,
        engine_version, decision, violation_count, incomplete_count, reasons, reasons_sha256, evaluated_as_of)
    VALUES (p_scan_id, v_pinned.project_id, v_pinned.organization_id, p_policy_version_id, p_policy_sha256,
        p_engine_version, p_decision, v_counts.violations, v_counts.incompletes, p_reasons,
        encode(sha256(convert_to(p_reasons, 'UTF8')), 'hex'), p_as_of)
    RETURNING id INTO v_eval_id;
    INSERT INTO policy.evaluation_evidence (evaluation_id, scan_id, job_id, scanner_type, lease_epoch, name, sha256,
        result_sha256)
    SELECT v_eval_id, p_scan_id, (e ->> 'job_id')::uuid, e ->> 'scanner_type', (e ->> 'lease_epoch')::bigint,
           e ->> 'name', e ->> 'sha256', e ->> 'result_sha256'
    FROM json_array_elements(v_evidence) e;

    UPDATE public.scans s
       SET execution_status = 'COMPLETED', security_decision = p_decision, decision_reason = 'POLICY_EVALUATED',
           completed_at = v_now, updated_at = v_now, version = s.version + 1
     WHERE s.id = p_scan_id;
    PERFORM lifecycle.log_event(p_scan_id, NULL, 'SCAN_COMPLETED', 'SUPERVISOR', session_user, NULL, p_decision);
    RETURN 'COMPLETED';
END
$fn$;

-- ---------------------------------------------------------------------------
-- 7. lifecycle.complete_evaluation: INCOMPLETE without a policy only
-- ---------------------------------------------------------------------------

-- Replaces V007's version. PASS and FAIL can no longer be recorded here: they require an
-- evaluation record (policy.record_evaluation). A scan with a pinned policy cannot be
-- completed here either (POLICY_EVALUATION_REQUIRED), so a COMPLETED pinned scan's decision
-- is always explained by an evaluation record (cancelled or failed scans are INCOMPLETE with
-- their own reason). Returns COMPLETED, NOT_FOUND, NOT_EVALUATING or
-- POLICY_EVALUATION_REQUIRED.
CREATE OR REPLACE FUNCTION lifecycle.complete_evaluation(p_scan_id UUID, p_decision TEXT, p_reason TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan public.scans%ROWTYPE;
    v_now  TIMESTAMPTZ;
BEGIN
    IF p_scan_id IS NULL OR p_decision IS DISTINCT FROM 'INCOMPLETE'
            OR p_reason IS NULL OR p_reason NOT IN ('POLICY_EVALUATION_UNAVAILABLE', 'SCANNER_EXECUTION_INCOMPLETE') THEN
        RAISE EXCEPTION 'invalid evaluation result' USING ERRCODE = '22023';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    IF v_scan.execution_status <> 'EVALUATING' THEN
        RETURN 'NOT_EVALUATING';
    END IF;
    IF EXISTS (SELECT 1 FROM policy.scan_policies sp WHERE sp.scan_id = p_scan_id) THEN
        RETURN 'POLICY_EVALUATION_REQUIRED';
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

-- ---------------------------------------------------------------------------
-- 8. Decisions only through the lifecycle and policy functions
-- ---------------------------------------------------------------------------

-- The API keeps INSERT on scans and scan_jobs (creation and planning), and the CHECK
-- constraints admit any consistent state, so before V009 the API role could insert a scan
-- born COMPLETED with PASS (final review, defect M4-5). New rows written by any role other
-- than a superuser must be born in their initial state; every later change goes through
-- the lifecycle functions. Superusers stay trusted (ADR-0013, residual risk R2).
CREATE FUNCTION policy.require_initial_state()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'scans' THEN
        IF NEW.execution_status <> 'QUEUED' OR NEW.security_decision <> 'PENDING' OR NEW.decision_reason IS NOT NULL
                OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR NEW.deadline_at IS NOT NULL THEN
            RAISE EXCEPTION 'new scans must be QUEUED without a decision' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.execution_status <> 'QUEUED' OR NEW.attempt_count <> 0 OR NEW.lease_epoch <> 0
            OR NEW.lease_owner IS NOT NULL OR NEW.lease_token_sha256 IS NOT NULL OR NEW.lease_expires_at IS NOT NULL
            OR NEW.heartbeat_at IS NOT NULL OR NEW.next_attempt_at IS NOT NULL OR NEW.failure_reason IS NOT NULL
            OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'new scan jobs must be QUEUED and unleased' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$fn$;

CREATE TRIGGER tr_scans_initial_state BEFORE INSERT ON public.scans
    FOR EACH ROW EXECUTE FUNCTION policy.require_initial_state();
CREATE TRIGGER tr_scan_jobs_initial_state BEFORE INSERT ON public.scan_jobs
    FOR EACH ROW EXECUTE FUNCTION policy.require_initial_state();

-- Cross-table invariant, checked whenever a decision is set (including inside SECURITY
-- DEFINER functions, which run as the owner): PASS and FAIL, and every decision with reason
-- POLICY_EVALUATED or of a COMPLETED policy-pinned scan, require a recorded evaluation with
-- the same decision. policy.record_evaluation writes the evaluation before the scan.
CREATE FUNCTION policy.require_evaluation_record()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
        RETURN NULL;
    END IF;
    IF (NEW.security_decision IN ('PASS', 'FAIL') OR NEW.decision_reason = 'POLICY_EVALUATED'
            OR (NEW.execution_status = 'COMPLETED'
                AND EXISTS (SELECT 1 FROM policy.scan_policies sp WHERE sp.scan_id = NEW.id)))
            AND NOT EXISTS (SELECT 1 FROM policy.evaluations e
                            WHERE e.scan_id = NEW.id AND e.decision = NEW.security_decision) THEN
        RAISE EXCEPTION 'a policy decision requires a matching evaluation record' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$fn$;

CREATE TRIGGER tr_scans_decision_inserted AFTER INSERT ON public.scans
    FOR EACH ROW EXECUTE FUNCTION policy.require_evaluation_record();
CREATE TRIGGER tr_scans_decision_changed AFTER UPDATE ON public.scans
    FOR EACH ROW
    WHEN (NEW.security_decision IS DISTINCT FROM OLD.security_decision
          OR NEW.decision_reason IS DISTINCT FROM OLD.decision_reason
          OR NEW.execution_status IS DISTINCT FROM OLD.execution_status)
    EXECUTE FUNCTION policy.require_evaluation_record();

-- ---------------------------------------------------------------------------
-- 9. Privileges
-- ---------------------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA policy FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.refuse_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.require_initial_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.require_evaluation_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.create_policy_version(UUID, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.assign_project_policy(UUID, UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.pin_scan_policy(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.evaluation_context(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.job_evidence(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.validate_reasons(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.record_evaluation(UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- The API reads policy records directly and writes them only through these functions.
GRANT USAGE ON SCHEMA policy TO sentinel_api;
GRANT SELECT ON policy.policies, policy.policy_versions, policy.project_assignments, policy.scan_policies,
    policy.evaluations, policy.evaluation_evidence TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.create_policy_version(UUID, TEXT, TEXT, TEXT) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.assign_project_policy(UUID, UUID, TEXT) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.pin_scan_policy(UUID) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.evaluation_context(UUID) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.job_evidence(UUID) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.record_evaluation(UUID, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
    TO sentinel_api;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.policy_engine', 'm4-phase1');

-- V011: Milestone 4, Phase 3. Security exceptions with independent approval (ADR-0015).
--
-- A security exception is a narrowly scoped, temporary, audited acceptance of one confirmed
-- policy violation: one blocking finding of one scan's original FAIL evaluation. It never
-- changes raw evidence, findings, the scan's decision, its original evaluation or any
-- historical re-evaluation. Whether a scan's gate may open despite an excepted finding is
-- computed on read (the effective gate, ADR-0015) and never persisted here.
--
-- 1. Scope. A request is bound declaratively (composite foreign keys) to the scan's
--    ORIGINAL evaluation, its pinned policy version and digest, its engine version, and the
--    evidence of record that evaluation relied on for one scanner (job, lease epoch,
--    artifact digest, result digest). The finding is identified by the fingerprint the
--    database itself finds exactly once, as a blocking finding, in the stored findings.json
--    bytes of that evidence: a caller cannot name a fingerprint that is not there, and
--    there are no wildcards, scanner-wide or project-wide exceptions.
-- 2. Eligibility. Only a COMPLETED scan whose original decision is FAIL, and only a scanner
--    with a BLOCKING_FINDINGS_EXCEEDED violation in that evaluation. Missing, purged,
--    invalid or incomplete evidence, scanner failures, coverage gaps and stale databases
--    are INCOMPLETE reasons, never violations: they cannot be excepted.
-- 3. Lifecycle. Requests are immutable. State changes are append-only transitions:
--        (none)    -> REQUESTED                    seq 0, by the requester
--        REQUESTED -> APPROVED | REJECTED | WITHDRAWN   seq 1
--        APPROVED  -> REVOKED                      seq 2
--    The primary key (request, seq) allows exactly one way out of each state, a self
--    reference proves the previous state was entered, and nothing returns to REQUESTED.
-- 4. Independence. APPROVED and REJECTED require an actor other than the requester (a
--    CHECK against the requester copied under a foreign key) who is a current OWNER member
--    of the organization (verified by a trigger against organization_memberships, also for
--    direct SQL). WITHDRAWN is the requester's own act.
-- 5. Time. Timestamps are taken from the database clock by triggers (clock_timestamp());
--    callers cannot backdate. Lifetime: 1 hour to 90 days from the request. No transition
--    is accepted at or after expiry, and approval needs at least 5 minutes of validity left.
--    Expiry is derived on read (policy.exception_status): an expired approval stops
--    applying without any scheduler.
-- 6. Records are append-only for every runtime role, and guarded by policy.refuse_change
--    against UPDATE, DELETE and TRUNCATE through ordinary statements.

-- ---------------------------------------------------------------------------
-- 1. Keys that let exception records prove their binding declaratively
-- ---------------------------------------------------------------------------

ALTER TABLE policy.evaluations
    ADD CONSTRAINT uq_evaluations_binding
    UNIQUE (id, scan_id, project_id, organization_id, policy_version_id, policy_sha256, engine_version);

ALTER TABLE policy.evaluation_evidence
    ADD CONSTRAINT uq_evaluation_evidence_binding
    UNIQUE (evaluation_id, scan_id, job_id, scanner_type, lease_epoch, name, sha256, result_sha256);

-- ---------------------------------------------------------------------------
-- 2. Tables
-- ---------------------------------------------------------------------------

CREATE TABLE policy.exception_requests (
    id                       UUID          NOT NULL DEFAULT gen_random_uuid(),
    organization_id          UUID          NOT NULL,
    project_id               UUID          NOT NULL,
    scan_id                  UUID          NOT NULL,
    evaluation_id            UUID          NOT NULL,
    policy_version_id        UUID          NOT NULL,
    policy_sha256            CHAR(64)      NOT NULL,
    engine_version           VARCHAR(40)   NOT NULL,
    job_id                   UUID          NOT NULL,
    scanner_type             VARCHAR(20)   NOT NULL,
    lease_epoch              BIGINT        NOT NULL,
    artifact_name            VARCHAR(64)   NOT NULL,
    artifact_sha256          CHAR(64)      NOT NULL,
    result_sha256            CHAR(64)      NOT NULL,
    finding_fingerprint      CHAR(64)      NOT NULL,
    finding_rule_id          VARCHAR(128)  NOT NULL,
    finding_category         VARCHAR(40)   NOT NULL,
    finding_scanner_severity VARCHAR(20),
    justification            VARCHAR(2000) NOT NULL,
    requested_by             VARCHAR(100)  NOT NULL,
    requested_at             TIMESTAMPTZ   NOT NULL DEFAULT clock_timestamp(),
    expires_at               TIMESTAMPTZ   NOT NULL,
    recorded_by              VARCHAR(63)   NOT NULL DEFAULT session_user,
    CONSTRAINT pk_exception_requests PRIMARY KEY (id),
    CONSTRAINT uq_exception_requests_transition_key UNIQUE (id, requested_by, expires_at),
    -- The original (gating) evaluation of this scan, with its policy and engine.
    CONSTRAINT fk_exception_requests_evaluation
        FOREIGN KEY (evaluation_id, scan_id, project_id, organization_id, policy_version_id, policy_sha256,
                     engine_version)
        REFERENCES policy.evaluations (id, scan_id, project_id, organization_id, policy_version_id, policy_sha256,
                                       engine_version) ON DELETE RESTRICT,
    -- The evidence of record that evaluation relied on for this scanner, with its digests.
    CONSTRAINT fk_exception_requests_evidence
        FOREIGN KEY (evaluation_id, scan_id, job_id, scanner_type, lease_epoch, artifact_name, artifact_sha256,
                     result_sha256)
        REFERENCES policy.evaluation_evidence (evaluation_id, scan_id, job_id, scanner_type, lease_epoch, name, sha256,
                                               result_sha256) ON DELETE RESTRICT,
    CONSTRAINT fk_exception_requests_scan FOREIGN KEY (scan_id, project_id)
        REFERENCES public.scans (id, project_id) ON DELETE RESTRICT,
    CONSTRAINT fk_exception_requests_project FOREIGN KEY (project_id, organization_id)
        REFERENCES public.projects (id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT fk_exception_requests_version FOREIGN KEY (policy_version_id, policy_sha256)
        REFERENCES policy.policy_versions (id, definition_sha256) ON DELETE RESTRICT,
    CONSTRAINT ck_exception_requests_digests CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'
        AND artifact_sha256 ~ '^[0-9a-f]{64}$' AND result_sha256 ~ '^[0-9a-f]{64}$'
        AND finding_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_exception_requests_scanner CHECK (scanner_type IN ('GITLEAKS', 'SEMGREP', 'TRIVY')),
    CONSTRAINT ck_exception_requests_finding CHECK (
        finding_rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
        AND ((scanner_type = 'GITLEAKS' AND finding_category = 'SECRET' AND finding_scanner_severity IS NULL)
          OR (scanner_type = 'SEMGREP' AND finding_category = 'CODE_PATTERN'
              AND finding_scanner_severity IN ('ERROR', 'WARNING', 'INFO'))
          OR (scanner_type = 'TRIVY' AND finding_category = 'DEPENDENCY_VULNERABILITY'
              AND finding_scanner_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')))),
    CONSTRAINT ck_exception_requests_justification CHECK (char_length(justification) BETWEEN 20 AND 2000
        AND justification !~ '[[:cntrl:]]' AND btrim(justification) = justification),
    -- The requester is an internal identity reference, never a name, e-mail or token subject.
    CONSTRAINT ck_exception_requests_requested_by
        CHECK (requested_by ~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    CONSTRAINT ck_exception_requests_lifetime CHECK (expires_at >= requested_at + interval '1 hour'
        AND expires_at <= requested_at + interval '90 days')
);

CREATE INDEX ix_exception_requests_scan ON policy.exception_requests (scan_id, requested_at, id);
CREATE INDEX ix_exception_requests_target ON policy.exception_requests (evaluation_id, job_id, finding_fingerprint);

COMMENT ON TABLE policy.exception_requests IS
    'Immutable requests to accept one verified blocking finding of one scan''s original FAIL evaluation.';

CREATE TABLE policy.exception_transitions (
    request_id   UUID          NOT NULL,
    seq          SMALLINT      NOT NULL,
    from_state   VARCHAR(20),
    to_state     VARCHAR(20)   NOT NULL,
    requested_by VARCHAR(100)  NOT NULL,
    expires_at   TIMESTAMPTZ   NOT NULL,
    actor        VARCHAR(100)  NOT NULL,
    actor_role   VARCHAR(20)   NOT NULL,
    rationale    VARCHAR(1000),
    occurred_at  TIMESTAMPTZ   NOT NULL DEFAULT clock_timestamp(),
    recorded_by  VARCHAR(63)   NOT NULL DEFAULT session_user,
    -- One transition per step: exactly one way out of REQUESTED and one out of APPROVED.
    CONSTRAINT pk_exception_transitions PRIMARY KEY (request_id, seq),
    CONSTRAINT uq_exception_transitions_state UNIQUE (request_id, to_state),
    -- The requester and expiry of the request, copied under a foreign key so that CHECKs
    -- below can compare against them.
    CONSTRAINT fk_exception_transitions_request FOREIGN KEY (request_id, requested_by, expires_at)
        REFERENCES policy.exception_requests (id, requested_by, expires_at) ON DELETE RESTRICT,
    -- The state being left was actually entered (NULL only for the creation step).
    CONSTRAINT fk_exception_transitions_previous FOREIGN KEY (request_id, from_state)
        REFERENCES policy.exception_transitions (request_id, to_state) ON DELETE RESTRICT,
    CONSTRAINT ck_exception_transitions_machine CHECK (
        (seq = 0 AND from_state IS NULL AND to_state = 'REQUESTED')
        OR (seq = 1 AND from_state = 'REQUESTED' AND to_state IN ('APPROVED', 'REJECTED', 'WITHDRAWN'))
        OR (seq = 2 AND from_state = 'APPROVED' AND to_state = 'REVOKED')),
    -- No user decides on their own request, whatever their role.
    CONSTRAINT ck_exception_transitions_independent
        CHECK (to_state NOT IN ('APPROVED', 'REJECTED') OR actor <> requested_by),
    CONSTRAINT ck_exception_transitions_requester
        CHECK (to_state NOT IN ('REQUESTED', 'WITHDRAWN') OR actor = requested_by),
    -- The actor's organization role at the time (verified by trigger against memberships).
    CONSTRAINT ck_exception_transitions_role CHECK (
        (to_state IN ('APPROVED', 'REJECTED', 'REVOKED') AND actor_role = 'OWNER')
        OR (to_state IN ('REQUESTED', 'WITHDRAWN') AND actor_role IN ('OWNER', 'ADMIN'))),
    CONSTRAINT ck_exception_transitions_actor
        CHECK (actor ~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    -- Nothing happens to an expired request; an approval keeps at least 5 minutes of validity.
    CONSTRAINT ck_exception_transitions_before_expiry CHECK (occurred_at < expires_at),
    CONSTRAINT ck_exception_transitions_approval_window
        CHECK (to_state <> 'APPROVED' OR occurred_at <= expires_at - interval '5 minutes'),
    CONSTRAINT ck_exception_transitions_rationale CHECK (
        (to_state = 'REQUESTED' AND rationale IS NULL)
        OR (to_state <> 'REQUESTED' AND char_length(rationale) BETWEEN 1 AND 1000
            AND rationale !~ '[[:cntrl:]]' AND btrim(rationale) = rationale))
);

COMMENT ON TABLE policy.exception_transitions IS
    'Append-only state transitions of security exception requests (ADR-0015).';

-- ---------------------------------------------------------------------------
-- 3. Immutability (as for every policy record, V009)
-- ---------------------------------------------------------------------------

CREATE TRIGGER tr_exception_requests_immutable BEFORE UPDATE OR DELETE ON policy.exception_requests
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_exception_transitions_immutable BEFORE UPDATE OR DELETE ON policy.exception_transitions
    FOR EACH ROW EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_exception_requests_no_truncate BEFORE TRUNCATE ON policy.exception_requests
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();
CREATE TRIGGER tr_exception_transitions_no_truncate BEFORE TRUNCATE ON policy.exception_transitions
    FOR EACH STATEMENT EXECUTE FUNCTION policy.refuse_change();

-- ---------------------------------------------------------------------------
-- 4. Internal helpers (owner only)
-- ---------------------------------------------------------------------------

-- The actor's current role in the organization, or NULL when the actor is not a member.
CREATE FUNCTION policy.member_role(p_organization_id UUID, p_actor TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT m.role::text FROM public.organization_memberships m
    WHERE m.organization_id = p_organization_id
      AND p_actor ~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      AND m.user_identity_id = substr(p_actor, 6)::uuid;
$fn$;

-- Resolves and verifies the target of an exception on the original evaluation p_evaluation_id:
-- the scanner must have a BLOCKING_FINDINGS_EXCEEDED violation in that FAIL evaluation, the
-- evaluation must reference that scanner's evidence of record, the stored findings.json bytes
-- must be present, bound to the job and scan, and contain exactly one finding with
-- p_fingerprint, of the scanner's category, that the pinned policy counts as blocking.
-- problem is NULL when the target is valid; otherwise NO_VIOLATION, EVIDENCE_UNAVAILABLE or
-- FINDING_NOT_ELIGIBLE (deliberately not more specific).
CREATE FUNCTION policy.exception_target(p_evaluation_id UUID, p_scanner_type TEXT, p_fingerprint TEXT)
RETURNS TABLE (problem TEXT, job_id UUID, lease_epoch BIGINT, artifact_name TEXT, artifact_sha256 TEXT,
    result_sha256 TEXT, rule_id TEXT, category TEXT, scanner_severity TEXT)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_eval     policy.evaluations%ROWTYPE;
    v_evidence policy.evaluation_evidence%ROWTYPE;
    v_content  BYTEA;
    v_found    BOOLEAN;
    v_doc      JSONB;
    v_matches  INTEGER;
    v_finding  JSONB;
    v_rules    JSONB;
    v_category TEXT;
    v_severity TEXT;
BEGIN
    SELECT e.* INTO v_eval FROM policy.evaluations e WHERE e.id = p_evaluation_id;
    IF NOT FOUND OR v_eval.decision <> 'FAIL'
            OR NOT v_eval.reasons::jsonb @> jsonb_build_array(jsonb_build_object(
                'code', 'BLOCKING_FINDINGS_EXCEEDED', 'effect', 'VIOLATION', 'scanner', p_scanner_type)) THEN
        RETURN QUERY SELECT 'NO_VIOLATION'::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    SELECT ee.* INTO v_evidence FROM policy.evaluation_evidence ee
     WHERE ee.evaluation_id = p_evaluation_id AND ee.scanner_type = p_scanner_type;
    IF NOT FOUND OR v_evidence.name <> 'findings.json' THEN
        RETURN QUERY SELECT 'FINDING_NOT_ELIGIBLE'::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    SELECT o.content, true INTO v_content, v_found
      FROM evidence.job_artifacts u
      JOIN evidence.objects o ON o.organization_id = u.organization_id AND o.sha256 = u.sha256
     WHERE u.job_id = v_evidence.job_id AND u.lease_epoch = v_evidence.lease_epoch AND u.name = v_evidence.name
       AND u.sha256 = v_evidence.sha256;
    IF v_found IS NULL OR v_content IS NULL THEN
        RETURN QUERY SELECT 'EVIDENCE_UNAVAILABLE'::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    BEGIN
        v_doc := convert_from(v_content, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        v_doc := NULL;
    END;
    v_category := CASE p_scanner_type WHEN 'GITLEAKS' THEN 'SECRET' WHEN 'SEMGREP' THEN 'CODE_PATTERN'
                                      WHEN 'TRIVY' THEN 'DEPENDENCY_VULNERABILITY' END;
    IF v_doc IS NULL OR jsonb_typeof(v_doc) <> 'object' OR jsonb_typeof(v_doc -> 'findings') <> 'array'
            OR v_doc -> 'context' ->> 'job_id' IS DISTINCT FROM v_evidence.job_id::text
            OR v_doc -> 'context' ->> 'scan_id' IS DISTINCT FROM v_eval.scan_id::text THEN
        RETURN QUERY SELECT 'FINDING_NOT_ELIGIBLE'::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    SELECT count(*)::integer, (array_agg(f))[1] INTO v_matches, v_finding
      FROM jsonb_array_elements(v_doc -> 'findings') f
     WHERE f ->> 'fingerprint' = p_fingerprint;
    -- Blocking per the pinned policy: severity in the scanner's blocking_severities; Gitleaks
    -- has no severity and every detected secret is blocking.
    SELECT v.definition::jsonb -> 'scanners' -> p_scanner_type INTO v_rules
      FROM policy.policy_versions v WHERE v.id = v_eval.policy_version_id;
    v_severity := v_finding ->> 'scanner_severity';
    IF v_matches <> 1 OR v_rules IS NULL
            OR v_finding ->> 'category' IS DISTINCT FROM v_category
            OR coalesce(v_finding ->> 'rule_id', '') !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
            OR (v_rules ? 'blocking_severities'
                AND (v_severity IS NULL OR NOT (v_rules -> 'blocking_severities') ? v_severity))
            OR (NOT v_rules ? 'blocking_severities' AND v_severity IS NOT NULL) THEN
        RETURN QUERY SELECT 'FINDING_NOT_ELIGIBLE'::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    RETURN QUERY SELECT NULL::text, v_evidence.job_id, v_evidence.lease_epoch, v_evidence.name::text,
        v_evidence.sha256::text, v_evidence.result_sha256::text, v_finding ->> 'rule_id', v_category, v_severity;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 5. Invariants enforced for every writer (also direct SQL by the owner or a superuser)
-- ---------------------------------------------------------------------------

-- A request must target a verified blocking finding of the scan's original FAIL evaluation,
-- be made by a current OWNER or ADMIN member, and carry database timestamps.
CREATE FUNCTION policy.check_exception_request()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_scan   public.scans%ROWTYPE;
    v_target RECORD;
BEGIN
    NEW.requested_at := clock_timestamp();
    NEW.recorded_by := session_user;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = NEW.scan_id;
    IF NOT FOUND OR v_scan.execution_status <> 'COMPLETED' OR v_scan.security_decision <> 'FAIL' THEN
        RAISE EXCEPTION 'exception rejected: SCAN_NOT_ELIGIBLE' USING ERRCODE = '23514';
    END IF;
    IF policy.member_role(NEW.organization_id, NEW.requested_by) IS DISTINCT FROM 'OWNER'
            AND policy.member_role(NEW.organization_id, NEW.requested_by) IS DISTINCT FROM 'ADMIN' THEN
        RAISE EXCEPTION 'exception rejected: NOT_AUTHORIZED' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO v_target FROM policy.exception_target(NEW.evaluation_id, NEW.scanner_type, NEW.finding_fingerprint);
    IF v_target.problem IS NOT NULL
            OR v_target.job_id IS DISTINCT FROM NEW.job_id
            OR v_target.lease_epoch IS DISTINCT FROM NEW.lease_epoch
            OR v_target.artifact_name IS DISTINCT FROM NEW.artifact_name::text
            OR v_target.artifact_sha256 IS DISTINCT FROM NEW.artifact_sha256::text
            OR v_target.result_sha256 IS DISTINCT FROM NEW.result_sha256::text
            OR v_target.rule_id IS DISTINCT FROM NEW.finding_rule_id::text
            OR v_target.category IS DISTINCT FROM NEW.finding_category::text
            OR v_target.scanner_severity IS DISTINCT FROM NEW.finding_scanner_severity::text THEN
        RAISE EXCEPTION 'exception rejected: FINDING_NOT_VERIFIED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$fn$;

CREATE TRIGGER tr_exception_requests_check BEFORE INSERT ON policy.exception_requests
    FOR EACH ROW EXECUTE FUNCTION policy.check_exception_request();

-- A transition is serialized per request, carries the database time, is recorded with the
-- actor's current organization role, follows the previous step in time, and an approval
-- still targets a verifiable finding.
CREATE FUNCTION policy.check_exception_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_request  policy.exception_requests%ROWTYPE;
    v_previous TIMESTAMPTZ;
    v_target   RECORD;
BEGIN
    SELECT r.* INTO v_request FROM policy.exception_requests r WHERE r.id = NEW.request_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'exception rejected: NOT_FOUND' USING ERRCODE = '23514';
    END IF;
    NEW.occurred_at := clock_timestamp();
    NEW.recorded_by := session_user;
    IF policy.member_role(v_request.organization_id, NEW.actor) IS DISTINCT FROM NEW.actor_role THEN
        RAISE EXCEPTION 'exception rejected: NOT_AUTHORIZED' USING ERRCODE = '23514';
    END IF;
    IF NEW.seq > 0 THEN
        SELECT t.occurred_at INTO v_previous FROM policy.exception_transitions t
         WHERE t.request_id = NEW.request_id AND t.seq = NEW.seq - 1;
        IF NOT FOUND OR v_previous >= NEW.occurred_at THEN
            RAISE EXCEPTION 'exception rejected: INVALID_TRANSITION' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.to_state = 'APPROVED' THEN
        SELECT * INTO v_target
          FROM policy.exception_target(v_request.evaluation_id, v_request.scanner_type, v_request.finding_fingerprint);
        IF v_target.problem IS NOT NULL OR v_target.job_id IS DISTINCT FROM v_request.job_id
                OR v_target.artifact_sha256 IS DISTINCT FROM v_request.artifact_sha256::text THEN
            RAISE EXCEPTION 'exception rejected: FINDING_NOT_VERIFIED' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$fn$;

CREATE TRIGGER tr_exception_transitions_check BEFORE INSERT ON policy.exception_transitions
    FOR EACH ROW EXECUTE FUNCTION policy.check_exception_transition();

-- ---------------------------------------------------------------------------
-- 6. Current status, derived from the database clock on every read
-- ---------------------------------------------------------------------------

-- state: the last recorded transition. status: what applies now. An approval is ACTIVE only
-- before its expiry; a request or approval at or after expiry is EXPIRED. A request without
-- any transition (impossible through the functions) is INVALID and never applies.
CREATE VIEW policy.exception_status AS
SELECT r.id, r.organization_id, r.project_id, r.scan_id, r.evaluation_id, r.policy_version_id, r.policy_sha256,
       r.engine_version, r.job_id, r.scanner_type, r.lease_epoch, r.artifact_name, r.artifact_sha256,
       r.result_sha256, r.finding_fingerprint, r.finding_rule_id, r.finding_category, r.finding_scanner_severity,
       r.justification, r.requested_by, r.requested_at, r.expires_at,
       t.to_state AS state, t.occurred_at AS state_changed_at,
       CASE WHEN t.to_state IS NULL THEN 'INVALID'
            WHEN t.to_state IN ('REQUESTED', 'APPROVED') AND now() >= r.expires_at THEN 'EXPIRED'
            WHEN t.to_state = 'APPROVED' THEN 'ACTIVE'
            ELSE t.to_state END AS status,
       now() AS status_as_of
FROM policy.exception_requests r
LEFT JOIN LATERAL (SELECT x.to_state, x.occurred_at FROM policy.exception_transitions x
                   WHERE x.request_id = r.id ORDER BY x.seq DESC LIMIT 1) t ON true;

COMMENT ON VIEW policy.exception_status IS
    'Security exception requests with their last recorded state and their status at the database clock.';

-- ---------------------------------------------------------------------------
-- 7. Writing requests and transitions (EXECUTE: sentinel_api)
-- ---------------------------------------------------------------------------

-- Requests an exception for the blocking finding p_fingerprint of scanner p_scanner_type in
-- the original FAIL evaluation of scan p_scan_id. Everything else (evaluation, policy,
-- engine, job, evidence digests, rule, category, severity) is derived here from stored
-- records, never accepted from the caller. Returns (outcome, exception_id): CREATED,
-- DUPLICATE (an open request or active exception exists for the same finding: its id),
-- NOT_FOUND, SCAN_NOT_ELIGIBLE, FINDING_NOT_ELIGIBLE, EVIDENCE_UNAVAILABLE, NOT_AUTHORIZED,
-- INVALID_EXPIRY or LIMIT_REACHED. Requests of one scan are serialized by a lock on its
-- original evaluation row.
CREATE FUNCTION policy.request_exception(p_scan_id UUID, p_scanner_type TEXT, p_fingerprint TEXT,
    p_justification TEXT, p_expires_at TIMESTAMPTZ, p_actor TEXT)
RETURNS TABLE (outcome TEXT, exception_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
    v_scan     public.scans%ROWTYPE;
    v_eval     policy.evaluations%ROWTYPE;
    v_role     TEXT;
    v_target   RECORD;
    v_existing UUID;
    v_now      TIMESTAMPTZ := clock_timestamp();
    v_id       UUID;
BEGIN
    IF p_scan_id IS NULL OR p_scanner_type IS NULL OR p_scanner_type NOT IN ('GITLEAKS', 'SEMGREP', 'TRIVY')
            OR p_fingerprint IS NULL OR p_fingerprint !~ '^[0-9a-f]{64}$'
            OR p_justification IS NULL OR char_length(p_justification) NOT BETWEEN 20 AND 2000
            OR p_justification ~ '[[:cntrl:]]' OR btrim(p_justification) <> p_justification
            OR p_expires_at IS NULL
            OR p_actor IS NULL
            OR p_actor !~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'exception rejected: INVALID_ARGUMENTS' USING ERRCODE = '22023';
    END IF;
    SELECT s.* INTO v_scan FROM public.scans s WHERE s.id = p_scan_id;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'NOT_FOUND'::text, NULL::uuid;
        RETURN;
    END IF;
    -- Serializes requests of this scan (duplicates, limit). NO KEY UPDATE does not conflict
    -- with the KEY SHARE locks of foreign-key checks.
    SELECT e.* INTO v_eval FROM policy.evaluations e WHERE e.scan_id = p_scan_id FOR NO KEY UPDATE;
    IF NOT FOUND OR v_scan.execution_status <> 'COMPLETED' OR v_scan.security_decision <> 'FAIL'
            OR v_eval.decision <> 'FAIL' THEN
        RETURN QUERY SELECT 'SCAN_NOT_ELIGIBLE'::text, NULL::uuid;
        RETURN;
    END IF;
    v_role := policy.member_role(v_eval.organization_id, p_actor);
    IF v_role IS NULL OR v_role NOT IN ('OWNER', 'ADMIN') THEN
        RETURN QUERY SELECT 'NOT_AUTHORIZED'::text, NULL::uuid;
        RETURN;
    END IF;
    IF p_expires_at < v_now + interval '1 hour' + interval '1 minute' OR p_expires_at > v_now + interval '90 days' THEN
        RETURN QUERY SELECT 'INVALID_EXPIRY'::text, NULL::uuid;
        RETURN;
    END IF;
    SELECT * INTO v_target FROM policy.exception_target(v_eval.id, p_scanner_type, p_fingerprint);
    IF v_target.problem IS NOT NULL THEN
        RETURN QUERY SELECT (CASE WHEN v_target.problem = 'EVIDENCE_UNAVAILABLE' THEN 'EVIDENCE_UNAVAILABLE'
                                  ELSE 'FINDING_NOT_ELIGIBLE' END)::text, NULL::uuid;
        RETURN;
    END IF;
    -- One open request or active exception per finding: a duplicate never bypasses approval.
    SELECT st.id INTO v_existing FROM policy.exception_status st
     WHERE st.evaluation_id = v_eval.id AND st.job_id = v_target.job_id AND st.finding_fingerprint = p_fingerprint
       AND st.state IN ('REQUESTED', 'APPROVED') AND clock_timestamp() < st.expires_at
     ORDER BY st.requested_at LIMIT 1;
    IF FOUND THEN
        RETURN QUERY SELECT 'DUPLICATE'::text, v_existing;
        RETURN;
    END IF;
    IF (SELECT count(*) FROM policy.exception_requests r WHERE r.scan_id = p_scan_id) >= 200 THEN
        RETURN QUERY SELECT 'LIMIT_REACHED'::text, NULL::uuid;
        RETURN;
    END IF;

    INSERT INTO policy.exception_requests (organization_id, project_id, scan_id, evaluation_id, policy_version_id,
        policy_sha256, engine_version, job_id, scanner_type, lease_epoch, artifact_name, artifact_sha256,
        result_sha256, finding_fingerprint, finding_rule_id, finding_category, finding_scanner_severity,
        justification, requested_by, expires_at)
    VALUES (v_eval.organization_id, v_eval.project_id, p_scan_id, v_eval.id, v_eval.policy_version_id,
        v_eval.policy_sha256, v_eval.engine_version, v_target.job_id, p_scanner_type, v_target.lease_epoch,
        v_target.artifact_name, v_target.artifact_sha256, v_target.result_sha256, p_fingerprint, v_target.rule_id,
        v_target.category, v_target.scanner_severity, p_justification, p_actor, p_expires_at)
    RETURNING id INTO v_id;
    INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at, actor,
        actor_role)
    VALUES (v_id, 0, NULL, 'REQUESTED', p_actor, p_expires_at, p_actor, v_role);
    RETURN QUERY SELECT 'CREATED'::text, v_id;
END
$fn$;

-- Moves a request to p_to_state (APPROVED, REJECTED, WITHDRAWN or REVOKED) on behalf of
-- p_actor. Returns TRANSITIONED, NOT_FOUND, INVALID_STATE (the request is not in the state
-- this transition leaves), EXPIRED, EXPIRES_TOO_SOON (approval with under 5 minutes left),
-- NOT_AUTHORIZED (not a member with the required role), SELF_DECISION (the requester cannot
-- approve or reject their own request), NOT_REQUESTER (only the requester withdraws) or
-- EVIDENCE_UNAVAILABLE (approval of a finding that can no longer be verified). Transitions of
-- one request are serialized by its row lock; a concurrent second decision sees the first
-- and returns INVALID_STATE.
CREATE FUNCTION policy.transition_exception(p_exception_id UUID, p_to_state TEXT, p_actor TEXT, p_rationale TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_request policy.exception_requests%ROWTYPE;
    v_current policy.exception_transitions%ROWTYPE;
    v_role    TEXT;
    v_from    TEXT;
    v_target  RECORD;
BEGIN
    IF p_exception_id IS NULL OR p_to_state IS NULL
            OR p_to_state NOT IN ('APPROVED', 'REJECTED', 'WITHDRAWN', 'REVOKED')
            OR p_actor IS NULL
            OR p_actor !~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            OR p_rationale IS NULL OR char_length(p_rationale) NOT BETWEEN 1 AND 1000
            OR p_rationale ~ '[[:cntrl:]]' OR btrim(p_rationale) <> p_rationale THEN
        RAISE EXCEPTION 'exception rejected: INVALID_ARGUMENTS' USING ERRCODE = '22023';
    END IF;
    SELECT r.* INTO v_request FROM policy.exception_requests r WHERE r.id = p_exception_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    SELECT t.* INTO v_current FROM policy.exception_transitions t
     WHERE t.request_id = p_exception_id ORDER BY t.seq DESC LIMIT 1;
    v_from := CASE WHEN p_to_state = 'REVOKED' THEN 'APPROVED' ELSE 'REQUESTED' END;
    IF NOT FOUND OR v_current.to_state <> v_from THEN
        RETURN 'INVALID_STATE';
    END IF;
    IF clock_timestamp() >= v_request.expires_at THEN
        RETURN 'EXPIRED';
    END IF;
    v_role := policy.member_role(v_request.organization_id, p_actor);
    IF v_role IS NULL OR (p_to_state IN ('APPROVED', 'REJECTED', 'REVOKED') AND v_role <> 'OWNER')
            OR (p_to_state = 'WITHDRAWN' AND v_role NOT IN ('OWNER', 'ADMIN')) THEN
        RETURN 'NOT_AUTHORIZED';
    END IF;
    IF p_to_state IN ('APPROVED', 'REJECTED') AND p_actor = v_request.requested_by THEN
        RETURN 'SELF_DECISION';
    END IF;
    IF p_to_state = 'WITHDRAWN' AND p_actor <> v_request.requested_by THEN
        RETURN 'NOT_REQUESTER';
    END IF;
    IF p_to_state = 'APPROVED' THEN
        IF clock_timestamp() > v_request.expires_at - interval '5 minutes' THEN
            RETURN 'EXPIRES_TOO_SOON';
        END IF;
        SELECT * INTO v_target
          FROM policy.exception_target(v_request.evaluation_id, v_request.scanner_type, v_request.finding_fingerprint);
        IF v_target.problem IS NOT NULL THEN
            RETURN 'EVIDENCE_UNAVAILABLE';
        END IF;
    END IF;
    INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at, actor,
        actor_role, rationale)
    VALUES (p_exception_id, v_current.seq + 1, v_from, p_to_state, v_request.requested_by, v_request.expires_at,
        p_actor, v_role, p_rationale);
    RETURN 'TRANSITIONED';
END
$fn$;

-- ---------------------------------------------------------------------------
-- 8. Privileges
-- ---------------------------------------------------------------------------

REVOKE ALL ON policy.exception_requests, policy.exception_transitions, policy.exception_status FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.member_role(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.exception_target(UUID, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.check_exception_request() FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.check_exception_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.request_exception(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION policy.transition_exception(UUID, TEXT, TEXT, TEXT) FROM PUBLIC;

-- The API reads the records directly and writes them only through the two functions.
GRANT SELECT ON policy.exception_requests, policy.exception_transitions, policy.exception_status TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.request_exception(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT) TO sentinel_api;
GRANT EXECUTE ON FUNCTION policy.transition_exception(UUID, TEXT, TEXT, TEXT) TO sentinel_api;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.security_exceptions', 'm4-phase3');

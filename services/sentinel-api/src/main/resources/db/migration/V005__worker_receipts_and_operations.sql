-- V005: Milestone 2, Phase 2C. Shared worker receipts, operator recovery, idempotency expiry.
--
-- 1. Worker receipts (schema `worker`). Every worker instance records processing
--    receipts in PostgreSQL, so deduplication holds across hosts. The worker's database
--    role has no table privileges at all: it may only EXECUTE worker.record_receipt,
--    a SECURITY DEFINER function that verifies the delivered message against the
--    authoritative outbox event, scan and project before accepting it. Queue payloads
--    are never trusted as proof of tenant ownership.
-- 2. Operator recovery (schema `ops`). Bounded, audited functions for requeueing FAILED
--    outbox events and recording dead-letter replays. Executable only by the
--    `sentinel_operator` role; every action writes an ops.recovery_actions row.
-- 3. Idempotency-key expiry. An index supporting bounded cleanup of expired keys on
--    scans (the scans themselves are never deleted).
--
-- Roles: `sentinel_worker` and `sentinel_operator` are NOLOGIN group roles holding the
-- privileges. Login users (with passwords) are provisioned outside migrations and
-- granted membership; see docs/runbooks/messaging.md. Creating the group roles requires
-- the CREATEROLE attribute for the migration user.
--
-- SECURITY DEFINER hardening: fixed search_path (pg_catalog, pg_temp), fully qualified
-- object names, and EXECUTE revoked from PUBLIC (PostgreSQL grants it by default).

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_worker') THEN
        CREATE ROLE sentinel_worker NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_operator') THEN
        CREATE ROLE sentinel_operator NOLOGIN;
    END IF;
END
$roles$;

-- ---------------------------------------------------------------------------
-- 1. Worker receipts
-- ---------------------------------------------------------------------------

CREATE SCHEMA worker;
REVOKE ALL ON SCHEMA worker FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA worker REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- One row per ACCEPTED event. Only messages whose digest matches the committed outbox
-- payload are stored here, so a forged message can never occupy a genuine event_id.
CREATE TABLE worker.processing_receipts (
    event_id        UUID         NOT NULL,
    message_sha256  CHAR(64)     NOT NULL,
    organization_id UUID         NOT NULL,
    project_id      UUID         NOT NULL,
    scan_id         UUID         NOT NULL,
    commit_sha      VARCHAR(64)  NOT NULL,
    outcome         VARCHAR(20)  NOT NULL,
    worker_id       VARCHAR(100) NOT NULL,
    worker_version  VARCHAR(50)  NOT NULL,
    -- Worker clock (as in the receipt document) and database clock.
    received_at     TIMESTAMPTZ  NOT NULL,
    recorded_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    receipt         JSONB        NOT NULL,
    CONSTRAINT pk_processing_receipts PRIMARY KEY (event_id),
    CONSTRAINT fk_processing_receipts_scan FOREIGN KEY (scan_id)
        REFERENCES public.scans (id) ON DELETE RESTRICT,
    CONSTRAINT ck_processing_receipts_sha CHECK (message_sha256 ~ '^[0-9a-f]{64}$'),
    -- Acceptance of a delivery, not completion of scanner execution.
    CONSTRAINT ck_processing_receipts_outcome CHECK (outcome = 'ACCEPTED'),
    CONSTRAINT ck_processing_receipts_document
        CHECK (jsonb_typeof(receipt) = 'object' AND octet_length(receipt::text) <= 4096)
);

CREATE INDEX ix_processing_receipts_scan ON worker.processing_receipts (scan_id);

COMMENT ON TABLE worker.processing_receipts IS
    'Worker acceptance receipts (at-least-once deduplication). Acceptance is not scan execution.';

-- Forensic record of deliveries that were refused. Deduplicated by content and reason so
-- that a flood of identical messages cannot grow it without bound. Claimed identifiers
-- come from the untrusted message and are evidence only.
CREATE TABLE worker.delivery_rejections (
    message_sha256          CHAR(64)     NOT NULL,
    reason                  VARCHAR(40)  NOT NULL,
    event_id                UUID,
    claimed_organization_id UUID,
    claimed_project_id      UUID,
    claimed_scan_id         UUID,
    occurrences             INTEGER      NOT NULL DEFAULT 1,
    first_rejected_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_rejected_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_worker_id          VARCHAR(100) NOT NULL,
    CONSTRAINT pk_delivery_rejections PRIMARY KEY (message_sha256, reason),
    CONSTRAINT ck_delivery_rejections_sha CHECK (message_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_delivery_rejections_reason
        CHECK (reason IN ('UNKNOWN_EVENT', 'DIGEST_MISMATCH', 'RELATIONSHIP_MISMATCH', 'EVENT_ID_CONFLICT')),
    CONSTRAINT ck_delivery_rejections_occurrences CHECK (occurrences >= 1)
);

COMMENT ON TABLE worker.delivery_rejections IS
    'Refused deliveries (possible forgery or tampering). Identifiers are untrusted claims.';

CREATE FUNCTION worker.note_rejection(p_receipt JSONB, p_reason TEXT)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    INSERT INTO worker.delivery_rejections AS r (message_sha256, reason, event_id, claimed_organization_id,
        claimed_project_id, claimed_scan_id, last_worker_id)
    VALUES (p_receipt ->> 'message_sha256', p_reason, (p_receipt ->> 'event_id')::uuid,
        (p_receipt ->> 'organization_id')::uuid, (p_receipt ->> 'project_id')::uuid,
        (p_receipt ->> 'scan_id')::uuid, left(p_receipt ->> 'worker_id', 100))
    ON CONFLICT (message_sha256, reason) DO UPDATE
        SET occurrences = least(r.occurrences, 2147483646) + 1,
            last_rejected_at = now(),
            last_worker_id = excluded.last_worker_id;
$fn$;

REVOKE ALL ON FUNCTION worker.note_rejection(JSONB, TEXT) FROM PUBLIC;

-- Records the acceptance of one delivery, atomically. Returns one of:
--   NEW        first acceptance; the receipt row was committed with this transaction;
--   DUPLICATE  the event was already accepted with an identical message;
--   CONFLICT   the event was already accepted with a DIFFERENT message (tampering);
--   REJECTED_UNKNOWN_EVENT          no scan.requested outbox event has this event_id;
--   REJECTED_DIGEST_MISMATCH        the message differs from the committed outbox payload;
--   REJECTED_RELATIONSHIP_MISMATCH  claimed scan/project/organization/commit differ from
--                                   the authoritative rows.
-- Concurrent calls for the same event_id serialize on the primary key: exactly one
-- returns NEW. The caller must not acknowledge the message before its transaction commits.
CREATE FUNCTION worker.record_receipt(p_receipt JSONB)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_event_id    UUID;
    v_sha         TEXT;
    v_existing    TEXT;
    v_expected    TEXT;
    v_event_org   UUID;
    v_scan_id     UUID;
    v_project_id  UUID;
    v_org_id      UUID;
    v_commit_sha  TEXT;
    v_reason      TEXT;
    v_inserted    INTEGER;
BEGIN
    -- The document is worker-supplied: bound its size (real receipts are under 1 KiB).
    IF p_receipt IS NULL OR jsonb_typeof(p_receipt) <> 'object'
            OR octet_length(p_receipt::text) > 4096
            OR (p_receipt ->> 'outcome') IS DISTINCT FROM 'ACCEPTED'
            OR (p_receipt ->> 'message_sha256') IS NULL
            OR (p_receipt ->> 'message_sha256') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid receipt document' USING ERRCODE = '22023';
    END IF;
    v_event_id := (p_receipt ->> 'event_id')::uuid;
    v_sha := p_receipt ->> 'message_sha256';

    SELECT r.message_sha256 INTO v_existing
    FROM worker.processing_receipts r
    WHERE r.event_id = v_event_id;
    IF FOUND THEN
        IF v_existing = v_sha THEN
            RETURN 'DUPLICATE';
        END IF;
        PERFORM worker.note_rejection(p_receipt, 'EVENT_ID_CONFLICT');
        RETURN 'CONFLICT';
    END IF;

    -- The published message body is exactly outbox_events.payload::text (OutboxStore#claim).
    SELECT encode(sha256(convert_to(o.payload::text, 'UTF8')), 'hex'), o.organization_id,
           s.id, s.project_id, p.organization_id, s.commit_sha
      INTO v_expected, v_event_org, v_scan_id, v_project_id, v_org_id, v_commit_sha
      FROM public.outbox_events o
      JOIN public.scans s ON s.id = o.aggregate_id
      JOIN public.projects p ON p.id = s.project_id
     WHERE o.id = v_event_id
       AND o.event_type = 'scan.requested'
       AND o.aggregate_type = 'scan';

    IF NOT FOUND THEN
        v_reason := 'UNKNOWN_EVENT';
    ELSIF v_expected <> v_sha THEN
        v_reason := 'DIGEST_MISMATCH';
    ELSIF v_scan_id IS DISTINCT FROM (p_receipt ->> 'scan_id')::uuid
            OR v_project_id IS DISTINCT FROM (p_receipt ->> 'project_id')::uuid
            OR v_org_id IS DISTINCT FROM (p_receipt ->> 'organization_id')::uuid
            OR v_event_org IS DISTINCT FROM v_org_id
            OR v_commit_sha IS DISTINCT FROM (p_receipt ->> 'commit_sha') THEN
        v_reason := 'RELATIONSHIP_MISMATCH';
    END IF;
    IF v_reason IS NOT NULL THEN
        PERFORM worker.note_rejection(p_receipt, v_reason);
        RETURN 'REJECTED_' || v_reason;
    END IF;

    -- Identifiers are stored from the authoritative rows, not from the message.
    INSERT INTO worker.processing_receipts (event_id, message_sha256, organization_id, project_id, scan_id,
        commit_sha, outcome, worker_id, worker_version, received_at, receipt)
    VALUES (v_event_id, v_sha, v_org_id, v_project_id, v_scan_id, v_commit_sha, 'ACCEPTED',
        left(p_receipt ->> 'worker_id', 100), left(p_receipt ->> 'worker_version', 50),
        (p_receipt ->> 'received_at')::timestamptz, p_receipt)
    ON CONFLICT (event_id) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted = 1 THEN
        RETURN 'NEW';
    END IF;

    -- A concurrent worker committed the receipt first (new statement, new snapshot).
    SELECT r.message_sha256 INTO v_existing
    FROM worker.processing_receipts r
    WHERE r.event_id = v_event_id;
    IF v_existing = v_sha THEN
        RETURN 'DUPLICATE';
    END IF;
    PERFORM worker.note_rejection(p_receipt, 'EVENT_ID_CONFLICT');
    RETURN 'CONFLICT';
END
$fn$;

REVOKE ALL ON FUNCTION worker.record_receipt(JSONB) FROM PUBLIC;
GRANT USAGE ON SCHEMA worker TO sentinel_worker;
GRANT EXECUTE ON FUNCTION worker.record_receipt(JSONB) TO sentinel_worker;

-- ---------------------------------------------------------------------------
-- 2. Operator recovery
-- ---------------------------------------------------------------------------

CREATE SCHEMA ops;
REVOKE ALL ON SCHEMA ops FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Append-only audit trail of recovery actions. Contains identifiers, digests and
-- sanitized codes only; never message bodies or credentials.
CREATE TABLE ops.recovery_actions (
    id             UUID         NOT NULL DEFAULT gen_random_uuid(),
    action         VARCHAR(40)  NOT NULL,
    operator       VARCHAR(100) NOT NULL,
    reason         VARCHAR(500) NOT NULL,
    database_user  VARCHAR(100) NOT NULL DEFAULT session_user,
    event_id       UUID,
    message_sha256 CHAR(64),
    detail         VARCHAR(100),
    performed_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_recovery_actions PRIMARY KEY (id),
    CONSTRAINT ck_recovery_actions_action
        CHECK (action IN ('OUTBOX_REQUEUE_FAILED', 'DEAD_LETTER_REPLAY')),
    CONSTRAINT ck_recovery_actions_operator CHECK (operator ~ '^[A-Za-z0-9._@-]{1,100}$'),
    CONSTRAINT ck_recovery_actions_reason CHECK (btrim(reason) <> ''),
    CONSTRAINT ck_recovery_actions_sha CHECK (message_sha256 IS NULL OR message_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_recovery_actions_detail CHECK (detail IS NULL OR detail ~ '^[A-Z0-9_]{1,100}$')
);

CREATE INDEX ix_recovery_actions_performed ON ops.recovery_actions (performed_at);

COMMENT ON TABLE ops.recovery_actions IS 'Audit trail of operator recovery actions (append-only).';

-- Read-only summary for operators (no payloads).
CREATE FUNCTION ops.outbox_summary()
RETURNS TABLE (pending BIGINT, failed BIGINT, expired_leases BIGINT, oldest_pending_age_seconds DOUBLE PRECISION)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT count(*) FILTER (WHERE o.status = 'PENDING'),
           count(*) FILTER (WHERE o.status = 'FAILED'),
           count(*) FILTER (WHERE o.status = 'PENDING' AND o.lease_expires_at <= now()),
           coalesce(extract(epoch FROM now() - min(o.created_at) FILTER (WHERE o.status = 'PENDING')), 0)::double precision
    FROM public.outbox_events o
    WHERE o.status IN ('PENDING', 'FAILED');
$fn$;

-- FAILED events, oldest first, without payloads. Bounded to 100 rows.
CREATE FUNCTION ops.list_failed_outbox_events(p_limit INTEGER DEFAULT 20)
RETURNS TABLE (event_id UUID, event_type VARCHAR, attempts INTEGER, last_error VARCHAR, failed_at TIMESTAMPTZ)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
    SELECT o.id, o.event_type, o.attempts, o.last_error, o.updated_at
    FROM public.outbox_events o
    WHERE o.status = 'FAILED'
    ORDER BY o.updated_at, o.id
    LIMIT least(greatest(coalesce(p_limit, 20), 1), 100);
$fn$;

-- Returns FAILED events to PENDING for immediate publication (attempts reset), and
-- audits each one. Either explicit ids or the oldest FAILED events, at most 100 per call.
-- Re-publication is safe: workers deduplicate by event_id against worker receipts.
CREATE FUNCTION ops.requeue_failed_outbox_events(p_operator TEXT, p_reason TEXT, p_event_ids UUID[] DEFAULT NULL,
    p_limit INTEGER DEFAULT 10)
RETURNS TABLE (event_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF p_operator IS NULL OR p_operator !~ '^[A-Za-z0-9._@-]{1,100}$' THEN
        RAISE EXCEPTION 'operator must be 1-100 characters: letters, digits, ._@-' USING ERRCODE = '22023';
    END IF;
    IF p_reason IS NULL OR btrim(p_reason) = '' OR length(p_reason) > 500 THEN
        RAISE EXCEPTION 'reason must be 1-500 characters' USING ERRCODE = '22023';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'limit must be between 1 and 100' USING ERRCODE = '22023';
    END IF;
    IF p_event_ids IS NOT NULL AND cardinality(p_event_ids) > 100 THEN
        RAISE EXCEPTION 'at most 100 event ids per call' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    WITH candidates AS (
        SELECT o.id
        FROM public.outbox_events o
        WHERE o.status = 'FAILED'
          AND (p_event_ids IS NULL OR o.id = ANY (p_event_ids))
        ORDER BY o.updated_at, o.id
        LIMIT CASE WHEN p_event_ids IS NULL THEN p_limit ELSE 100 END
        FOR UPDATE SKIP LOCKED
    ), requeued AS (
        UPDATE public.outbox_events o
        SET status = 'PENDING', attempts = 0, next_attempt_at = now(), last_error = NULL, updated_at = now()
        FROM candidates c
        WHERE o.id = c.id
        RETURNING o.id, o.last_error
    ), audited AS (
        INSERT INTO ops.recovery_actions (action, operator, reason, event_id)
        SELECT 'OUTBOX_REQUEUE_FAILED', p_operator, p_reason, r.id FROM requeued r
        RETURNING ops.recovery_actions.event_id
    )
    SELECT a.event_id FROM audited a;
END
$fn$;

-- Audit record written by the dead-letter replay tool BEFORE it republishes a message.
CREATE FUNCTION ops.record_dead_letter_replay(p_operator TEXT, p_reason TEXT, p_event_id UUID,
    p_message_sha256 TEXT, p_failure_code TEXT)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_id UUID;
BEGIN
    IF p_reason IS NULL OR length(p_reason) > 500 THEN
        RAISE EXCEPTION 'reason must be 1-500 characters' USING ERRCODE = '22023';
    END IF;
    INSERT INTO ops.recovery_actions (action, operator, reason, event_id, message_sha256, detail)
    VALUES ('DEAD_LETTER_REPLAY', p_operator, p_reason, p_event_id, p_message_sha256, p_failure_code)
    RETURNING id INTO v_id;
    RETURN v_id;
END
$fn$;

REVOKE ALL ON FUNCTION ops.outbox_summary() FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.list_failed_outbox_events(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.requeue_failed_outbox_events(TEXT, TEXT, UUID[], INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops.record_dead_letter_replay(TEXT, TEXT, UUID, TEXT, TEXT) FROM PUBLIC;
GRANT USAGE ON SCHEMA ops TO sentinel_operator;
GRANT EXECUTE ON FUNCTION ops.outbox_summary() TO sentinel_operator;
GRANT EXECUTE ON FUNCTION ops.list_failed_outbox_events(INTEGER) TO sentinel_operator;
GRANT EXECUTE ON FUNCTION ops.requeue_failed_outbox_events(TEXT, TEXT, UUID[], INTEGER) TO sentinel_operator;
GRANT EXECUTE ON FUNCTION ops.record_dead_letter_replay(TEXT, TEXT, UUID, TEXT, TEXT) TO sentinel_operator;

-- ---------------------------------------------------------------------------
-- 3. Idempotency-key expiry
-- ---------------------------------------------------------------------------

-- Bounded cleanup scans only scans that still hold a key, oldest first.
CREATE INDEX ix_scans_idempotency_expiry ON scans (requested_at, id) WHERE idempotency_key IS NOT NULL;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.worker_receipts', 'm2-phase2c');

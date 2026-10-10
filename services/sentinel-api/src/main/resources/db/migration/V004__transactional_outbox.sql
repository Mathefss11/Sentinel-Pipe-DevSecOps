-- V004: Milestone 2, Phase 2B transactional outbox.
--
-- Domain events are written to this table in the same transaction as the state
-- change that produces them (for example, a new scan). A separate publisher
-- claims pending rows, publishes them to RabbitMQ with publisher confirms, and
-- marks them PUBLISHED only after a positive broker confirmation.
--
-- Delivery is at-least-once: a crash between the broker confirmation and the
-- PUBLISHED update re-publishes the event. Consumers deduplicate by event id.
-- There is no ordering guarantee between events.
--
-- Claims are leases: `lease_owner` / `lease_expires_at` are set by the claiming
-- publisher (SELECT ... FOR UPDATE SKIP LOCKED); an expired lease is claimable
-- again, which recovers events abandoned by crashed publishers.

CREATE TABLE outbox_events (
    id               UUID         NOT NULL,
    event_type       VARCHAR(100) NOT NULL,
    schema_version   INTEGER      NOT NULL,
    aggregate_type   VARCHAR(50)  NOT NULL,
    aggregate_id     UUID         NOT NULL,
    organization_id  UUID         NOT NULL,
    correlation_id   UUID         NOT NULL,
    payload          JSONB        NOT NULL,
    status           VARCHAR(20)  NOT NULL,
    attempts         INTEGER      NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ  NOT NULL,
    lease_owner      VARCHAR(100),
    lease_expires_at TIMESTAMPTZ,
    -- Sanitized failure category only (for example BROKER_UNAVAILABLE); never
    -- payloads, credentials or raw exception messages.
    last_error       VARCHAR(100),
    created_at       TIMESTAMPTZ  NOT NULL,
    published_at     TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_outbox_events PRIMARY KEY (id),
    -- One event of each type per aggregate: idempotent scan replays can never
    -- enqueue a second scan.requested event, even under concurrency.
    CONSTRAINT uq_outbox_events_aggregate_event_type UNIQUE (aggregate_id, event_type),
    CONSTRAINT ck_outbox_events_event_type_format CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT ck_outbox_events_schema_version CHECK (schema_version >= 1),
    CONSTRAINT ck_outbox_events_aggregate_type_format CHECK (aggregate_type ~ '^[a-z][a-z0-9_]*$'),
    CONSTRAINT ck_outbox_events_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_outbox_events_status CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED')),
    CONSTRAINT ck_outbox_events_attempts CHECK (attempts >= 0),
    CONSTRAINT ck_outbox_events_lease_pair
        CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CONSTRAINT ck_outbox_events_status_consistency CHECK (
        (status = 'PENDING' AND published_at IS NULL)
        OR (status = 'PUBLISHED' AND published_at IS NOT NULL AND lease_owner IS NULL)
        OR (status = 'FAILED' AND published_at IS NULL AND lease_owner IS NULL)
    ),
    CONSTRAINT ck_outbox_events_timestamps CHECK (
        updated_at >= created_at AND (published_at IS NULL OR published_at >= created_at)
    )
);

-- Claim scan over due pending events.
CREATE INDEX ix_outbox_events_pending_due
    ON outbox_events (next_attempt_at, created_at)
    WHERE status = 'PENDING';

-- Operational lookups of terminally failed events.
CREATE INDEX ix_outbox_events_failed
    ON outbox_events (updated_at)
    WHERE status = 'FAILED';

COMMENT ON TABLE outbox_events IS 'Transactional outbox: at-least-once publication of domain events to RabbitMQ.';
COMMENT ON COLUMN outbox_events.payload IS 'Exact message body published to the broker; contains no credentials or tokens.';

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.outbox', 'm2-phase2b');

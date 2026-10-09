-- V001: Milestone 1 foundation baseline.
--
-- Intentionally minimal. It establishes the Flyway-managed schema and records
-- which baseline the database was created from. The domain model
-- (organizations, projects, scans, findings, ...) is introduced by later,
-- separately reviewed migrations.

CREATE TABLE platform_metadata (
    metadata_key   VARCHAR(100) NOT NULL,
    metadata_value VARCHAR(500) NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_platform_metadata PRIMARY KEY (metadata_key),
    CONSTRAINT ck_platform_metadata_key_format CHECK (metadata_key ~ '^[a-z][a-z0-9_.]{0,99}$')
);

COMMENT ON TABLE platform_metadata IS 'Platform-level schema metadata (non-tenant, no secrets).';

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.baseline', 'm1-foundation');

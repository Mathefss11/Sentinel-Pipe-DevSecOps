-- V003: Milestone 2, Phase 2A identity and organization memberships.
--
-- Users authenticate with an external OIDC identity provider. SentinelPipe stores
-- no passwords and no profile data: a user identity is only the (issuer, subject)
-- pair from validated access tokens.
--
-- Authorization is based exclusively on server-side membership rows. Organization
-- or role claims inside tokens are never trusted for tenant access.

CREATE TABLE user_identities (
    id         UUID         NOT NULL,
    issuer     VARCHAR(512) NOT NULL,
    subject    VARCHAR(255) NOT NULL,
    version    BIGINT       NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_user_identities PRIMARY KEY (id),
    CONSTRAINT uq_user_identities_issuer_subject UNIQUE (issuer, subject),
    CONSTRAINT ck_user_identities_issuer_format
        CHECK (btrim(issuer) <> '' AND issuer !~ '[[:cntrl:]]'),
    CONSTRAINT ck_user_identities_subject_format
        CHECK (btrim(subject) <> '' AND subject !~ '[[:cntrl:]]'),
    CONSTRAINT ck_user_identities_timestamps CHECK (updated_at >= created_at)
);

COMMENT ON TABLE user_identities IS 'External OIDC identities, keyed by token issuer and subject. No credentials or PII.';

CREATE TABLE organization_memberships (
    id               UUID        NOT NULL,
    organization_id  UUID        NOT NULL,
    user_identity_id UUID        NOT NULL,
    role             VARCHAR(20) NOT NULL,
    -- NULL only for the bootstrap owner created together with the organization.
    granted_by       UUID,
    version          BIGINT      NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_organization_memberships PRIMARY KEY (id),
    CONSTRAINT fk_organization_memberships_organization FOREIGN KEY (organization_id)
        REFERENCES organizations (id) ON DELETE RESTRICT,
    CONSTRAINT fk_organization_memberships_user_identity FOREIGN KEY (user_identity_id)
        REFERENCES user_identities (id) ON DELETE RESTRICT,
    CONSTRAINT fk_organization_memberships_granted_by FOREIGN KEY (granted_by)
        REFERENCES user_identities (id) ON DELETE RESTRICT,
    CONSTRAINT uq_organization_memberships_organization_user
        UNIQUE (organization_id, user_identity_id),
    CONSTRAINT ck_organization_memberships_role
        CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER')),
    CONSTRAINT ck_organization_memberships_not_self_granted
        CHECK (granted_by IS NULL OR granted_by <> user_identity_id),
    CONSTRAINT ck_organization_memberships_timestamps CHECK (updated_at >= created_at)
);

-- Authorization lookups by user, and the paginated per-organization member listing.
CREATE INDEX ix_organization_memberships_user ON organization_memberships (user_identity_id);
CREATE INDEX ix_organization_memberships_organization_created
    ON organization_memberships (organization_id, created_at, id);

COMMENT ON TABLE organization_memberships IS 'Server-side source of truth for organization roles (OWNER, ADMIN, MEMBER, VIEWER).';

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.identity', 'm2-phase2a');

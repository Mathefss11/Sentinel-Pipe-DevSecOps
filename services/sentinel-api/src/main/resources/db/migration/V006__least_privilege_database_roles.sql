-- V006: Milestone 3, Phase 1. Least-privilege database roles.
--
-- Until V005 the API connected as the schema owner (in local and CI stacks, the cluster
-- superuser), and every SECURITY DEFINER function ran with the owner's privileges. From
-- this version on:
--
--   sentinel_owner     (NOLOGIN, not a superuser) owns every object. Flyway connects as a
--                      dedicated migrator login that may SET ROLE sentinel_owner but
--                      inherits nothing from it (spring.flyway.init-sqls).
--   sentinel_api       API runtime: DML on the tables it uses, no DDL, no access to the
--                      worker or ops schemas. UPDATE on scans, scan_jobs and outbox_events
--                      is granted per column, so identifiers, commits and published
--                      payloads cannot be rewritten after insertion.
--   sentinel_worker    unchanged (V005): EXECUTE on worker functions only.
--   sentinel_operator  unchanged (V005): EXECUTE on ops functions only.
--
-- Roles, login users and ownership of pre-existing objects are managed by the
-- administrative provisioning script (infrastructure/docker/postgres/provision-roles.sh),
-- because role creation is cluster-wide and needs CREATEROLE. This migration only grants
-- and verifies; it fails, changing nothing, if the database was not provisioned. See
-- docs/runbooks/database-roles.md for the upgrade path of existing installations.

DO $preconditions$
DECLARE
    v_missing TEXT;
    v_foreign TEXT;
BEGIN
    IF current_user <> 'sentinel_owner' THEN
        RAISE EXCEPTION 'V006 must run as sentinel_owner (current role: %). Run provision-roles.sh, then '
            'migrate with the migrator login and spring.flyway.init-sqls=SET ROLE sentinel_owner.', current_user
            USING ERRCODE = '42501';
    END IF;

    SELECT string_agg(r, ', ') INTO v_missing
    FROM unnest(ARRAY['sentinel_api', 'sentinel_worker', 'sentinel_operator']) r
    WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
    IF v_missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing group roles: %. Run provision-roles.sh first.', v_missing USING ERRCODE = '42704';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_owner'
               AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)) THEN
        RAISE EXCEPTION 'sentinel_owner must not be a superuser or hold CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS'
            USING ERRCODE = '42501';
    END IF;

    -- Every object of the application schemas must already belong to sentinel_owner
    -- (provision-roles.sh transfers ownership on upgrade).
    SELECT string_agg(name, ', ') INTO v_foreign FROM (
        SELECT n.nspname || '.' || c.relname AS name
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('public', 'worker', 'ops') AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND c.relowner <> 'sentinel_owner'::regrole
        UNION ALL
        SELECT p.oid::regprocedure::text
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname IN ('public', 'worker', 'ops') AND p.proowner <> 'sentinel_owner'::regrole
        UNION ALL
        SELECT n.nspname FROM pg_catalog.pg_namespace n
        WHERE n.nspname IN ('worker', 'ops') AND n.nspowner <> 'sentinel_owner'::regrole
    ) foreign_objects;
    IF v_foreign IS NOT NULL THEN
        RAISE EXCEPTION 'objects not owned by sentinel_owner: %. Run provision-roles.sh (upgrade path).',
            left(v_foreign, 500) USING ERRCODE = '42501';
    END IF;
END
$preconditions$;

-- Functions created from now on are never executable by PUBLIC by default. V005 set this
-- for the role that ran it; on upgraded installations that was the former owner.
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner IN SCHEMA public, worker, ops
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Nothing in the application schemas is reachable through PUBLIC.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA worker FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ops FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- API runtime. (USAGE on schema public is held by PUBLIC; the schema is owned by the
-- database owner and only sentinel_owner may create in it, see provision-roles.sh.)
GRANT SELECT ON platform_metadata TO sentinel_api;
GRANT SELECT, INSERT, UPDATE ON organizations, projects TO sentinel_api;
GRANT SELECT, INSERT ON user_identities TO sentinel_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON organization_memberships TO sentinel_api;

GRANT SELECT, INSERT ON scans, scan_jobs, outbox_events TO sentinel_api;
GRANT UPDATE (execution_status, security_decision, idempotency_key, request_fingerprint, version,
    started_at, completed_at, updated_at) ON scans TO sentinel_api;
GRANT UPDATE (execution_status, attempt_count, version, started_at, completed_at, updated_at)
    ON scan_jobs TO sentinel_api;
GRANT UPDATE (status, attempts, next_attempt_at, lease_owner, lease_expires_at, last_error,
    published_at, updated_at) ON outbox_events TO sentinel_api;

INSERT INTO platform_metadata (metadata_key, metadata_value)
VALUES ('schema.database_roles', 'm3-phase1');

#!/bin/sh
# SentinelPipe PostgreSQL roles and ownership. Runs INSIDE the database container as the
# cluster administrator (POSTGRES_USER), through the local socket. The administrator is a
# provisioning identity only: no service connects with it.
#
# Group roles (NOLOGIN; privileges are granted to these, see Flyway V005-V006):
#
#   sentinel_owner     owns every schema object and every SECURITY DEFINER function.
#                      Not a superuser; no CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS.
#   sentinel_api       API runtime: DML on the control-plane tables it uses; no DDL.
#   sentinel_worker    EXECUTE on worker.* functions only; no table privileges.
#   sentinel_operator  EXECUTE on audited ops.* functions only; no table privileges.
#
# Login roles (created or updated; passwords from the environment):
#
#   migrator  SENTINEL_DB_MIGRATION_USERNAME / _PASSWORD  Flyway. May SET ROLE sentinel_owner
#                                                         but inherits nothing from it.
#   api       SENTINEL_DB_USERNAME / _PASSWORD            member of sentinel_api
#   worker    SENTINEL_WORKER_DB_USERNAME / _PASSWORD     member of sentinel_worker
#   operator  SENTINEL_OPERATOR_DB_USERNAME / _PASSWORD   member of sentinel_operator (optional)
#
# Upgrade path: installations created before Flyway V006 have every object owned by the
# administrator. This script transfers ownership of all objects in the public, worker and
# ops schemas (including flyway_schema_history) to sentinel_owner, so it must run BEFORE
# the API is started with V006. See docs/runbooks/database-roles.md.
#
# Passwords are read with psql's \getenv, so they never appear in process arguments.
# Idempotent; safe to re-run (for example after changing a password).
set -eu

: "${SENTINEL_DB_MIGRATION_PASSWORD:?SENTINEL_DB_MIGRATION_PASSWORD must be set}"
: "${SENTINEL_DB_PASSWORD:?SENTINEL_DB_PASSWORD must be set (API runtime login)}"
: "${SENTINEL_WORKER_DB_PASSWORD:?SENTINEL_WORKER_DB_PASSWORD must be set}"
export SENTINEL_DB_MIGRATION_USERNAME="${SENTINEL_DB_MIGRATION_USERNAME:-sentinel_migrator_app}"
export SENTINEL_DB_USERNAME="${SENTINEL_DB_USERNAME:-sentinel_api_app}"
export SENTINEL_WORKER_DB_USERNAME="${SENTINEL_WORKER_DB_USERNAME:-sentinel_worker_app}"
export SENTINEL_OPERATOR_DB_USERNAME="${SENTINEL_OPERATOR_DB_USERNAME:-sentinel_operator_app}"
export SENTINEL_OPERATOR_DB_PASSWORD="${SENTINEL_OPERATOR_DB_PASSWORD:-}"

psql -v ON_ERROR_STOP=1 --quiet --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv admin_user POSTGRES_USER
\getenv database POSTGRES_DB
\getenv migrator_user SENTINEL_DB_MIGRATION_USERNAME
\getenv migrator_password SENTINEL_DB_MIGRATION_PASSWORD
\getenv api_user SENTINEL_DB_USERNAME
\getenv api_password SENTINEL_DB_PASSWORD
\getenv worker_user SENTINEL_WORKER_DB_USERNAME
\getenv worker_password SENTINEL_WORKER_DB_PASSWORD
\getenv operator_user SENTINEL_OPERATOR_DB_USERNAME
\getenv operator_password SENTINEL_OPERATOR_DB_PASSWORD
-- Re-runs re-grant unchanged memberships; their notices are noise.
SET client_min_messages = warning;

-- Refuse configurations that would demote the administrator, reuse a group role as a
-- login, or give one login two identities (for example a pre-upgrade .env whose
-- SENTINEL_DB_USERNAME still names the administrator).
-- One row; `problem` is NULL (and \gset leaves the variable unset) when all checks pass.
SELECT 'invalid login role configuration: ' || string_agg(problem, '; ') AS problem
FROM (
    SELECT 'login roles must be distinct' AS problem
    WHERE (SELECT count(DISTINCT u) FROM unnest(ARRAY[:'migrator_user', :'api_user', :'worker_user',
              :'operator_user']) u) <> 4
    UNION ALL
    SELECT format('%s is the administrator or a group role', u)
    FROM unnest(ARRAY[:'migrator_user', :'api_user', :'worker_user', :'operator_user']) u
    WHERE u IN (:'admin_user', 'sentinel_owner', 'sentinel_api', 'sentinel_worker', 'sentinel_operator')
    UNION ALL
    SELECT format('%s is a superuser', r.rolname)
    FROM pg_roles r
    WHERE r.rolsuper AND r.rolname IN (:'migrator_user', :'api_user', :'worker_user', :'operator_user')
) p \gset
\if :{?problem}
SELECT format('DO $fail$ BEGIN RAISE EXCEPTION %L; END $fail$', :'problem') \gexec
\endif

-- Group roles. ALTER makes the attributes explicit even if a role pre-exists.
SELECT format('CREATE ROLE %I NOLOGIN', g)
FROM unnest(ARRAY['sentinel_owner', 'sentinel_api', 'sentinel_worker', 'sentinel_operator']) g
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = g) \gexec
SELECT format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', g)
FROM unnest(ARRAY['sentinel_owner', 'sentinel_api', 'sentinel_worker', 'sentinel_operator']) g \gexec

-- Login roles.
CREATE TEMPORARY TABLE provision_logins (name TEXT, password TEXT, grp TEXT, conn_limit INT,
    membership TEXT);
INSERT INTO provision_logins VALUES
    (:'migrator_user', :'migrator_password', 'sentinel_owner', 2, 'INHERIT FALSE, SET TRUE'),
    (:'api_user', :'api_password', 'sentinel_api', 50, 'INHERIT TRUE, SET FALSE'),
    (:'worker_user', :'worker_password', 'sentinel_worker', 20, 'INHERIT TRUE, SET FALSE'),
    (:'operator_user', :'operator_password', 'sentinel_operator', 5, 'INHERIT TRUE, SET FALSE');
-- The operator identity is optional.
DELETE FROM provision_logins WHERE grp = 'sentinel_operator' AND password = '';

SELECT format('CREATE ROLE %I LOGIN', name) FROM provision_logins
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = name) \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
              'NOBYPASSRLS INHERIT CONNECTION LIMIT %s', name, password, conn_limit)
FROM provision_logins \gexec
-- Re-granting updates the membership options of an existing grant.
SELECT format('GRANT %I TO %I WITH ADMIN FALSE, %s', grp, name, membership) FROM provision_logins \gexec

-- Database: no access for PUBLIC; only the SentinelPipe logins may connect.
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'database') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database', name) FROM provision_logins \gexec
-- The owner creates the worker and ops schemas (V005) and objects in public.
SELECT format('GRANT CREATE ON DATABASE %I TO sentinel_owner', :'database') \gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO sentinel_owner;
DROP TABLE provision_logins;

-- Upgrade path: transfer ownership of pre-existing objects to sentinel_owner. Existing
-- grants are preserved (PostgreSQL rewrites the grantor to the new owner). Objects that
-- belong to an extension are left alone.
DO $transfer$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT n.nspname, c.relname,
               CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                              WHEN 'S' THEN 'SEQUENCE' WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END AS kind
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle')
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND c.relowner <> 'sentinel_owner'::regrole
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid
                            AND d.deptype = 'e')
          -- Sequences owned by a table column follow their table.
          AND NOT (c.relkind = 'S' AND EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid
                            AND d.deptype IN ('a', 'i')))
    LOOP
        EXECUTE format('ALTER %s %I.%I OWNER TO sentinel_owner', r.kind, r.nspname, r.relname);
    END LOOP;

    FOR r IN
        SELECT p.oid::regprocedure AS routine
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle')
          AND p.proowner <> 'sentinel_owner'::regrole
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid
                            AND d.deptype = 'e')
    LOOP
        EXECUTE format('ALTER ROUTINE %s OWNER TO sentinel_owner', r.routine);
    END LOOP;

    FOR r IN
        SELECT n.nspname FROM pg_catalog.pg_namespace n
        WHERE n.nspname IN ('worker', 'ops', 'lifecycle') AND n.nspowner <> 'sentinel_owner'::regrole
    LOOP
        EXECUTE format('ALTER SCHEMA %I OWNER TO sentinel_owner', r.nspname);
    END LOOP;
END
$transfer$;
SQL
echo "provision: database roles and ownership ready"

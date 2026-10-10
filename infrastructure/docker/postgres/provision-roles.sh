#!/bin/sh
# SentinelPipe PostgreSQL login roles. Runs INSIDE the database container as the
# database owner (POSTGRES_USER), through the local socket.
#
# Creates (if missing) the NOLOGIN group roles that Flyway V005 grants privileges to, and
# creates or updates the login roles that are members of them:
#
#   worker    SENTINEL_WORKER_DB_USERNAME / _PASSWORD    -> member of sentinel_worker
#             (EXECUTE worker.record_receipt only; no table privileges)
#   operator  SENTINEL_OPERATOR_DB_USERNAME / _PASSWORD  -> member of sentinel_operator
#             (EXECUTE ops.* recovery functions only; optional)
#
# Passwords are read with psql's \getenv, so they never appear in process arguments.
# Idempotent; safe to run before or after migrations.
set -eu

: "${SENTINEL_WORKER_DB_PASSWORD:?SENTINEL_WORKER_DB_PASSWORD must be set}"
export SENTINEL_WORKER_DB_USERNAME="${SENTINEL_WORKER_DB_USERNAME:-sentinel_worker_app}"
export SENTINEL_OPERATOR_DB_USERNAME="${SENTINEL_OPERATOR_DB_USERNAME:-sentinel_operator_app}"
export SENTINEL_OPERATOR_DB_PASSWORD="${SENTINEL_OPERATOR_DB_PASSWORD:-}"

psql -v ON_ERROR_STOP=1 --quiet --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv worker_user SENTINEL_WORKER_DB_USERNAME
\getenv worker_password SENTINEL_WORKER_DB_PASSWORD
\getenv operator_user SENTINEL_OPERATOR_DB_USERNAME
\getenv operator_password SENTINEL_OPERATOR_DB_PASSWORD

SELECT 'CREATE ROLE sentinel_worker NOLOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker') \gexec
SELECT 'CREATE ROLE sentinel_operator NOLOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_operator') \gexec

SELECT format('CREATE ROLE %I LOGIN', :'worker_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'worker_user') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
              'NOBYPASSRLS INHERIT CONNECTION LIMIT 20', :'worker_user', :'worker_password') \gexec
SELECT format('GRANT sentinel_worker TO %I', :'worker_user') \gexec

SELECT format('CREATE ROLE %I LOGIN', :'operator_user')
WHERE :'operator_password' <> ''
  AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'operator_user') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
              'NOBYPASSRLS INHERIT CONNECTION LIMIT 5', :'operator_user', :'operator_password')
WHERE :'operator_password' <> '' \gexec
SELECT format('GRANT sentinel_operator TO %I', :'operator_user')
WHERE :'operator_password' <> '' \gexec
SQL
echo "provision: database login roles ready"

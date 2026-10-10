#!/bin/sh
# Verifies the PostgreSQL roles created by infrastructure/docker/postgres/provision-roles.sh in
# the running Compose stack: group roles cannot log in, no SentinelPipe role holds cluster
# privileges, the migrator may only SET ROLE sentinel_owner (inheriting nothing), and the
# runtime logins cannot create objects. Schema-level grants are covered by the Java
# DatabasePrivilegeIntegrationTests, which run the migrations.
#
# Usage: sh scripts/ci/verify-database-roles.sh [env-file]
set -eu

ENV_FILE="${1:-.env}"
set -a
# shellcheck disable=SC1090
. "./$ENV_FILE"
set +a
failures=0

admin_query() {
    docker compose --env-file "$ENV_FILE" exec -T postgres \
        psql --no-psqlrc -At -v ON_ERROR_STOP=1 -U "$SENTINEL_DB_ADMIN_USERNAME" -d "$SENTINEL_DB_NAME" -c "$1"
}

# Runs SQL as a login over TCP inside the container; the password is passed as an environment variable.
as_login() {
    docker compose --env-file "$ENV_FILE" exec -T -e PGPASSWORD="$2" postgres \
        psql --no-psqlrc -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$1" -d "$SENTINEL_DB_NAME" -c "$3"
}

expect() {
    if [ "$2" = "$3" ]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected [$3], got [$2]" >&2
        failures=$((failures + 1))
    fi
}

expect_denied() {
    if as_login "$2" "$3" "$4" >/dev/null 2>&1; then
        echo "FAIL: $1 was allowed" >&2
        failures=$((failures + 1))
    else
        echo "ok: $1 denied"
    fi
}

expect "group roles cannot log in" \
    "$(admin_query "SELECT count(*) FROM pg_roles WHERE rolname IN ('sentinel_owner','sentinel_api','sentinel_worker','sentinel_operator') AND NOT rolcanlogin")" \
    "4"
expect "no SentinelPipe role holds cluster privileges" \
    "$(admin_query "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'sentinel\_%' AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)")" \
    "0"
expect "migrator membership (inherit, set, admin)" \
    "$(admin_query "SELECT inherit_option || ',' || set_option || ',' || admin_option FROM pg_auth_members WHERE roleid = 'sentinel_owner'::regrole AND member = '$SENTINEL_DB_MIGRATION_USERNAME'::regrole")" \
    "false,true,false"
expect "only the migrator may become the owner" \
    "$(admin_query "SELECT string_agg(member::regrole::text, ',') FROM pg_auth_members WHERE roleid = 'sentinel_owner'::regrole")" \
    "$SENTINEL_DB_MIGRATION_USERNAME"
expect "PUBLIC cannot connect" \
    "$(admin_query "SELECT has_database_privilege('public', current_database(), 'CONNECT')")" \
    "f"

expect "API login connects" "$(as_login "$SENTINEL_DB_USERNAME" "$SENTINEL_DB_PASSWORD" "SELECT 1")" "1"
expect_denied "API login CREATE" "$SENTINEL_DB_USERNAME" "$SENTINEL_DB_PASSWORD" "CREATE TABLE probe (id int)"
expect_denied "API login SET ROLE sentinel_owner" "$SENTINEL_DB_USERNAME" "$SENTINEL_DB_PASSWORD" "SET ROLE sentinel_owner"
expect_denied "worker login CREATE" "$SENTINEL_WORKER_DB_USERNAME" "$SENTINEL_WORKER_DB_PASSWORD" "CREATE TABLE probe (id int)"
expect_denied "migrator login CREATE without SET ROLE" "$SENTINEL_DB_MIGRATION_USERNAME" "$SENTINEL_DB_MIGRATION_PASSWORD" \
    "CREATE TABLE probe (id int)"

if [ "$failures" -ne 0 ]; then
    echo "$failures database role check(s) failed" >&2
    exit 1
fi
echo "database roles verified"

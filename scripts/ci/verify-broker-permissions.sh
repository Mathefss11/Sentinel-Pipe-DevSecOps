#!/bin/sh
# Verifies the RabbitMQ permissions created by infrastructure/docker/rabbitmq/provision.sh in
# the running Compose stack: exact configure/write/read patterns and no user tags (no
# management access) for every runtime identity.
#
# Usage: sh scripts/ci/verify-broker-permissions.sh [env-file]
set -eu

ENV_FILE="${1:-.env}"
failures=0

rabbitmqctl() {
    docker compose --env-file "$ENV_FILE" exec -T rabbitmq rabbitmqctl --quiet "$@"
}

expect_permissions() {
    user="$1"
    expected="$(printf '/\t%s\t%s\t%s' "$2" "$3" "$4")"
    actual="$(rabbitmqctl list_user_permissions --no-table-headers "$user" | tr -d '\r')"
    if [ "$actual" = "$expected" ]; then
        echo "ok: $user permissions"
    else
        echo "FAIL: $user permissions: expected [$expected], got [$actual]" >&2
        failures=$((failures + 1))
    fi
}

expect_permissions sentinel-publisher '^$' '^sentinel\.scan-requests$' '^$'
expect_permissions sentinel-worker '^$' '^sentinel\.scan-requests\.(dlx|retry)$' '^sentinel\.scan-requests\.worker$'
expect_permissions sentinel-operator '^$' '^sentinel\.scan-requests$' '^sentinel\.scan-requests\.dead-letter$'

tags="$(rabbitmqctl list_users --no-table-headers | tr -d '\r' | grep -E '^sentinel-(publisher|worker|operator)\b' || true)"
if echo "$tags" | grep -v -E '\[\]$' | grep -q .; then
    echo "FAIL: runtime users must have no tags: $tags" >&2
    failures=$((failures + 1))
else
    echo "ok: runtime users have no management tags"
fi

policy="$(rabbitmqctl list_queues --no-table-headers name policy | tr -d '\r' | grep '^sentinel.scan-requests.dead-letter' || true)"
case "$policy" in
    *sentinel-dead-letter-retention*) echo "ok: dead-letter retention policy applied" ;;
    *) echo "FAIL: dead-letter retention policy missing: [$policy]" >&2; failures=$((failures + 1)) ;;
esac

[ "$failures" -eq 0 ]

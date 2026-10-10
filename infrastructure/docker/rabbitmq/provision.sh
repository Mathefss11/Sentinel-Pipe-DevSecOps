#!/bin/sh
# SentinelPipe RabbitMQ provisioning. Runs INSIDE the broker container with rabbitmqctl
# (administrative access through the node's Erlang cookie; no AMQP credentials needed).
#
#   1. Imports the topology (exchanges, queues, bindings, policies) from definitions.json,
#      which is generated from packages/contracts/messaging/topology.v1.json and contains
#      no users or secrets. Import is additive and idempotent.
#   2. Creates or updates the least-privileged runtime users. Passwords come from the
#      environment only; none of the runtime users has the configure permission or any
#      management tag, so none can declare, delete or alter topology.
#
# Users (passwords required unless noted):
#   publisher  SENTINEL_RABBITMQ_PUBLISHER_USERNAME / _PASSWORD  (sentinel-api)
#              write sentinel.scan-requests only
#   worker     SENTINEL_WORKER_RABBITMQ_USERNAME / _PASSWORD     (sentinel-worker)
#              read sentinel.scan-requests.worker; write the dlx and retry exchanges
#   operator   SENTINEL_OPERATOR_RABBITMQ_USERNAME / _PASSWORD   (recovery tools; optional)
#              read sentinel.scan-requests.dead-letter; write sentinel.scan-requests
#
# rabbitmqctl takes passwords as arguments, so they are briefly visible to processes in
# the broker container. Passwords must not start with "-" (parsed as an option).
set -eu

DEFINITIONS="${SENTINEL_RABBITMQ_DEFINITIONS:-/etc/sentinelpipe/rabbitmq/definitions.json}"
VHOST="${SENTINEL_RABBITMQ_VHOST:-/}"

fail() {
    echo "provision: $*" >&2
    exit 1
}

ensure_user() {
    name="$1"
    password="$2"
    configure="$3"
    write="$4"
    read="$5"
    case "$name" in
        "" | -*) fail "invalid user name" ;;
    esac
    case "$password" in
        "") fail "password for $name is empty" ;;
        -*) fail "password for $name must not start with '-'" ;;
    esac
    if rabbitmqctl --quiet list_users --no-table-headers | cut -f1 | grep -qxF "$name"; then
        rabbitmqctl --quiet change_password "$name" "$password" >/dev/null
    else
        rabbitmqctl --quiet add_user "$name" "$password" >/dev/null
    fi
    # No tags: no management UI or HTTP API access.
    rabbitmqctl --quiet set_user_tags "$name" >/dev/null
    rabbitmqctl --quiet set_permissions -p "$VHOST" "$name" "$configure" "$write" "$read" >/dev/null
    echo "provision: user $name ready"
}

[ -r "$DEFINITIONS" ] || fail "definitions file not readable: $DEFINITIONS"
rabbitmqctl --quiet import_definitions "$DEFINITIONS" >/dev/null
echo "provision: topology imported"

ensure_user "${SENTINEL_RABBITMQ_PUBLISHER_USERNAME:-sentinel-publisher}" \
    "${SENTINEL_RABBITMQ_PUBLISHER_PASSWORD:?SENTINEL_RABBITMQ_PUBLISHER_PASSWORD must be set}" \
    '^$' '^sentinel\.scan-requests$' '^$'

ensure_user "${SENTINEL_WORKER_RABBITMQ_USERNAME:-sentinel-worker}" \
    "${SENTINEL_WORKER_RABBITMQ_PASSWORD:?SENTINEL_WORKER_RABBITMQ_PASSWORD must be set}" \
    '^$' '^sentinel\.scan-requests\.(dlx|retry)$' '^sentinel\.scan-requests\.worker$'

if [ -n "${SENTINEL_OPERATOR_RABBITMQ_PASSWORD:-}" ]; then
    ensure_user "${SENTINEL_OPERATOR_RABBITMQ_USERNAME:-sentinel-operator}" \
        "$SENTINEL_OPERATOR_RABBITMQ_PASSWORD" \
        '^$' '^sentinel\.scan-requests$' '^sentinel\.scan-requests\.dead-letter$'
else
    echo "provision: operator user skipped (SENTINEL_OPERATOR_RABBITMQ_PASSWORD not set)"
fi

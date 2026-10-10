#!/bin/sh
# Provisions the least-privileged runtime identities in the local Compose stack:
#   RabbitMQ  topology (definitions.json) + publisher, worker and operator users
#   PostgreSQL worker and operator login roles
#
# Usage (repository root, stack running):  sh scripts/dev/provision.sh [env-file]
# Values come from the environment, or from the env file (default .env). Secrets are
# passed to the containers as environment variables (docker compose exec -e NAME), never
# as command-line arguments on the host. Idempotent; re-run after changing a password.
set -eu

ENV_FILE="${1:-.env}"
if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "./$ENV_FILE"
    set +a
fi

docker compose --env-file "$ENV_FILE" exec -T \
    -e SENTINEL_RABBITMQ_PUBLISHER_USERNAME -e SENTINEL_RABBITMQ_PUBLISHER_PASSWORD \
    -e SENTINEL_WORKER_RABBITMQ_USERNAME -e SENTINEL_WORKER_RABBITMQ_PASSWORD \
    -e SENTINEL_OPERATOR_RABBITMQ_USERNAME -e SENTINEL_OPERATOR_RABBITMQ_PASSWORD \
    rabbitmq sh /etc/sentinelpipe/rabbitmq/provision.sh

docker compose --env-file "$ENV_FILE" exec -T \
    -e SENTINEL_WORKER_DB_USERNAME -e SENTINEL_WORKER_DB_PASSWORD \
    -e SENTINEL_OPERATOR_DB_USERNAME -e SENTINEL_OPERATOR_DB_PASSWORD \
    postgres sh /etc/sentinelpipe/postgres/provision-roles.sh

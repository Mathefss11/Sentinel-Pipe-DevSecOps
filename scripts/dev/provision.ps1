<#
.SYNOPSIS
    Provisions the least-privileged runtime identities in the local Compose stack.

.DESCRIPTION
    RabbitMQ:   topology (definitions.json) and the publisher, worker and operator users.
    PostgreSQL: group roles, ownership transfer (upgrade path) and the migrator, API,
                worker and operator login roles.

    Values come from the current environment, or from the env file (default .env) for
    variables that are not already set. Secrets are passed to the containers as
    environment variables (docker compose exec -e NAME), never as command-line arguments
    on the host. Idempotent; re-run after changing a password.

.EXAMPLE
    docker compose up --detach --wait
    .\scripts\dev\provision.ps1
#>
param([string]$EnvFile = ".env")

$ErrorActionPreference = "Stop"

$names = @(
    "SENTINEL_RABBITMQ_PUBLISHER_USERNAME", "SENTINEL_RABBITMQ_PUBLISHER_PASSWORD",
    "SENTINEL_WORKER_RABBITMQ_USERNAME", "SENTINEL_WORKER_RABBITMQ_PASSWORD",
    "SENTINEL_OPERATOR_RABBITMQ_USERNAME", "SENTINEL_OPERATOR_RABBITMQ_PASSWORD",
    "SENTINEL_DB_MIGRATION_USERNAME", "SENTINEL_DB_MIGRATION_PASSWORD",
    "SENTINEL_DB_USERNAME", "SENTINEL_DB_PASSWORD",
    "SENTINEL_WORKER_DB_USERNAME", "SENTINEL_WORKER_DB_PASSWORD",
    "SENTINEL_OPERATOR_DB_USERNAME", "SENTINEL_OPERATOR_DB_PASSWORD"
)

if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*([A-Z0-9_]+)=(.*)$' -and $names -contains $Matches[1]) {
            if (-not [Environment]::GetEnvironmentVariable($Matches[1], "Process")) {
                # Process scope only: inherited by docker compose, gone when the shell exits.
                [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
            }
        }
    }
}

$rabbit = @("compose", "--env-file", $EnvFile, "exec", "-T")
foreach ($name in $names | Where-Object { $_ -like "*RABBITMQ*" }) { $rabbit += @("-e", $name) }
$rabbit += @("rabbitmq", "sh", "/etc/sentinelpipe/rabbitmq/provision.sh")
& docker @rabbit
if ($LASTEXITCODE -ne 0) { throw "RabbitMQ provisioning failed (exit $LASTEXITCODE)" }

$postgres = @("compose", "--env-file", $EnvFile, "exec", "-T")
foreach ($name in $names | Where-Object { $_ -like "SENTINEL_*DB_*" }) { $postgres += @("-e", $name) }
$postgres += @("postgres", "sh", "/etc/sentinelpipe/postgres/provision-roles.sh")
& docker @postgres
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL role provisioning failed (exit $LASTEXITCODE)" }

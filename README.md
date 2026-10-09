# SentinelPipe

SentinelPipe is an open-source, security-first DevSecOps platform. It is designed to analyze
software repositories, consolidate vulnerability findings from multiple scanners, evaluate them
against versioned security policies, and publish actionable remediation reports to GitHub.

It is also a cybersecurity engineering portfolio project. The emphasis is on secure design,
verifiable behavior, and honest reporting of coverage and limitations.

> **Status: Milestone 1 (Foundation).** This repository currently contains the platform
> skeleton only: the control-plane API, the worker package, local infrastructure, and CI.
> Scanning, policy evaluation, and GitHub integration are **not implemented yet**; see
> [Roadmap](#roadmap).

## Architecture overview

SentinelPipe is a **modular monolith plus separate workers**, not a set of microservices.

```text
                 ┌────────────────────────────────────────────┐
                 │  Control plane: sentinel-api (Java 21,     │
                 │  Spring Boot 4)                            │
                 │  organizations, projects, scan lifecycle,  │
                 │  policies, evaluations, audit, reporting   │
                 └───────┬───────────────┬───────────────┬────┘
                         │ JDBC/Flyway   │ AMQP          │ HTTP (decisions)
                 ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
                 │ PostgreSQL 18│ │ RabbitMQ 4  │ │ OPA (Rego)  │
                 └──────────────┘ └──────▲──────┘ └─────────────┘
                                         │ commands / events (later milestones)
                 ┌───────────────────────┴────────────────────┐
                 │  Execution plane: sentinel-worker (Python)  │
                 │  discovery, scanner adapters, normalization │
                 │  (runs in isolated, restricted contexts)    │
                 └────────────────────────────────────────────┘
```

| Component | Technology | Responsibility |
|---|---|---|
| `services/sentinel-api` | Java 21, Spring Boot 4.1, Maven Wrapper | Control plane: tenancy, authorization, scan lifecycle, policies, audit, reporting coordination |
| `services/sentinel-worker` | Python 3.12+, Pytest, Ruff | Execution/processing plane: repository discovery, scanner adapters, normalization |
| PostgreSQL 18 | Flyway migrations | System of record. Hibernate only *validates* the schema. |
| RabbitMQ 4 | Spring AMQP | Asynchronous commands and events |
| Open Policy Agent | Rego | Deterministic policy decisions |

Key design principles: least privilege, untrusted repository content, separation between
scanning and privileged publication, fail-closed security decisions (`PASS` / `FAIL` /
`INCOMPLETE`), and auditable, reproducible policy evaluation. See [`SECURITY.md`](SECURITY.md).

## Repository layout

```text
.
├── .github/workflows/ci.yml        # CI: Java build/tests, Python lint/tests, infra validation
├── compose.yaml                    # Local PostgreSQL, RabbitMQ and OPA (loopback only)
├── .env.example                    # Development-only placeholder configuration
├── infrastructure/docker/opa/      # OPA server authorization policy and its tests
├── services/
│   ├── sentinel-api/               # Spring Boot control plane (Maven Wrapper)
│   └── sentinel-worker/            # Python worker package
├── CLAUDE.md                       # Engineering guidelines for AI-assisted development
├── SECURITY.md
└── README.md
```

## Prerequisites

| Tool | Version used for validation |
|---|---|
| JDK | 21 (Temurin/Oracle). Builds also verified on JDK 25. Maven is provided by the wrapper. |
| Python | 3.12 or newer (validated locally on 3.14; CI runs 3.12 and 3.14) |
| Docker | Docker Engine with Compose v2 (validated with Docker Desktop, Engine 29.7) |
| Git | Any recent version |

Commands below use Windows PowerShell. On Linux/macOS, use `./mvnw` and
`.venv/bin/...` equivalents.

## Local setup

### 1. Configure the environment

```powershell
Copy-Item .env.example .env
```

Replace every `dev-only-change-me` value in `.env` with a locally generated secret. For
example, the following generates a random value:

```powershell
$b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
```

`.env` is git-ignored. Never commit it.

### 2. Start the infrastructure

```powershell
docker compose up --detach --wait
docker compose ps
```

All three services report `healthy` when ready. Host ports are bound to `127.0.0.1` only:

| Service | Host address |
|---|---|
| PostgreSQL | `127.0.0.1:5432` (`SENTINEL_DB_PORT`) |
| RabbitMQ (AMQP) | `127.0.0.1:5672` (`SENTINEL_RABBITMQ_PORT`) |
| RabbitMQ management UI | `http://127.0.0.1:15672` (`SENTINEL_RABBITMQ_MANAGEMENT_PORT`) |
| OPA | `http://127.0.0.1:8181` (`SENTINEL_OPA_PORT`) |

> **Port conflicts:** if a local PostgreSQL installation already listens on 5432, set
> `SENTINEL_DB_PORT` in `.env` to a free port (for example `55432`). The API reads the same
> variable.

Stop the stack with `docker compose down`. Add `--volumes` to also delete the local data
(this is destructive).

### 3. Run the API

Spring Boot does not read `.env` directly. Load it into the current PowerShell session, then
start the application:

```powershell
Get-Content .env | Where-Object { $_ -match '^\s*[A-Z_]+=' } | ForEach-Object {
    $name, $value = $_ -split '=', 2
    Set-Item "env:$($name.Trim())" $value.Trim()
}
Set-Location services\sentinel-api
.\mvnw.cmd spring-boot:run
```

On startup, Flyway applies pending migrations from
`src/main/resources/db/migration`. Check health:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/actuator/health
```

The application deliberately refuses to start if `SENTINEL_DB_PASSWORD` or
`SENTINEL_RABBITMQ_PASSWORD` is missing.

### 4. Set up the worker

```powershell
Set-Location services\sentinel-worker
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\sentinel-worker.exe self-check
```

`self-check` prints a JSON report and exits with `0` when healthy and `1` otherwise. It
validates the Python runtime and the worker configuration (`SENTINEL_WORKER_*` variables).
It does not connect to external services.

## Testing

| Scope | Command (from the component directory) | Requires |
|---|---|---|
| API build, unit and integration tests | `.\mvnw.cmd clean test` (`services/sentinel-api`) | Docker (Testcontainers) |
| Worker lint | `.\.venv\Scripts\ruff.exe check .` | — |
| Worker formatting | `.\.venv\Scripts\ruff.exe format --check .` | — |
| Worker tests | `.\.venv\Scripts\python.exe -m pytest` | — |
| Compose configuration | `docker compose --env-file .env.example config --quiet` (repository root) | Docker |
| OPA authorization policy | `docker run --rm -v "${PWD}\infrastructure\docker\opa:/policies:ro" openpolicyagent/opa:1.21.1 test /policies -v` | Docker |

The API integration tests start their own PostgreSQL and RabbitMQ containers through
Testcontainers, pinned to the same image digests as `compose.yaml`. They do not use the
Compose stack. They verify that:

- the application context starts against real PostgreSQL and RabbitMQ;
- Flyway applies `V001__initial_schema.sql` to a fresh database with no pending migrations;
- Hibernate is configured to `validate` and creates no tables of its own;
- `/actuator/health`, liveness and readiness are `UP` without exposing component details,
  and non-health actuator endpoints are not exposed.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main`, on pull requests, and manually. It has
three jobs:

- **sentinel-api:** `mvnw clean verify` on JDK 21, including the Testcontainers integration tests.
- **sentinel-worker:** Ruff lint, Ruff format check and Pytest on Python 3.12 and 3.14.
- **Infrastructure:** validates `compose.yaml`, checks and tests the OPA authorization policy,
  starts the stack and waits for all health checks, then tears it down.

The workflow uses a read-only `GITHUB_TOKEN` (`contents: read`). It does not persist checkout
credentials and has no deployment or publishing steps. Third-party actions are pinned to full
commit SHAs.

## Milestone 1 checklist

- [x] Monorepo layout with `services/sentinel-api` and `services/sentinel-worker`
- [x] Spring Boot API (`dev.sentinelpipe.api`) builds with the Maven Wrapper on JDK 21
- [x] Health endpoint (`/actuator/health`, liveness, readiness) with minimal exposure
- [x] Docker Compose: PostgreSQL 18, RabbitMQ 4 and OPA, digest-pinned, loopback-only, with health checks
- [x] OPA management APIs denied by an authorization policy, with policy tests
- [x] Flyway baseline migration `V001__initial_schema.sql`, with Hibernate in `validate` mode
- [x] Integration tests with Testcontainers (context, migration, health)
- [x] Python worker package with configuration, self-check, Ruff and Pytest
- [x] GitHub Actions CI with least-privilege token and pinned actions
- [x] `.gitignore`, `.env.example`, `README.md`, `SECURITY.md`
- [ ] First CI run on GitHub (pending the initial push)

## Roadmap

| Milestone | Scope |
|---|---|
| **M1 — Foundation** | Current milestone (see checklist) |
| M2 — Domain & Contracts | JSON Schemas, entities, migrations, APIs, idempotency, outbox, authorization groundwork |
| M3 — Scanners | Discovery, Semgrep/Gitleaks/Trivy adapters, normalized findings, correlation |
| M4 — Security Gate & Remediation | OPA policies, coverage, exceptions, decisions, remediation reports |
| M5 — GitHub Integration | GitHub App, webhooks, OIDC, Checks, SARIF, PR comments, artifacts |
| M6 — Advanced Security | Checkov, Syft/SBOM, ZAP, attestation, isolated staging |
| M7 — Hardening & Observability | Audit, timeouts, retries/DLQ, monitoring, adversarial tests |
| M8 — Portfolio Release | Reproducible demos, C4 diagrams, ADRs, threat model |

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting process and the current
security baseline. Please do not report vulnerabilities through public issues.

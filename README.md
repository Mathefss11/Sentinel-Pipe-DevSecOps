# SentinelPipe

SentinelPipe is an open-source, security-first DevSecOps platform. It is designed to analyze
software repositories, consolidate vulnerability findings from multiple scanners, evaluate them
against versioned security policies, and publish actionable remediation reports to GitHub.

It is also a cybersecurity engineering portfolio project. The emphasis is on secure design,
verifiable behavior, and honest reporting of coverage and limitations.

> **Status: Milestone 2, Phase 1 (Domain model & REST contracts).** The control plane can
> register organizations and GitHub-hosted projects, accept scan requests for specific
> commits, and track scan and scanner-job lifecycles in PostgreSQL. **Authentication,
> tenant authorization, scanning, policy evaluation and GitHub integration are not
> implemented yet.** The domain API is therefore disabled by default and is meant for
> local, loopback-only development (see [Security limitations](#current-security-limitations)).

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

## Domain model

```text
Organization 1 ──── * Project 1 ──── * Scan 1 ──── * ScanJob
 (tenant)        (GitHub repo)    (one commit)   (one scanner run)
```

| Entity | Key rules |
|---|---|
| `Organization` | Unique, immutable `slug` (`^[a-z0-9]+(-[a-z0-9]+)*$`, ≤ 63). Display names are trimmed and may not contain control characters. |
| `Project` | Belongs to exactly one organization. Identified by provider (`GITHUB`), owner and repository name, normalized to lowercase. URLs are never accepted. A repository can be registered once per organization. Nothing is cloned or executed. |
| `Scan` | Requested for a **full** commit SHA (40 or 64 hex characters) and a branch. `executionStatus` and `securityDecision` are independent dimensions. |
| `ScanJob` | One scanner execution per scanner type per scan, with a bounded attempt count (max. 3). No scanner is executed yet. |

**Scan lifecycle** (enforced in the entity and by database CHECK constraints):

```text
QUEUED ──▶ RUNNING ──▶ COMPLETED   (decision: PASS | FAIL | INCOMPLETE)
  │           │
  ├───────────┴──────▶ FAILED      (decision: always INCOMPLETE)
  └───────────┴──────▶ CANCELLED   (decision: always INCOMPLETE)
```

- The decision is `PENDING` while the scan is `QUEUED` or `RUNNING`.
- Terminal scans cannot change.
- Completing execution never implies `PASS`. `PASS` is rejected unless the scan has at
  least one job and every job `COMPLETED` (fail closed).
- Transitions are performed only by the internal `ScanLifecycleService`. **There is no
  public endpoint that changes scan or job state.** Trusted internal components will drive
  transitions in later phases.

> CLAUDE.md also lists `PLANNING` and `EVALUATING` stages. This phase implements the
> reduced status set requested for M2 Phase 1. Adding those stages later needs a new
> migration that extends the CHECK constraints.

## Repository layout

```text
.
├── .github/workflows/ci.yml        # CI: Java build/tests, Python lint/tests, infra validation
├── compose.yaml                    # Local PostgreSQL, RabbitMQ and OPA (loopback only)
├── .env.example                    # Development-only placeholder configuration
├── infrastructure/docker/opa/      # OPA server authorization policy and its tests
├── packages/contracts/             # OpenAPI 3.1 and JSON Schema 2020-12 contracts
├── docs/adr/                       # Architecture decision records
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

With the default configuration, only the health endpoints exist. To use the domain API
locally, start the application with the `local` profile. It binds the server to
`127.0.0.1` and enables `/api/v1`:

```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"
```

Startup fails on purpose if the domain API is enabled while `server.address` is not a
literal loopback IP, or if a `prod`/`production` profile is active
([ADR-0002](docs/adr/0002-domain-api-exposure-before-authentication.md)).

### 4. Use the domain API (local profile)

```powershell
$api = 'http://127.0.0.1:8080/api/v1'

$org = Invoke-RestMethod -Method Post "$api/organizations" -ContentType 'application/json' `
    -Body '{"name": "Acme Security", "slug": "acme-security"}'

$project = Invoke-RestMethod -Method Post "$api/organizations/$($org.id)/projects" `
    -ContentType 'application/json' `
    -Body '{"name": "Payments", "repositoryProvider": "GITHUB", "repositoryOwner": "acme-corp",
            "repositoryName": "payments-service", "defaultBranch": "main"}'

# 202 Accepted. Retrying with the same Idempotency-Key returns the same scan.
$scan = Invoke-RestMethod -Method Post "$api/projects/$($project.id)/scans" `
    -ContentType 'application/json' -Headers @{ 'Idempotency-Key' = 'manual-run-1' } `
    -Body '{"commitSha": "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e", "branch": "main",
            "triggerType": "MANUAL"}'

Invoke-RestMethod "$api/scans/$($scan.id)"
Invoke-RestMethod "$api/projects/$($project.id)/scans?page=0&size=20"
```

| Method | Path | Success |
|---|---|---|
| `POST` | `/api/v1/organizations` | `201` + `Location` |
| `GET` | `/api/v1/organizations/{organizationId}` | `200` |
| `POST` | `/api/v1/organizations/{organizationId}/projects` | `201` + `Location` |
| `GET` | `/api/v1/organizations/{organizationId}/projects?page&size` | `200` (oldest first) |
| `GET` | `/api/v1/projects/{projectId}` | `200` |
| `POST` | `/api/v1/projects/{projectId}/scans` | `202` + `Location`, optional `Idempotency-Key` |
| `GET` | `/api/v1/projects/{projectId}/scans?page&size` | `200` (newest first) |
| `GET` | `/api/v1/scans/{scanId}` | `200` (includes jobs) |

Errors are RFC 9457 Problem Details (`application/problem+json`): `400` validation, malformed
JSON or unknown property; `404` not found; `409` conflict, with a machine-readable `code`;
`415` non-JSON body; `422` an `Idempotency-Key` reused for a different request. Error
responses never contain stack traces, exception names or rejected input values. Pagination
is zero-based, with `size` ≤ 100.

The full contract is in [`packages/contracts`](packages/contracts/README.md).

**Idempotency.** Keys are scoped per project and enforced by the database unique
constraint `uq_scans_project_idempotency_key`, together with a SHA-256 fingerprint of the
normalized request. Concurrent retries create at most one scan. In-memory locks are not
relied on. Keys do not expire yet.

### 5. Set up the worker

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
| API build, unit, integration and contract tests | `.\mvnw.cmd clean verify` (`services/sentinel-api`, JDK 21) | Docker (Testcontainers) |
| Worker lint | `.\.venv\Scripts\ruff.exe check .` | — |
| Worker formatting | `.\.venv\Scripts\ruff.exe format --check .` | — |
| Worker tests | `.\.venv\Scripts\python.exe -m pytest` | — |
| Compose configuration | `docker compose --env-file .env.example config --quiet` (repository root) | Docker |
| OPA authorization policy | `docker run --rm -v "${PWD}\infrastructure\docker\opa:/policies:ro" openpolicyagent/opa:1.21.1 test /policies -v` | Docker |

The API integration tests start their own PostgreSQL and RabbitMQ containers through
Testcontainers, pinned to the same image digests as `compose.yaml`. They do not use the
Compose stack. Two application contexts are used: the default configuration and one
with the domain API enabled on loopback. The tests verify that:

- the application context starts against real PostgreSQL and RabbitMQ;
- Flyway applies `V001` and `V002` to a fresh database with valid checksums and no
  pending migrations. Hibernate only validates the schema and creates no tables;
- `/actuator/health`, liveness and readiness are `UP` without exposing component details;
- with the default configuration, no `/api/**` route exists. The exposure guard rejects
  non-loopback bindings and production profiles;
- organizations, projects and scans follow their validation, uniqueness, normalization,
  pagination and Problem Details rules;
- scan and job state machines reject invalid and terminal-state transitions, and `PASS`
  is rejected without completed jobs;
- PostgreSQL CHECK, UNIQUE and FOREIGN KEY constraints reject inconsistent rows written
  directly with SQL;
- idempotent scan creation is safe under concurrent retries and conflicting reuse;
- real API responses and all OpenAPI examples validate against the JSON Schemas, and the
  OpenAPI operations exactly match the registered endpoints.

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

Container images are pre-pulled with bounded retries (`scripts/ci/pull-images.sh`), because
Docker Hub rate-limits anonymous pulls and GitHub-hosted runners share IP addresses.
No credentials are required: by default, CI pulls images anonymously.

Authenticated pulls are an optional opt-in that raises the rate limit. To enable them, create
a Docker Hub personal access token with **Public Repo Read-only** scope. Add your Docker Hub
username as the repository variable `DOCKERHUB_USERNAME` and the token as the repository secret
`DOCKERHUB_TOKEN`. The workflow logs out of Docker Hub before any build or test code runs.

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
- [x] First CI run on GitHub

## Milestone 2, Phase 1 checklist

- [x] Domain entities `Organization`, `Project`, `Scan`, `ScanJob` with enforced invariants
- [x] Flyway migration `V002__core_domain.sql` (FKs, unique/check constraints, indexes)
- [x] Versioned REST API under `/api/v1` with pagination and RFC 9457 errors
- [x] Database-backed idempotent scan creation (`Idempotency-Key`)
- [x] OpenAPI 3.1 and JSON Schema 2020-12 contracts, with automated contract tests
- [x] Domain API disabled by default; loopback-only `local` profile with a fail-fast guard
- [x] ADR-0001 (modular monolith) and ADR-0002 (API exposure before authentication)
- [ ] Authentication and organization-scoped authorization (next phase)
- [ ] Transactional outbox and event publication (next phase)

## Architecture decisions

- [ADR-0001: Modular monolith control plane](docs/adr/0001-modular-monolith-control-plane.md)
- [ADR-0002: Domain API disabled until authentication exists](docs/adr/0002-domain-api-exposure-before-authentication.md)

## Current security limitations

- **No authentication or tenant authorization.** Any caller that can reach the API can
  read and write every organization's data. This is why the domain API is disabled by
  default and restricted to loopback in the `local` profile. Loopback binding is not
  access control: other local processes can still reach it. Production-grade identity
  and organization-scoped authorization are required before any external deployment.
- `triggerType` and `branch` are supplied by the caller and not yet verified against
  GitHub events or Actions OIDC claims.
- Idempotency keys do not expire, and there is no rate limiting.
- No scanner runs, so no real security decision is produced yet. `PASS`/`FAIL` can only
  be set by internal code paths, which are exercised by tests.

## Roadmap

| Milestone | Scope |
|---|---|
| M1 — Foundation | Complete |
| **M2 — Domain & Contracts** | Phase 1 complete (see checklist); remaining: authorization groundwork, outbox |
| M3 — Scanners | Discovery, Semgrep/Gitleaks/Trivy adapters, normalized findings, correlation |
| M4 — Security Gate & Remediation | OPA policies, coverage, exceptions, decisions, remediation reports |
| M5 — GitHub Integration | GitHub App, webhooks, OIDC, Checks, SARIF, PR comments, artifacts |
| M6 — Advanced Security | Checkov, Syft/SBOM, ZAP, attestation, isolated staging |
| M7 — Hardening & Observability | Audit, timeouts, retries/DLQ, monitoring, adversarial tests |
| M8 — Portfolio Release | Reproducible demos, C4 diagrams, ADRs, threat model |

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting process and the current
security baseline. Please do not report vulnerabilities through public issues.

# SentinelPipe

SentinelPipe is an open-source, security-first DevSecOps platform. It is designed to analyze
software repositories, consolidate vulnerability findings from multiple scanners, evaluate them
against versioned security policies, and publish actionable remediation reports to GitHub.

It is also a cybersecurity engineering portfolio project. The emphasis is on secure design,
verifiable behavior, and honest reporting of coverage and limitations.

> **Status: Milestone 2, Phase 2C (Distributed reliability, hardening & observability).**
> The control plane registers organizations and GitHub-hosted projects, accepts
> authenticated and authorized scan requests for specific commits, and delivers them
> reliably to any number of Python workers through a transactional outbox and RabbitMQ.
> Workers share one PostgreSQL receipt store that accepts a message only if it matches
> the committed outbox event and its tenant relationships. All runtime identities are
> least-privileged. **No scanner is executed yet**, and policy
> evaluation and GitHub integration are not implemented. The domain API is still
> restricted to loopback, development-stage use (see
> [Security limitations](#current-security-limitations)).

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
UserIdentity 1 ──── * OrganizationMembership * ──── 1 Organization
 (iss + sub)          (OWNER|ADMIN|MEMBER|VIEWER)       (tenant)
                                                             1
                                                             │
Organization 1 ──── * Project 1 ──── * Scan 1 ──── * ScanJob
 (tenant)        (GitHub repo)    (one commit)   (one scanner run)
```

| Entity | Key rules |
|---|---|
| `UserIdentity` | An external OIDC user, identified only by token issuer and subject. No passwords or profile data. Created when a membership is granted, not on login. |
| `OrganizationMembership` | One role per user per organization; the server-side source of truth for authorization. Records who granted it. |
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
├── packages/contracts/             # OpenAPI 3.1, JSON Schemas, message contracts, broker topology
├── docs/adr/                       # Architecture decision records
├── docs/architecture/              # Architecture notes (asynchronous messaging)
├── docs/runbooks/                  # Operational runbooks (outbox, dead letters)
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

The API publishes with the least-privileged `sentinel-publisher` broker user and does not
declare the broker topology. Provision the topology and all runtime identities once,
right after the stack is up and **before** starting the API or a worker (otherwise the
API's publishes fail until the topology exists). The scripts work before or after the
Flyway migrations:

```powershell
.\scripts\dev\provision.ps1        # see docs/runbooks/messaging.md, section 2
```

With the default configuration, only the health endpoints are reachable; every other
request is denied. To use the domain API locally, configure an identity provider (below)
and start the application with the `local` profile. It binds the server to `127.0.0.1`
and enables `/api/v1`:

```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"
```

Startup fails on purpose if the domain API is enabled while the identity settings are
incomplete, `server.address` is not a literal loopback IP, or a `prod`/`production`
profile is active ([ADR-0002](docs/adr/0002-domain-api-exposure-before-authentication.md),
[ADR-0003](docs/adr/0003-identity-and-tenant-authorization.md)).

### 4. Identity provider setup

SentinelPipe does not store passwords or run a login flow. Users authenticate with an
external OpenID Connect provider (for example Keycloak, Microsoft Entra ID, Auth0 or
Okta), and the API validates the provider's **access tokens**. Configure (environment
variables or `.env` loaded into the shell):

| Variable | Value |
|---|---|
| `SENTINEL_SECURITY_JWT_ISSUER` | Exact `iss` of the access tokens (from the provider's discovery document) |
| `SENTINEL_SECURITY_JWT_AUDIENCE` | Audience the provider puts in `aud` for this API |
| `SENTINEL_SECURITY_JWT_JWK_SET_URI` | The provider's `jwks_uri` (HTTPS; plain HTTP only for a loopback provider) |
| `SENTINEL_SECURITY_PLATFORM_ADMIN_SUBJECTS` | Comma-separated `sub` values allowed to create organizations |
| `SENTINEL_SECURITY_JWT_TOKEN_TYPES` | Optional. Default `at+jwt` (RFC 9068). Add `JWT` only for providers that do not emit `at+jwt` |
| `SENTINEL_SECURITY_JWT_JWS_ALGORITHMS` | Optional. Default `RS256`; only asymmetric RS/ES/PS algorithms are accepted |

None of these values is a secret. There is no shared-secret (HMAC) option and no
development bypass: the `local` profile requires real tokens.

**Access-token `typ` compatibility.** By default the API accepts only tokens whose JOSE
header has `typ: at+jwt` (or `application/at+jwt`, case-insensitive), the access-token type
defined by RFC 9068. Tokens with `typ: JWT` or without `typ` are rejected. This prevents
OIDC **ID tokens**, which are not access tokens, from being replayed against the API.

Not every provider emits `at+jwt`. Some issue access tokens with `typ: JWT`, the same value
used for ID tokens, depending on product and configuration. Before deploying, decode the
header of a real access token from your provider (locally; never paste tokens into online
tools) and check its `typ`:

- `at+jwt`: keep the default.
- `JWT`: prefer enabling RFC 9068 access tokens in the provider, if it supports that. Only
  otherwise, set `SENTINEL_SECURITY_JWT_TOKEN_TYPES=JWT`. The header then no longer
  distinguishes ID tokens from access tokens, and the **audience check becomes the only
  barrier**. Configure a dedicated API audience, for example `sentinel-api`, that the
  provider adds to access tokens, and **never use an OAuth client ID as the audience**: ID
  tokens carry the client ID in `aud`.
- No `typ`: not supported. Tokens without `typ` are always rejected.

**Bootstrap procedure for the first organization owner**

1. Configure the provider and the variables above. Find your user's `sub` claim, for
   example by decoding a token you obtained from the provider (do not paste tokens into
   online tools).
2. Set `SENTINEL_SECURITY_PLATFORM_ADMIN_SUBJECTS` to that subject and start the API.
3. As that user, `POST /api/v1/organizations`. The creator becomes the organization's
   first `OWNER` in the same transaction.
4. Grant roles to other users with `POST /api/v1/organizations/{id}/members`
   (`{"subject": "...", "role": "ADMIN"}`).
5. Optionally remove yourself from `SENTINEL_SECURITY_PLATFORM_ADMIN_SUBJECTS` and
   restart. Platform administrators can only create organizations; they have no access
   to existing ones.

Organizations created before M2 Phase 2A have no members and are therefore inaccessible
through the API. Recreate local development data, or insert an `OWNER` membership
manually with SQL as a one-off, reviewed operation.

### 5. Use the domain API (local profile)

```powershell
$api = 'http://127.0.0.1:8080/api/v1'
# An access token from your identity provider (never commit or log it).
$auth = @{ Authorization = "Bearer $env:SENTINEL_ACCESS_TOKEN" }

Invoke-RestMethod "$api/me" -Headers $auth

$org = Invoke-RestMethod -Method Post "$api/organizations" -Headers $auth -ContentType 'application/json' `
    -Body '{"name": "Acme Security", "slug": "acme-security"}'

Invoke-RestMethod -Method Post "$api/organizations/$($org.id)/members" -Headers $auth `
    -ContentType 'application/json' -Body '{"subject": "<user-sub>", "role": "MEMBER"}'

$project = Invoke-RestMethod -Method Post "$api/organizations/$($org.id)/projects" -Headers $auth `
    -ContentType 'application/json' `
    -Body '{"name": "Payments", "repositoryProvider": "GITHUB", "repositoryOwner": "acme-corp",
            "repositoryName": "payments-service", "defaultBranch": "main"}'

# 202 Accepted. Retrying with the same Idempotency-Key returns the same scan.
$scan = Invoke-RestMethod -Method Post "$api/projects/$($project.id)/scans" `
    -ContentType 'application/json' -Headers ($auth + @{ 'Idempotency-Key' = 'manual-run-1' }) `
    -Body '{"commitSha": "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e", "branch": "main",
            "triggerType": "MANUAL"}'

Invoke-RestMethod "$api/scans/$($scan.id)" -Headers $auth
Invoke-RestMethod "$api/projects/$($project.id)/scans?page=0&size=20" -Headers $auth
```

| Method | Path | Success | Minimum role |
|---|---|---|---|
| `GET` | `/api/v1/me` | `200` | any authenticated user |
| `POST` | `/api/v1/organizations` | `201` + `Location` | platform administrator |
| `GET` | `/api/v1/organizations/{organizationId}` | `200` | VIEWER |
| `GET` | `/api/v1/organizations/{organizationId}/members?page&size` | `200` | ADMIN |
| `POST` | `/api/v1/organizations/{organizationId}/members` | `201` + `Location` | ADMIN (MEMBER/VIEWER only), OWNER (any) |
| `GET` | `/api/v1/organizations/{organizationId}/members/{membershipId}` | `200` | ADMIN |
| `PUT` | `/api/v1/organizations/{organizationId}/members/{membershipId}` | `200` | ADMIN (MEMBER/VIEWER only), OWNER (any) |
| `DELETE` | `/api/v1/organizations/{organizationId}/members/{membershipId}` | `204` | ADMIN (MEMBER/VIEWER only), OWNER (any) |
| `POST` | `/api/v1/organizations/{organizationId}/projects` | `201` + `Location` | ADMIN |
| `GET` | `/api/v1/organizations/{organizationId}/projects?page&size` | `200` (oldest first) | VIEWER |
| `GET` | `/api/v1/projects/{projectId}` | `200` | VIEWER |
| `POST` | `/api/v1/projects/{projectId}/scans` | `202` + `Location`, optional `Idempotency-Key` | MEMBER |
| `GET` | `/api/v1/projects/{projectId}/scans?page&size` | `200` (newest first) | VIEWER |
| `GET` | `/api/v1/scans/{scanId}` | `200` (includes jobs) | VIEWER |

**Authorization rules.** Roles are hierarchical (OWNER ⊃ ADMIN ⊃ MEMBER ⊃ VIEWER) and
stored server-side; role, scope or organization claims inside tokens are ignored. A caller
who is not a member of the owning organization receives `404`, exactly as for a resource
that does not exist, so knowing a UUID neither grants access nor confirms existence. A
member whose role is insufficient receives `403` with a `code`. Nobody can grant a role
they cannot manage, and nobody can change or revoke their own membership. An organization
always keeps at least one OWNER.

Errors are RFC 9457 Problem Details (`application/problem+json`): `400` validation, malformed
JSON or unknown property; `401` missing or invalid token (the reason is never disclosed);
`403` insufficient role, with a `code`; `404` not found or not visible; `409` conflict, with a
machine-readable `code`; `415` non-JSON body; `422` an `Idempotency-Key` reused for a
different request. Error responses never contain stack traces, exception names or rejected
input values. Pagination is zero-based, with `size` ≤ 100.

The full contract is in [`packages/contracts`](packages/contracts/README.md).

**Idempotency.** Keys are scoped per project and enforced by the database unique
constraint `uq_scans_project_idempotency_key`, together with a SHA-256 fingerprint of the
normalized request. Concurrent retries create at most one scan. In-memory locks are not
relied on.

Keys are retained for `sentinel.idempotency.retention`, 24 h by default, counted from
when the scan was requested. A key is **expired** once `requested_at <= now - retention`:

- An expired key never replays. Reusing it creates a new scan, even with a different
  payload, and the response carries `Idempotent-Replayed: false`.
- Concurrent reuses of an expired key still create exactly one new scan.
- A periodic cleanup releases expired keys in bounded batches. It only clears the key
  columns: scans, outbox events and receipts are never deleted.

### 6. Set up the worker

```powershell
Set-Location services\sentinel-worker
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\sentinel-worker.exe self-check
```

`self-check` prints a JSON report and exits with `0` when healthy and `1` otherwise. It
validates the Python runtime and the worker configuration (`SENTINEL_WORKER_*` variables).
It does not connect to external services.

To consume scan requests, provision the worker's own broker user and database role first
([runbook §2](docs/runbooks/messaging.md#2-provisioning-least-privilege-identities)),
load `.env` into the session (as for the API), then:

```powershell
.\.venv\Scripts\sentinel-worker.exe consume --idle-timeout 30
```

| Variable | Purpose |
|---|---|
| `SENTINEL_WORKER_RABBITMQ_HOST` / `_PORT` / `_VHOST` | Broker address (defaults `localhost`, `5672`, `/`) |
| `SENTINEL_WORKER_RABBITMQ_USERNAME` / `_PASSWORD` | The worker's own broker user (required; never logged) |
| `SENTINEL_WORKER_RECEIPT_BACKEND` | `postgres` (default, shared and verified) or `sqlite` (development only) |
| `SENTINEL_WORKER_DB_HOST` / `_PORT` / `_NAME` | Receipt database (defaults `localhost`, `5432`, `sentinelpipe`) |
| `SENTINEL_WORKER_DB_USERNAME` / `_PASSWORD` | The worker's own database login role (required; never logged) |
| `SENTINEL_WORKER_DB_SSLMODE` | libpq `sslmode`; `production` requires `verify-ca` or `verify-full` |
| `SENTINEL_WORKER_METRICS_PORT` / `_ADDRESS` | Optional Prometheus exposition, loopback only (off by default) |
| `SENTINEL_WORKER_PREFETCH` | Unacknowledged messages in flight, 1–50 (default 1) |

Operator recovery commands (`outbox-summary`, `outbox-list-failed`,
`outbox-requeue-failed`, `dlq-depth`, `dlq-replay`) use separate `SENTINEL_OPERATOR_*`
credentials. Every requeue and replay is bounded and audited
([runbook §5–6](docs/runbooks/messaging.md#5-recovering-failed-outbox-events)).

## Asynchronous scan delivery

```text
POST /scans ─► [ scans + outbox_events ] one transaction ─► OutboxPublisher (confirms)
  ─► RabbitMQ sentinel.scan-requests ─► sentinel-worker × N: validate
  ─► worker.record_receipt (PostgreSQL: verify against outbox + scan, unique event_id) ─► ack
```

- **Transactional outbox.** A scan and its `scan.requested` v1 event are committed
  together; the request never talks to the broker. Idempotent replays create no event
  (also enforced by `UNIQUE(aggregate_id, event_type)`).
- **Publisher.** Claims events with `FOR UPDATE SKIP LOCKED` and a lease (safe with many
  instances; abandoned claims are recovered after the lease expires). It publishes
  persistent, mandatory messages and marks an event `PUBLISHED` only after a positive
  publisher confirm. Failures retry with exponential backoff (2 s doubling to 5 min, 8
  attempts) and then become `FAILED`, which is recoverable by an operator.
- **Worker.** Validates size, encoding, strict JSON, the shared schema and AMQP
  properties, then calls `worker.record_receipt` in PostgreSQL **before** acknowledging.
  The database accepts the message only if it is byte-identical to the committed outbox
  payload and its scan, project, organization and commit match the authoritative rows.
  Acceptance is unique per `event_id` across all workers. Duplicates are acknowledged
  without effect. Forged, altered or cross-tenant messages are dead-lettered and recorded
  for forensics. The worker's database role can execute only that function. Transient
  failures (for example a database outage) retry through a delayed retry queue (max 5);
  crash loops are bounded by the quorum queue's delivery limit.
- **Least privilege.** The API publishes as `sentinel-publisher` (write only), and the
  worker and operator have their own users. No runtime identity can change the broker
  topology, which is provisioned separately.
- **Guarantees.** At-least-once delivery, idempotent processing by `event_id`, **no
  exactly-once delivery and no ordering guarantee**. Exactly-once would require a
  distributed transaction spanning PostgreSQL, RabbitMQ and the worker, which RabbitMQ does
  not support. A crash after the broker confirms a publication but before the outbox row is
  marked, or after the worker commits a receipt but before it acknowledges, causes a
  harmless duplicate instead.

Details: [ADR-0004](docs/adr/0004-transactional-outbox-and-at-least-once-messaging.md),
[ADR-0005](docs/adr/0005-shared-receipts-tenant-verification-and-least-privilege.md),
[architecture](docs/architecture/asynchronous-messaging.md),
[messaging runbook](docs/runbooks/messaging.md),
[observability runbook](docs/runbooks/observability.md) (metrics, alerts), contracts in
[`packages/contracts/messages`](packages/contracts/messages/v1) and
[`packages/contracts/messaging/topology.v1.json`](packages/contracts/messaging/topology.v1.json).

## Testing

| Scope | Command (from the component directory) | Requires |
|---|---|---|
| API build, unit, integration and contract tests | `.\mvnw.cmd clean verify` (`services/sentinel-api`, JDK 21) | Docker (Testcontainers) |
| Worker lint | `.\.venv\Scripts\ruff.exe check .` | — |
| Worker formatting | `.\.venv\Scripts\ruff.exe format --check .` | — |
| Worker unit tests | `.\.venv\Scripts\python.exe -m pytest -m "not integration"` | — |
| Worker tests incl. RabbitMQ and PostgreSQL integration | `.\.venv\Scripts\python.exe -m pytest` | Docker (Testcontainers) |
| End to end: API → outbox → RabbitMQ → real worker | `.\mvnw.cmd verify -Pe2e "-Dsentinel.e2e.python=..\sentinel-worker\.venv\Scripts\python.exe"` (`services/sentinel-api`) | Docker, worker installed |
| Compose configuration | `docker compose --env-file .env.example config --quiet` (repository root) | Docker |
| OPA authorization policy | `docker run --rm -v "${PWD}\infrastructure\docker\opa:/policies:ro" openpolicyagent/opa:1.21.1 test /policies -v` | Docker |

The API integration tests start their own PostgreSQL and RabbitMQ containers through
Testcontainers, pinned to the same image digests as `compose.yaml`. They do not use the
Compose stack. Two application contexts are used: the default configuration and one
with the domain API enabled on loopback. The second uses the production JWT decoder with
a test-only RSA key pair generated in memory at test start; no private key is stored in
the repository. The tests verify that:

- the application context starts against real PostgreSQL and RabbitMQ;
- Flyway applies `V001`–`V004` to a fresh database with valid checksums and no pending
  migrations. Hibernate only validates the schema and creates no tables;
- a scan and its outbox event commit or roll back together; replays and concurrent
  retries create exactly one event; events carry the project's organization;
- against real RabbitMQ, the publisher sends persistent, confirmed messages; concurrent
  publishers send each event exactly once; crashed claims are recovered and fenced;
  broker downtime, broker nacks, unroutable messages and unknown event types never
  produce `PUBLISHED`; retries are bounded and `FAILED` events are recoverable;
- the declared topology and the messages match `packages/contracts`;
- `/actuator/health`, liveness and readiness are `UP` without exposing component details;
- with the default configuration, no `/api/**` route or token decoder exists and every
  non-health request is denied. The exposure guard rejects non-loopback bindings and
  production profiles, and incomplete identity configuration aborts startup;
- missing, expired, not-yet-valid, wrong-issuer, wrong-audience, wrong-`typ`, unsigned
  (`alg: none`), HMAC key-confusion, foreign-key, tampered and malformed tokens are
  rejected with `401` without revealing the reason;
- every registered `/api` operation (discovered automatically) rejects anonymous callers
  and authenticated outsiders, so a new unprotected endpoint fails the build;
- each role can perform exactly the operations of the authorization matrix; cross-tenant
  reads and writes by UUID return `404` and change nothing; role escalation and
  self-modification are rejected; concurrent mutual demotion of two OWNERs leaves one;
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
four jobs (the worker job runs once per Python version):

- **sentinel-api:** `mvnw clean verify` on JDK 21, including the Testcontainers integration tests.
- **sentinel-worker:** Ruff lint, Ruff format check and Pytest on Python 3.12 and 3.14,
  including RabbitMQ and PostgreSQL integration tests via Testcontainers (pinned images,
  pre-pulled; schema from the real Flyway migrations, identities from the real
  provisioning scripts).
- **End-to-end:** an authenticated scan request travels through the outbox, publisher
  confirms and RabbitMQ to the real Python worker, which records its receipt in
  PostgreSQL. The suite also covers a publisher crash after the broker confirm, a
  forged message, and an audited dead-letter replay through the operator CLI (`-Pe2e`;
  the profile fails if no E2E test runs).
- **Infrastructure:** validates `compose.yaml`, checks and tests the OPA authorization
  policy, starts the stack and waits for all health checks, provisions the runtime
  identities and verifies the exact broker permissions, then tears it down.

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
- [x] Authentication and organization-scoped authorization (Phase 2A)
- [ ] Transactional outbox and event publication (next phase)

## Milestone 2, Phase 2A checklist

- [x] OAuth 2.0 Resource Server with strict JWT validation (issuer, audience, signature,
  expiry, `typ`, asymmetric algorithms only)
- [x] `UserIdentity` keyed by issuer and subject; Flyway `V003__identity_and_memberships.sql`
- [x] Organization memberships with OWNER, ADMIN, MEMBER and VIEWER roles
- [x] Authorization on every domain endpoint; IDOR-safe `404` for non-members
- [x] Role-escalation and self-modification prevention; last-OWNER protection under concurrency
- [x] Platform-administrator bootstrap for the first organization owner
- [x] OpenAPI security scheme, membership endpoints and JSON Schemas
- [x] ADR-0003 (identity and tenant authorization)

## Milestone 2, Phase 2B checklist

- [x] Flyway `V004__transactional_outbox.sql`; scan and event written atomically
- [x] Multi-instance publisher with `SKIP LOCKED` leases, crash recovery and fencing
- [x] Persistent messages, publisher confirms, mandatory routing; bounded retries with backoff
- [x] Durable quorum-queue topology with retry and dead-letter queues and a delivery limit
- [x] `scan.requested` v1, processing-receipt and dead-letter metadata contracts (Java + Python)
- [x] Python consumer: strict validation, durable receipts before ack, duplicate and
  tampering detection, least-privileged broker user
- [x] Outbox metrics, structured logs, ADR-0004, architecture notes and runbook
- [x] Shared receipt store for multiple worker instances (Phase 2C)
- [x] Restricted broker user for the API; metrics endpoint exposure (Phase 2C)

## Milestone 2, Phase 2C checklist

- [x] Flyway `V005__worker_receipts_and_operations.sql`: shared receipts, rejections,
  audited recovery functions, group roles; historical migrations unchanged
- [x] Database-verified acceptance: digest of the committed outbox payload and
  authoritative tenant relationships; worker role limited to one function
- [x] Least-privileged RabbitMQ publisher, worker and operator users; topology provisioned
  from `definitions.json`; dead-letter queue protected against the default delivery limit
- [x] Idempotency-key retention, expiry semantics and bounded cleanup
- [x] Low-cardinality metrics (API and worker), loopback-only Prometheus exposure, outbox
  health contributor, alert guidance
- [x] Audited, bounded operator CLI for outbox requeue and dead-letter replay
- [x] Concurrency, fault-injection, permission and end-to-end tests against real
  PostgreSQL and RabbitMQ; ADR-0005 and runbooks

## Architecture decisions

- [ADR-0001: Modular monolith control plane](docs/adr/0001-modular-monolith-control-plane.md)
- [ADR-0002: Domain API disabled until authentication exists](docs/adr/0002-domain-api-exposure-before-authentication.md)
- [ADR-0003: External OIDC identity and membership-based tenant authorization](docs/adr/0003-identity-and-tenant-authorization.md)
- [ADR-0004: Transactional outbox and at-least-once messaging](docs/adr/0004-transactional-outbox-and-at-least-once-messaging.md)
- [ADR-0005: Shared worker receipts, database-verified messages and least-privilege runtime identities](docs/adr/0005-shared-receipts-tenant-verification-and-least-privilege.md)

## Current security limitations

- **Not yet approved for external deployment.** Authentication and tenant authorization
  are enforced, but audit logging of security-relevant events, rate limiting and a
  hardened deployment are missing. The domain API therefore remains disabled by default
  and loopback-only.
- Revoking a membership takes effect on the next request, but access tokens themselves
  stay valid until they expire; there is no token revocation or introspection.
- A single trusted token issuer is supported. Machine identities (GitHub App, Actions
  OIDC) arrive in M5.
- Queue messages are not signed. Workers accept only messages identical to the
  committed outbox event, so broker access alone cannot inject an accepted request, but a
  party that can write both the database and the broker could.
- Delivery is at-least-once, never exactly-once. Acceptance is exactly once per
  `event_id` across all workers.
- RabbitMQ lets an identity that may read a queue also purge it (worker: work queue;
  operator: dead-letter queue). The outbox remains the system of record.
- The API connects to PostgreSQL as the schema owner; separate runtime and migration
  roles are future work.
- `triggerType` and `branch` are supplied by the caller and not yet verified against
  GitHub events or Actions OIDC claims. There is no rate limiting.
- No scanner runs, so no real security decision is produced yet. `PASS`/`FAIL` can only
  be set by internal code paths, which are exercised by tests.

## Roadmap

| Milestone | Scope |
|---|---|
| M1 — Foundation | Complete |
| **M2 — Domain & Contracts** | Phases 1, 2A, 2B and 2C complete (see checklists) |
| M3 — Scanners | Discovery, Semgrep/Gitleaks/Trivy adapters, normalized findings, correlation |
| M4 — Security Gate & Remediation | OPA policies, coverage, exceptions, decisions, remediation reports |
| M5 — GitHub Integration | GitHub App, webhooks, OIDC, Checks, SARIF, PR comments, artifacts |
| M6 — Advanced Security | Checkov, Syft/SBOM, ZAP, attestation, isolated staging |
| M7 — Hardening & Observability | Audit, timeouts, retries/DLQ, monitoring, adversarial tests |
| M8 — Portfolio Release | Reproducible demos, C4 diagrams, ADRs, threat model |

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting process and the current
security baseline. Please do not report vulnerabilities through public issues.

# ADR-0001: Implement the control plane as a modular monolith

- **Status:** Accepted (pending owner review)
- **Date:** 2026-10-09
- **Milestone:** M2 Phase 1

## Context

The SentinelPipe control plane manages organizations, projects, scans, scanner jobs and,
in later milestones, policies, evaluations, exceptions, audit events and GitHub
integration. These concepts are strongly related: a scan decision depends on the
project, its jobs, policy results and exceptions, and must be recorded consistently.

The project is developed and operated by a small team. Its primary security goals are
correctness of the security decision (fail closed), auditable state transitions and
tenant isolation. Scanner execution has very different trust and resource requirements
and already runs separately (the Python worker on isolated runners).

Options considered:

1. **Microservices** per domain concept (organization, project, scan, ...).
2. **Modular monolith** for the control plane, with separate execution workers.
3. **Unstructured monolith** (layered by technical concern only).

## Decision

Implement the control plane (`services/sentinel-api`) as a **modular monolith**: one
deployable Spring Boot application and one PostgreSQL schema, organized into domain
modules with explicit boundaries. Scanner execution stays outside it, in separate,
restricted workers.

Module rules (package `dev.sentinelpipe.api`):

| Module | Owns |
|---|---|
| `organization` | `Organization` aggregate and its API |
| `project` | `Project` aggregate, GitHub repository identity |
| `scan` | `Scan` aggregate, scan requests, idempotency, lifecycle orchestration |
| `scanjob` | `ScanJob` entity and its state machine |
| `common` | Problem Details, pagination, shared validation, time source |
| `security` | HTTP security, JWT validation, exposure guard (ADR-0002, ADR-0003) |
| `identity` | User identities keyed by token issuer and subject (M2 Phase 2A) |
| `authorization` | Organization memberships, roles, access control (M2 Phase 2A) |

- Aggregates reference each other **by identifier**, not by JPA associations. This keeps
  transactions small, avoids lazy-loading across modules, and keeps a later extraction
  possible.
- Other modules call a module through its public **service**, not its repository
  (exception: `scan` reads `ScanJobRepository`, because the scan lifecycle owns its jobs).
  Repositories, DTOs and controllers are package-private where possible.
- The dependency direction is acyclic: `project → organization`, `scan → project`,
  `scan → scanjob`, `authorization → identity, security`, and the domain controllers →
  `authorization`. Nothing depends on `scan`; `authorization` does not depend on
  `organization` (it locks organization rows with a native query).
- Domain invariants live in entities (state machines, normalization) and are mirrored
  by database constraints. Controllers only translate HTTP to service calls.
- Schema changes are made only through versioned Flyway migrations.

## Consequences

Positive:

- Cross-aggregate invariants (for example, "PASS requires every job COMPLETED") are
  enforced in one ACID transaction with row locks, without distributed transactions or
  sagas.
- One deployable artifact, one database and one CI pipeline: lower operational and
  security surface (no service-to-service authentication, network policies or schema
  versioning between internal services yet).
- Module boundaries keep the code reviewable and allow later extraction if load or
  isolation requirements justify it.

Negative / risks:

- Package boundaries are enforced by convention, visibility and review, not by the build.
  Mitigation (future): architecture tests (for example ArchUnit or Spring Modulith).
- All modules scale together. Acceptable at the current scale; scanner workloads, which
  dominate resource usage, are already separate.
- A defect in one module can affect the whole control plane process. Mitigated by tests,
  fail-closed defaults and database constraints.

## Related

- CLAUDE.md §3 (architecture baseline)
- ADR-0002 (domain API exposure before authentication exists)

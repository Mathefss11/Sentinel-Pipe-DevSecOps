# ADR-0002: Disable the domain API by default until authentication exists

- **Status:** Accepted (pending owner review). Amended by
  [ADR-0003](0003-identity-and-tenant-authorization.md): authentication and tenant
  authorization now exist; the default-off switch and the loopback guard remain.
- **Date:** 2026-10-09
- **Milestone:** M2 Phase 1

## Context

M2 Phase 1 introduces the `/api/v1` domain endpoints (organizations, projects, scans).
SentinelPipe is a multi-organization platform, but authentication and
organization-scoped authorization are not implemented yet. An exposed API would let any
caller create organizations, enumerate projects and queue scans for any tenant. Knowing
a UUID is not authorization.

The endpoints must still be usable for local development and testable in CI.

## Decision

1. **Off by default.** The domain controllers are registered only when
   `sentinel.domain-api.enabled=true` (`@ConditionalOnDomainApiEnabled`). With the default
   configuration the routes do not exist and return `404`.
2. **Explicit development profile.** `application-local.yml` (profile `local`) enables the
   API and sets `server.address=127.0.0.1`.
3. **Fail-fast exposure guard.** When the API is enabled, `DomainApiExposureGuard` aborts
   startup unless `server.address` is a **literal loopback IP** (`127.0.0.0/8` or `::1`)
   and no `prod`/`production` profile is active. Host names (including `localhost`) are
   rejected because their resolution depends on the environment. Leaving
   `server.address` unset is rejected because the default binds all interfaces.
4. **No shortcuts.** No API keys, development passwords, header-based bypasses or
   "trusted" tenant IDs. Organization IDs in paths are resource selectors, not proof of
   authorization.
5. **No public lifecycle endpoints.** Scan and job state transitions are only reachable
   through the internal `ScanLifecycleService`.

## Consequences

- A production deployment with the default configuration exposes only the Actuator
  health endpoints. Accidentally setting `SENTINEL_DOMAIN_API_ENABLED=true` on a server
  bound to a public interface makes startup fail instead of exposing the API.
- The guard is a development safety net, **not access control**: any process on the same
  host, a container sharing the network namespace, or a reverse proxy on the same host can
  reach a loopback-bound server. The `local` profile must only be used on a personal
  workstation.
- The Actuator health endpoints share the same port and therefore the same binding.

## Required before any external deployment

- Authentication (for example OIDC for users; GitHub App / Actions OIDC for automation).
- Organization membership and role checks on every tenant-scoped read and write,
  including list endpoints and lookups by UUID.
- Removal of the `sentinel.domain-api.enabled` development switch, or making it
  conditional on authentication being configured.
- Rate limiting and request size limits.
- Audit events for state-changing operations.

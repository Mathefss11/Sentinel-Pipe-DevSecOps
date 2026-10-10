# Security Policy

## Project status

SentinelPipe is pre-release software under active development (Milestone 2, Phase 2A: identity and tenant authorization).
It is not yet intended for production use, and no version is currently supported for
production deployments. Security fixes are applied to the `main` branch.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, discussions,
or pull requests.

Report them privately through GitHub's private vulnerability reporting: open the repository's
**Security** tab and select **Report a vulnerability**. Please include:

- a description of the issue and its potential impact;
- the affected component, file, or configuration;
- steps to reproduce or a minimal proof of concept;
- any suggested remediation.

Please do not include real credentials, personal data, or third-party secrets in a report.
Reports are acknowledged on a best-effort basis. This is a personal open-source project with
no formal response-time commitment.

## Scope

In scope:

- code and configuration in this repository (`services/`, `infrastructure/`, `compose.yaml`,
  `.github/workflows/`);
- weaknesses that could cause SentinelPipe to report a passing security decision without
  complete, verified evidence (fail-open behavior).

Out of scope:

- vulnerabilities in third-party dependencies or container images that have not been shown to
  be exploitable through SentinelPipe (please report those upstream);
- the local development stack (`compose.yaml`) when it is deliberately exposed beyond
  `127.0.0.1` or run with placeholder credentials outside a workstation;
- the intentionally vulnerable example applications planned under `examples/`.

## Security baseline

The current version implements the following controls:

- **Secrets:** no credentials are committed. Passwords have no defaults in the application
  configuration or in `compose.yaml`. Both fail to start if a password is missing. `.env` is
  git-ignored, and `.env.example` contains development-only placeholders.
- **Local network exposure:** all Docker Compose host ports bind to `127.0.0.1` only.
- **Image supply chain:** container images in `compose.yaml` and in the Testcontainers test
  configuration are pinned to immutable multi-arch digests.
- **OPA:** the server runs with `--authorization=basic` and a deny-by-default `system.authz`
  policy. It permits health checks and decision queries and rejects policy and data
  management requests. The container runs as a non-root user with a read-only root
  filesystem, all Linux capabilities dropped, and `no-new-privileges`.
- **API surface:** by default, only the Actuator health endpoints are reachable, without
  component details; every other request is denied. The domain API (`/api/v1`) is
  registered only when `sentinel.domain-api.enabled=true`. Startup then fails unless the
  identity settings are complete, `server.address` is a literal loopback IP and no
  `prod`/`production` profile is active (ADR-0002, ADR-0003). There is no public endpoint
  that changes scan or job state.
- **Authentication:** OAuth 2.0 Resource Server. Access tokens from an external OIDC
  provider must be JWS-signed with an allow-listed asymmetric algorithm, carry an
  allow-listed `typ` (`at+jwt` by default), the exact configured issuer, the configured
  audience and an unexpired `exp`. Unsigned and HMAC tokens cannot be accepted, there is
  no shared signing secret, tokens are accepted only in the `Authorization` header, and
  401 responses do not disclose the rejection reason. SentinelPipe stores no passwords.
- **Authorization:** every tenant-scoped request is checked against server-side
  organization memberships (OWNER, ADMIN, MEMBER, VIEWER); token role or organization
  claims are ignored. Non-members receive 404 for foreign resources (no IDOR or existence
  disclosure). Role escalation and self-modification are rejected, membership changes are
  serialized per organization, and an organization always keeps an OWNER. Organization
  creation is limited to configured platform administrators.
- **Input handling:** request bodies reject unknown properties. Repository identity is
  accepted only as validated owner and name, never as a URL. Commit SHAs must be full
  object names, and branch names are restricted to a conservative character set. Errors are
  RFC 9457 Problem Details without stack traces, exception names, SQL or echoed input
  values.
- **Fail-closed scan state:** failed or cancelled scans are always `INCOMPLETE`, and `PASS`
  requires every scanner job to have completed. These invariants are enforced in code and
  by PostgreSQL CHECK constraints.
- **Database:** the schema is managed exclusively by versioned Flyway migrations. Hibernate
  only validates the schema.
- **CI:** GitHub Actions runs with a read-only token (`contents: read`). Checkout credentials
  are not persisted, third-party actions are pinned to commit SHAs, and there are no deployment
  or publishing steps.

## Known limitations

- The domain API is authenticated and tenant-authorized, but it is not yet approved for
  external exposure: audit logging of security events, rate limiting and a hardened
  deployment are still missing. It remains disabled by default and loopback-only.
- Access tokens stay valid until they expire (no revocation or introspection). Membership
  revocation takes effect on the next request. Only one trusted issuer is supported.
- Scan `triggerType` and `branch` are caller-supplied and not yet verified against GitHub
  events or OIDC claims. Idempotency keys do not expire, and there is no rate limiting.
- The Compose stack is for local development only. It does not use TLS between services, and
  OPA does not authenticate clients.
- Scanner execution, evidence integrity verification, GitHub webhook and OIDC validation, and
  policy-based security decisions are not implemented yet.
- Image digests and action SHAs are pinned but not yet updated automatically. Dependency
  update automation and provenance verification are planned for later milestones.

# Security Policy

## Project status

SentinelPipe is pre-release software under active development (Milestone 2, Phase 2B: transactional outbox and reliable messaging).
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
- **Messaging:** scan requests reach the worker through a transactional outbox and RabbitMQ
  (ADR-0004). Events are built from committed server-side state and contain no tokens,
  credentials or user identities. The worker treats messages as untrusted input: bounded
  size, strict JSON, schema and AMQP property validation. Receipts are shared in PostgreSQL
  and committed before acknowledgement. A message is accepted only if it is byte-identical
  to the committed outbox payload and matches the authoritative scan, project and
  organization (ADR-0005). Payload tenant identifiers are never trusted, and forged or
  altered messages are dead-lettered and recorded for forensics. Messages are never
  authorization credentials. Failed publications and dead letters are retained for
  recovery (docs/runbooks/messaging.md); the dead-letter queue has an unlimited delivery
  limit, so nothing is silently dropped. Logs and metrics contain identifiers and outcome
  codes only, never payloads, and metric labels are fixed low-cardinality enumerations.
- **Least-privilege runtime identities:** the API publishes as `sentinel-publisher`
  (write `sentinel.scan-requests` only). The worker can only read its queue and write the
  retry and dead-letter exchanges. No runtime user can configure topology or use the
  management interface; topology is provisioned separately by an administrator. In
  PostgreSQL, the worker role may only execute `worker.record_receipt` and the operator
  role only the `ops.*` recovery functions. Both are `SECURITY DEFINER` functions with a
  fixed `search_path`, and `EXECUTE` is revoked from `PUBLIC`.
- **Recovery:** operator actions (requeue FAILED outbox events, dead-letter replay) are CLI
  commands with separate operator credentials, bounded to 100 items per call and audited
  in `ops.recovery_actions` before they take effect. There are no recovery HTTP endpoints.
- **Metrics exposure:** no metrics endpoint is exposed by default. The API's Prometheus
  endpoint and the worker's exposition server can only be enabled on a loopback address,
  and for the API only on a separate management port; startup fails otherwise.
- **Idempotency keys** expire after a documented retention (default 24 h). Expired keys
  never replay, and cleanup never deletes scans, outbox events or receipts.
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
- Queue messages are not signed; they are authenticated against the database, so a party
  that can write both the outbox and the broker could forge a request. Delivery is
  at-least-once, not exactly-once (acceptance is exactly once per `event_id`).
- RabbitMQ authorizes `queue.purge` with the read permission: the worker can purge its
  work queue and the operator the dead-letter queue. The outbox remains the system of
  record for recovery.
- The API connects to PostgreSQL as the schema owner (the Compose superuser locally), and
  `SECURITY DEFINER` functions run as the migration owner. Separate runtime and migration
  roles are still to be introduced. **This is a blocker before real scanner execution
  (M3).**
- Dead-letter replay audit is enforced by the operator CLI, not by the broker: the
  operator's broker credentials alone can republish or discard dead letters without an
  audit row. Workers still verify and deduplicate every message.
- Provisioning passes RabbitMQ passwords to `rabbitmqctl` as process arguments inside the
  broker container. PostgreSQL role passwords appear in an `ALTER ROLE` statement that
  the server would log under non-default logging settings or on error. See
  [messaging runbook §2](docs/runbooks/messaging.md#2-provisioning-least-privilege-identities).
- Scan `triggerType` and `branch` are caller-supplied and not yet verified against GitHub
  events or OIDC claims. There is no rate limiting.
- The Compose stack is for local development only. It does not use TLS between services, and
  OPA does not authenticate clients.
- Scanner execution, evidence integrity verification, GitHub webhook and OIDC validation, and
  policy-based security decisions are not implemented yet.
- Image digests and action SHAs are pinned but not yet updated automatically. Dependency
  update automation and provenance verification are planned for later milestones.

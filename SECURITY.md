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
  `prod`/`production` profile is active (ADR-0002, ADR-0003). The only endpoint that
  changes scan state is the tenant-checked, audited cancellation (MEMBER and above).
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
  requires every scanner job to have completed **and** a policy evaluation, which does not
  exist yet, so completed scans are `INCOMPLETE` with a recorded reason. Execution status
  and security decision are separate. These invariants are enforced by PostgreSQL
  lifecycle functions and CHECK constraints (ADR-0007).
- **Execution protocol:** workers claim jobs through `SECURITY DEFINER` functions only,
  authenticated by their own database login, a random lease token (stored only as
  SHA-256) and a monotonic fencing epoch. Stale, forged, stolen or cross-tenant reports
  change nothing and are recorded in an append-only audit trail; duplicate reports are
  idempotent. Leases expire after 60 s without heartbeats, jobs have at most 3 attempts,
  and scans a 15-minute hard deadline. Retry decisions belong to the control plane.
  Identifiers in queue messages are never used: workers act only on the authoritative
  context returned by the claim. The API's database login cannot write execution state
  directly.
- **Result integrity and evidence:** results are versioned `job-result.v1` documents
  (16 KiB, canonical JSON). PostgreSQL validates each one in a single transaction against
  the lease and the authoritative job, scan, project, organization and commit. Evidence
  digests are computed by the database from the uploaded bytes; worker-supplied digests
  are never accepted on their own. Evidence is content-addressed per organization, bound
  to the uploading lease, immutable (a CHECK constraint recomputes the digest) and
  re-verified on read. Artifact names are restricted identifiers, never paths or URLs.
  Repeated refused submissions are deduplicated in the audit trail (ADR-0008).
- **Execution sandbox:** every job attempt runs in a fresh container with no network, a
  read-only root, a noexec size-limited `/tmp`, user 65534, all capabilities dropped,
  no-new-privileges, seccomp, and PID, memory, CPU, output and time limits. There is no
  Docker socket, mount, host environment or credential inside, and images are digest-pinned
  and never pulled at run time. Cancellation, lease loss and timeouts kill the container,
  which is always removed. Output is data only (no paths), strictly parsed and bounded.
  The controls are verified from inside a sandbox by `sentinel-worker sandbox-check` and in
  CI (ADR-0009).
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
  PostgreSQL, the worker role may only execute `worker.record_receipt` and the execution
  protocol functions (`worker.claim_job`, `heartbeat_job`, `put_evidence`, `submit_result`), and the operator
  role only the `ops.*` recovery functions. All are `SECURITY DEFINER` functions with a
  fixed `search_path`, and `EXECUTE` is revoked from `PUBLIC`, including by default for
  future functions of the owner role.
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
- Database identities are separated (ADR-0006): the API runtime login has DML on its own
  tables only, Flyway uses a migrator login that switches to the non-superuser
  `sentinel_owner`, and definer functions run as that owner. If Flyway runs inside the API
  process, the process holds the migration credentials at startup; production-like
  deployments should migrate in a separate step (`SPRING_FLYWAY_ENABLED=false` for the
  API).
- A worker that legitimately holds a lease can report a false outcome or upload false
  evidence for that job. The evidence is integrity-checked and attributable, but how it
  was produced is not attested yet (planned for M6).
  An API compromise can cancel or fail scans and record an evaluation for an EVALUATING
  scan. It cannot complete jobs or skip execution, and `PASS` still requires every job to
  have completed.
- **Trust policy (ADR-0009):**
  - Docker/runc may run only controlled fixtures and explicitly trusted scanners.
  - Arbitrary untrusted repository code never runs under runc; the sandbox policy refuses
    it without a hardened runtime.
  - Disposable VMs or validated gVisor/Kata deployments are required before untrusted
    code is enabled.
  - Repository content is always untrusted input, even for trusted scanners.
- No untrusted repository content is fetched or executed yet; only a harmless fixture
  runs in the sandbox. With the default runc runtime the sandbox shares the host kernel and
  is not a sufficient boundary against kernel or runtime exploits. A stronger runtime
  (gVisor, Kata) or per-job VMs must be chosen before untrusted code runs, and worker hosts,
  whose Docker access is root-equivalent, must be dedicated (ADR-0009, threat model).
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

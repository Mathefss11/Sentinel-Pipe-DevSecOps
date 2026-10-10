# M3 Phase 1 security assessment: consolidated threat model

Status: 2026-10-10, code at `42c0299` plus the Slice 5 review changes (uncommitted).
Consolidates ADR-0003 to ADR-0009 and `docs/threat-model/execution-sandbox.md`.

**Severity** is that of the residual risk after the existing mitigations: Critical, High,
Medium, Low.

This table lists **accepted residual risks** of the design. They are not defects. The
review's **newly discovered defects** (F-01 to F-05) are listed separately below and in the
readiness report; all of them are fixed and covered by regression tests.
**Blocks Phase 2** means it must be resolved before M3 Phase 2 (real scanners) begins.

## System and trust boundaries

```text
 user / CI ──HTTPS + JWT──▶ API (sentinel_api_app) ──definer functions──▶ PostgreSQL ◀── migrator (Flyway, SET ROLE owner)
                              │ outbox → RabbitMQ (publisher user)            ▲   ▲
                              ▼                                               │   └── operator CLI (sentinel_operator_app)
                           RabbitMQ ──(verified message, receipts)──▶ worker (sentinel_worker_app) ──docker CLI──▶ sandbox (untrusted)
```

| Boundary | Authentication | Authorization |
|---|---|---|
| Client → API | OIDC JWT (asymmetric, exact issuer and audience, `typ`) | Membership per organization; 404 for non-members |
| API → database | Own login; no DDL; no UPDATE of lifecycle columns | Column grants and `lifecycle.*` functions |
| Worker → database | Own login | Functions only; lease token, epoch and `session_user` |
| Worker → sandbox | n/a (worker is trusted) | Frozen policy; allowlisted image, command and runtime |
| Sandbox → worker | None (untrusted) | Bounded `sandbox-output.v1`, then database-verified evidence |

## Threats

| # | Threat | Attack surface | Boundary | Existing mitigation | Verification evidence | Residual risk | Sev. | Blocks Ph. 2 |
|---|---|---|---|---|---|---|---|---|
| A1 | External API attacker | `/api/v1`, actuator | Client → API | Domain API off by default and loopback-only; JWT validation; RFC 9457 errors without internals; no unauthenticated endpoints | `JwtAuthenticationIntegrationTests`, `EndpointProtectionCoverageTests` (every endpoint), `DomainApiExposureGuardTests` | No rate limiting; API not approved for external exposure (ADR-0002) | Medium | No (API stays loopback) |
| A2 | Malicious authenticated tenant | Scan, project and membership endpoints; scan and job ids | Client → API | Membership checks on every resource; cancellation checked against the project's organization; ids are never authorization | `TenantIsolationIntegrationTests`, `ScanCancellationApiIntegrationTests` (foreign project, foreign org, viewer), `RoleAuthorizationIntegrationTests` | None known | Low | No |
| A3 | Compromised worker credentials | `worker.*` functions | Worker → database | No table access; claims return database context; tokens fenced by epoch and login; evidence tenant-scoped; bounded, deduplicated rejections | `ExecutionProtocolIntegrationTests`, `ResultIntegrityIntegrationTests`, `ExecutionAdversarialIntegrationTests`, `DatabasePrivilegeIntegrationTests` (worker denials) | Workers are tenant-agnostic by design. A stolen worker login can claim any tenant's queued jobs and submit **false results and evidence for the jobs it claims**, and can tie up jobs until attempts run out. It cannot touch jobs it does not hold or read other data | **High** | No: requires secret management for worker logins (Phase 2 entry criterion), and evidence authenticity is planned for M6 |
| A4 | Compromised API credentials | API login | API → database | No DDL, no deletes of security history, no UPDATE of lifecycle columns; lifecycle only via functions; no worker functions | `DatabasePrivilegeIntegrationTests` (apiRuntimeIdentityIsDenied, 40+ statements) | Can cancel or fail scans, create tenants' data, read all tenant data, and record an evaluation, **including PASS**, for EVALUATING scans whose jobs all completed | High (once decisions are consumed) | No for Phase 2 (no PASS producer or consumer exists); **yes for M4/M5 gate enforcement** |
| A5 | Malicious repository content (future) | Scanner input | Sandbox | Trust policy: trusted scanners only under runc; content is always untrusted; sandbox controls; no network | `sandbox-check`, `tests/sandbox` (13 controls observed from inside) | A scanner parsing bug gives code execution **inside** the sandbox; escape then requires a kernel or runtime exploit (A7) | Medium | No: Phase 2 must keep scanners inside the sandbox and update the threat model per scanner |
| A6 | Malicious scanner output | stdout envelope, artifacts, results | Sandbox → worker → database | Bounded stdout and stderr; strict parsing (duplicate keys, base64, names as identifiers, never paths); database-computed digests; lease-bound, tenant-scoped evidence | `test_sandbox.py` (path names, duplicate keys, deep nesting), `malicious_output` and `oversized_output` modes, `ResultIntegrityIntegrationTests` | False findings inside its own job's evidence (integrity is not authenticity) | Medium | No |
| A7 | Container escape | Kernel, runc | Sandbox → host | Non-root, no capabilities, no-new-privileges, seccomp, read-only root, no network, no mounts; **trust policy forbids untrusted code under runc** (enforced: `Workload.UNTRUSTED_CODE` requires gVisor or Kata) | Probe controls; `test_untrusted_code_never_runs_under_the_default_runc_boundary` | runc shares the host kernel; a kernel exploit escapes. Acceptable only for trusted tools | High (for hostile code) | No for trusted scanners; **yes before any untrusted code** |
| A8 | Docker daemon compromise | Worker host | Worker → daemon | Worker hosts are trusted and dedicated (ADR-0009); no socket in sandboxes; CLI without `SENTINEL_*` variables | Probe `no_docker_socket`, `no_host_mounts`; `cli_environment` test | The daemon is root on its host; a compromised worker process controls it | High | No, given dedicated hosts (Phase 2 entry criterion) |
| A9 | Database privilege escalation | Logins, functions, roles | All → database | Non-superuser owner; group roles NOLOGIN; logins in one group each; no CREATE or TEMP; no predefined roles; definer functions only in four schemas with pinned `search_path`; no PUBLIC EXECUTE, also by default; only `plpgsql` | `DatabasePrivilegeIntegrationTests` (115 tests, including Slice 5 escalation tests), `FlywayMigrationIntegrationTests`, `scripts/ci/verify-database-roles.sh` | Runtime logins can set their own session defaults (harmless: no schema allows them to create objects) | Low | No |
| A10 | Evidence tampering | Evidence tables, storage | Database | No runtime write access; a CHECK recomputes SHA-256 on every write (even a superuser's ordinary UPDATE fails); re-verification on read in Java | `modifiedEvidenceBytesCannotReplaceStoredEvidence` (superuser UPDATE → 23514), `EvidenceVerifier` tests | A database administrator who drops the constraint; there is no external append-only copy | Low | No |
| A11 | Supply-chain compromise | Actions, images, dependencies | CI and runtime | Actions pinned to SHAs; `contents: read`; `pull_request` (not `pull_request_target`); every CI and runtime image pinned by digest (Ryuk removed from CI); sandbox images pinned, `--pull never`; Maven wrapper distribution verified by SHA-256 (F-03, fixed) | Workflow review; policy tests; wrapper negative control (a tampered checksum is refused) | Python dependencies are ranges without hashes; image and artifact signatures are not verified | Medium | No (M6 signatures) |
| A12 | Denial of service and resource exhaustion | API, database, workers, sandboxes | All | Sandbox PID, memory, CPU, output and time limits; bounded evidence (16 artifacts, 8 MiB per lease); deduplicated rejection audit; bounded supervisor batches; leases and deadlines bound stuck work | `pids`, `memory`, `cpu`, `oversized_output` modes; worker-responsiveness test; `repeatedRejectionsAreCountedWithoutGrowingTheAuditTrail` | No API rate limiting; total evidence volume grows with the number of jobs; concurrent sandboxes on one host compete | Medium | No |
| A13 | Stale or racing workers | Lease protocol | Worker → database | Epoch fencing; expired leases never revived; atomic submission; cancellation kills the sandbox | Concurrency, adversarial and real-sandbox lease-loss tests; randomized workload with cross-table invariants | None known | Low | No |
| A14 | Secret leakage | Logs, metrics, audit, errors | All | Tokens returned once and stored only hashed; codes instead of content; sanitized stderr (not logged); closed metric labels; 22023 errors never echo input | Leakage tests in Java (audit rows) and Python (logs, metrics exposition, CLI output) | Heuristic stderr redaction; PostgreSQL could log function arguments (tokens) under non-default logging settings | Low | No |

## Newly discovered defects (M3 Phase 1 review)

These were defects, not design risks. They are fixed and listed here so they are not
confused with the residual risks above.

| ID | Sev. | Defect | Status |
|---|---|---|---|
| F-01 | Low | Sandbox probe did not verify the mount table | Fixed (`no_host_mounts`, real negative control) |
| F-02 | Low | Ryuk image pulled by tag in CI | Fixed (Ryuk disabled on ephemeral runners) |
| F-03 | Low | Maven wrapper distribution not integrity-checked | Fixed (verified `distributionSha256Sum`) |
| F-04 | Low | Missing database escalation regression tests | Fixed (tests; no escalation path existed) |
| F-05 | Low | Missing adversarial execution tests | Fixed (tests and cross-table invariants; no defect existed) |
| Slice 4 review | Medium/Low | Reaper ownership, monitor thread leak, lost runtime CLI, zero timeout, cancellation before start | Fixed (ADR-0009) |

## Integrity, authenticity and trust

The four properties below are distinct, and only the first is guaranteed today.

| Property | Status | Meaning |
|---|---|---|
| **Evidence integrity** | **Guaranteed** | The control plane computed the digest from the bytes it stores; the bytes cannot change without detection; a result references only evidence of its own job, lease and tenant |
| **Evidence authenticity** | **Not provided** | Nothing proves *which software* produced the bytes. A lease holder can upload anything for its own job |
| **Scanner trustworthiness** | Policy only | Scanners are trusted by review and digest pinning (trust policy). There is no runtime verification that the scanner ran correctly |
| **Attestation and provenance** | Future (M6) | Signed images (Cosign), SLSA provenance and signed results bound to the job |

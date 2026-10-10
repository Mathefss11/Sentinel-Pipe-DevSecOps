# M3 Phase 1: security-readiness report

- **Date:** 2026-10-10
- **Scope:** M3 Phase 1, Slices 1–5 (secure scan execution foundation)
- **Code:** `42c0299` (Slices 1–4, on `origin/main` per local refs) plus the Slice 5 review
  and closure changes (uncommitted)
- **Verdict:** **READY WITH CONDITIONS** (section 10)

## 1. Architecture overview

- **Control plane** (Java 21, Spring Boot): tenants, projects, scans, the outbox, the
  supervisor and evaluation.
- **PostgreSQL** is the single authority for execution state:
  - leases with fencing epochs and hashed tokens (ADR-0007);
  - result and evidence integrity (ADR-0008).
- **Workers** (Python):
  - verify RabbitMQ deliveries against the outbox (ADR-0005);
  - claim jobs through `SECURITY DEFINER` functions with their own login;
  - run each attempt in a fresh, hardened, single-use container (ADR-0009).
- **Identities:** every component has its own least-privileged database identity
  (ADR-0006). The non-superuser `sentinel_owner` owns all objects.

Consolidated threat model: [m3-phase1-threat-assessment.md](m3-phase1-threat-assessment.md).

## 2. Implemented security controls

| Area | Controls |
|---|---|
| Database | Separate owner, migrator, API, worker and operator identities; no runtime DDL, TEMP or extensions; column-level grants; lifecycle and worker operations only through definer functions with a pinned `search_path`; no PUBLIC EXECUTE (also by default); `CONNECT` limited to provisioned logins |
| Execution | Atomic claims (`SKIP LOCKED`); 60 s leases with 15 s heartbeats; epoch fencing; at most 3 attempts with backoff; 15-minute hard deadline; supervisor recovery; cancellation; append-only audit with deduplicated rejections; execution status separate from the security decision; PASS impossible without completed jobs and a policy evaluation |
| Results and evidence | `job-result.v1` (canonical, 16 KiB, strict) validated in the database against authoritative context; digests computed by the database; evidence content-addressed per tenant and bound to the lease; immutable (CHECK) and re-verified on read; retention with purge; idempotent and fenced submission |
| Sandbox | No network, read-only root, noexec bounded `/tmp`, uid 65534, no capabilities, no-new-privileges, seccomp; PID, memory (no swap), CPU, file, output and time limits; no mounts, socket, environment or credentials; digest-pinned images with `--pull never`; argument vectors only; allowlisted image, command and runtime; data-only output channel; kill on cancellation and lease loss; always removed; expiry-based crash reaping that never removes another worker's live sandbox; **trust policy enforced in code** |
| CI | Actions pinned to SHAs; read-only token; no `pull_request_target`; every image pinned by digest; dedicated sandbox job with real containers that fails rather than skips |

## 3. Tests and verification evidence

All runs are local, on 2026-10-10: Windows 11, Docker Desktop (Engine 29.7.2, cgroups v2),
JDK 21.0.10, Python 3.14. The Slice 5 code changes are included.

| Suite | Command | Result |
|---|---|---|
| Java build, unit, integration, contract and database privilege tests | `mvnw clean verify` | **609 / 609 passed**, BUILD SUCCESS |
| — database privileges | `DatabasePrivilegeIntegrationTests` | 115 / 115 |
| — upgrade paths (V005→V008, V007→V008) | `DatabaseUpgradePathIntegrationTests` | 6 / 6 |
| — execution adversarial, with cross-table invariants | `ExecutionAdversarialIntegrationTests` | 7 / 7 |
| — contracts (JSON Schema, OpenAPI, messages) | `ContractIntegrationTests`, `OpenApiContractTests`, `MessagingContractIntegrationTests` | 9 / 9, 5 / 5, 4 / 4 |
| End to end (API → outbox → RabbitMQ → real worker; sandboxed execution, cancellation, crash recovery) | `mvnw verify -Pe2e` | **8 / 8 passed** |
| Python unit, integration and real-container sandbox tests | `pytest` with `SENTINEL_REQUIRE_SANDBOX=1` | **385 / 385 passed** (28 sandbox-marked) |
| Sandbox self-check | `sentinel-worker sandbox-check` | healthy, **13 / 13 controls** |
| Lint and formatting | `ruff check`, `ruff format --check` | clean |
| Compose configuration | `docker compose --env-file .env.example config --quiet` | valid |
| Leftover sandbox containers after all runs | `docker ps -a --filter label=sentinelpipe.sandbox=1` | 0 |

The compose-level role check (`scripts/ci/verify-database-roles.sh`) was verified in Slice 1
against an isolated Compose project; it was not rerun in Slice 5, and no provisioning code
changed since.

## 4. Findings and remediations (Slice 5 review)

Remediated in this review:

| ID | Sev. | Component | Root cause | Impact | Remediation | Regression test |
|---|---|---|---|---|---|---|
| F-01 | Low | `sandbox/isolation.py`, `fixture.py` | The isolation probe checked the Docker socket but not the full mount table | A host directory mounted by a misconfigured daemon or a future code path would pass `sandbox-check` | New `no_host_mounts` control: every mount target must be one the runtime itself creates | `test_only_runtime_created_mounts_are_accepted`; real negative control `test_the_mount_check_detects_a_real_host_mount` (a bind mount is detected) |
| F-02 | Low | `.github/workflows/ci.yml` | `testcontainers/ryuk:0.14.0` pulled by tag in the api and e2e jobs | A mutable tag in CI; inconsistent with digest pinning | Ryuk disabled on ephemeral runners (as the worker job already did); no longer pulled | Workflow review; every remaining CI image is a digest |
| F-04 | Low (test gap) | Database privileges | No regression tests for escalation through predefined roles, temporary objects, server file and program functions, extensions, or definer functions outside the controlled schemas | Silent regression possible | Audit found no escalation path; tests added | `runtimeLoginsBelongOnlyToTheirOwnGroupAndGroupsToNothing`, `noRuntimeLoginReachesServerFilesProgramsExtensionsOrTemporaryObjects`, `securityDefinerFunctionsExistOnlyInControlledSchemasWithAPinnedSearchPath` |
| F-05 | Low (test gap) | Execution protocol | Untested: a crash inside the submission or upload transaction, out-of-order events, the deadline passing between upload and submission, mixed retry exhaustion, forged cross-tenant context, a randomized concurrent workload, a V007→V008 rolling upgrade, repeated heartbeat disconnections, a runtime CLI reporting success without a container | Silent regression possible | No defect found; tests added, each asserting the answer **and** the database state, plus cross-table invariants (no COMPLETED job without its accepted report, no report from a future lease, no unjustified PASS or FAIL, no unfinished job in a finished scan, no evidence outside its tenant) | `ExecutionAdversarialIntegrationTests`, `upgradingFromV007KeepsLegacyReportsAndInFlightLeasesUsable`, `test_heartbeats_survive_repeated_database_disconnections`, `test_runtime_cli_output_without_a_real_container_is_never_success` |

Remediated in the Slice 4 review (for completeness): reaper ownership, a monitor thread
leak, a lost runtime CLI being misclassified, a zero timeout, and cancellation before start
(ADR-0009).

Remediated in the M3 Phase 1 closure:

| ID | Sev. | Component | Root cause | Remediation | Verification |
|---|---|---|---|---|---|
| F-03 | Low | `services/sentinel-api/.mvn/wrapper/maven-wrapper.properties` | No `distributionSha256Sum`: the Maven distribution downloaded by CI and developers was not integrity-checked | Added `distributionSha256Sum=1f6d9909266510f039f59aa0e13dcd2c66da85f043e56276e41f2918f8bddaff` for `apache-maven-3.10.0-bin.zip` | See the verification steps below |

How F-03 was verified:
1. The archive was downloaded from the configured `distributionUrl` (Maven Central).
2. Apache publishes no SHA-256 for it (Maven Central returns 404 for `.sha256`), so its
   SHA-512 was compared with the **three official SHA-512 files** (Maven Central,
   downloads.apache.org, archive.apache.org), and its SHA-1 with Maven Central's. All
   matched.
3. The **PGP signature** (`.asc`) verified as a good signature from key
   `88BE 34F9 4BDB 2B53 5704 4E2E 3A38 7D43 9641 43E3` (Tamas Cservenak, Maven release
   manager). The key was imported from the official
   `https://downloads.apache.org/maven/KEYS` into an isolated keyring.
4. The SHA-256 was then computed from the verified bytes.
5. With fresh, empty Maven user homes:
   - both `mvnw` (POSIX, used by CI) and `mvnw.cmd` (Windows) downloaded, validated and ran
     Maven 3.10.0;
   - in a copy of the wrapper with one altered hex digit, both refused with "Failed to
     validate Maven distribution SHA-256".

Caveat: the wrapper validates only when it downloads. Distributions already cached in
`~/.m2/wrapper` are not re-validated. CI runners start without that cache, so CI validates
on every run.

Open (informational):

| ID | Sev. | Component | Finding | Remediation (owner action) |
|---|---|---|---|---|
| I-01 | Info | CI | No test-report artifacts are uploaded when a job fails | Optional: `actions/upload-artifact`, pinned to a verified SHA |
| I-02 | Info | Python | Dependencies are version ranges without hashes or a lock file | Consider a hashed lock for CI before release (M8) |

## 5. Accepted residual risks

From the threat assessment, with severity:
- **A3, High:** a stolen worker login can claim and falsely complete jobs of any tenant.
  Mitigated by integrity, fencing and audit, not by authenticity.
- **A4, High once decisions are consumed:** a compromised API can record PASS for scans
  whose jobs all completed.
- **A7, High for hostile code:** runc shares the host kernel. Trusted tools only.
- **A8, High:** the Docker daemon is root on worker hosts. Hosts must be dedicated.
- **A11, Medium:** there are no image or artifact signatures, and Python dependencies are
  version ranges without hashes. The Maven wrapper checksum (F-03) is now fixed.
- **A12, Medium:** no API rate limiting; total evidence volume grows with job count.

## 6. Operational requirements

- Follow [upgrade-m3-phase1.md](../runbooks/upgrade-m3-phase1.md) for existing
  installations:
  - provisioning before V006;
  - workers stopped across V008, which drops `report_job`;
  - the sandbox image pulled by digest;
  - `sandbox-check` healthy on every worker host.
- Separate secrets per login (owner via migrator, API, worker, operator). Run migrations
  as a separate step in production-like deployments.
- Worker hosts are dedicated (they have Docker access) and run on Linux with cgroups v2.
  Rootless Docker or Podman is recommended.
- Keep PostgreSQL statement and parameter logging at defaults (function arguments include
  lease tokens).
- Monitor the execution metrics (execution runbook §2), especially
  `sentinel_execution_rejections_results{reason}`. Treat `TOKEN_MISMATCH`,
  `NOT_LEASE_OWNER`, `CONTEXT_MISMATCH`, `ARTIFACT_MISMATCH` and `MISSING_ARTIFACT` as
  incidents.
- The FIXTURE scanner stays disabled outside development and CI (refused under production
  profiles and in the worker's `production` environment).

## 7. CI status

- **Remote CI is unverified.**
  - Local refs show `42c0299` (Slices 1–4) on `origin/main`, but no CI result was
    inspected: the GitHub CLI is not installed on the review machine, and no other GitHub
    API access was used.
  - The Slice 5 and closure changes are uncommitted and have never run in CI.
  - In particular, the new **`sandbox` job and the sandboxed E2E path have not yet run on a
    GitHub-hosted Linux runner.**
- **Jobs that must pass after the owner pushes** (`.github/workflows/ci.yml`, triggered by
  `push` to `main`, `pull_request` and `workflow_dispatch`):

  | Job (`jobs.<id>`) | Display name | What it proves |
  |---|---|---|
  | `api` | sentinel-api (Java 21) | Wrapper checksum, build, all Java unit, integration, contract and database privilege tests |
  | `worker` (matrix 3.12, 3.14) | sentinel-worker (Python …) | Lint, formatting, all non-sandbox Python tests incl. PostgreSQL and RabbitMQ |
  | `sandbox` | Sandbox isolation (real containers) | `sandbox-check` (13 controls) and every sandbox-marked test on Linux; no leftover containers |
  | `e2e` | End-to-end (API → outbox → RabbitMQ → worker) | Real worker process, sandboxed execution, cancellation, crash recovery |
  | `infrastructure` | Infrastructure configuration | Compose config, OPA policy tests, provisioning, broker and database role checks |
- **Expected jobs:**
  - `api` (Java, with Ryuk disabled);
  - `worker` (Python 3.12 and 3.14, `-m "not sandbox"`);
  - `sandbox` (`sandbox-check`, then `pytest -m sandbox` with `SENTINEL_REQUIRE_SANDBOX=1`,
    then a no-leftover check);
  - `e2e` (with the sandbox image pre-pulled);
  - `infrastructure` (Compose, OPA, provisioning, broker and database role checks).
- **Failure handling:**
  - image pulls retry with backoff and then fail explicitly;
  - a missing sandbox image fails the sandbox and E2E jobs; it is never skipped;
  - pytest exits nonzero when no tests are selected;
  - no step uses `continue-on-error`.

## 8. Migration and compatibility notes

- V001–V005 are unchanged.
- V006–V008 are forward-only. Rollback means restoring the backup.
- Slice 2 workers fail closed against V008: their reports error, the lease expires and the
  job is retried by new workers.
- V007 reports keep `result = NULL`.
- Jobs and scans that were RUNNING before V007 receive a deadline and an expired
  placeholder lease, so they are recovered like crashed jobs.

All of these paths are tested (`DatabaseUpgradePathIntegrationTests`).

## 9. M3 Phase 2 entry criteria

1. **Remote CI green** for the Slice 5 commit, including the `sandbox` and `e2e` jobs on
   Linux.
2. ~~F-03 resolved or explicitly accepted~~: **resolved** (verified checksum, section 4).
3. **Trust policy upheld:** Phase 2 integrates only reviewed scanners (Semgrep, Gitleaks,
   Trivy) as `Workload.TRUSTED_TOOL`, digest-pinned. Repository content is treated as
   untrusted input. No build or test execution of repository code.
4. **Decided before repository content enters a sandbox:**
   - how repositories are fetched (inside the sandbox, with short-lived scoped credentials,
     never the worker's);
   - per-scanner network needs (for example, Trivy's database: pre-provisioned offline,
     or an explicit egress allowlist);
   - output size limits for SARIF and SBOM, and whether this requires the object-storage
     evidence backend.
5. **Worker login secrets** stored in a secret manager, one login per worker deployment.
   Worker hosts dedicated.
6. **Threat-model update** per scanner (A5/A6), before each scanner is enabled.

## 10. Verdict

**READY WITH CONDITIONS.** (F-03 resolved in the closure; the remaining condition is remote
CI.)

- **Supporting evidence:**
  - all local suites pass (Java 609, E2E 8, Python 385, `sandbox-check` 13/13), with no
    skipped security tests;
  - the review found no Critical, High or Medium **defects**;
  - the four remediated findings are Low and have regression tests;
  - residual High risks are architectural, documented and gated by the trust policy and
    entry criteria; none can produce a false PASS today.
- **Condition:** remote CI must be green for the pushed Slice 5 and closure commit,
  especially the new `sandbox` job and the sandboxed `e2e` job on Linux. F-03, the second
  original condition, was resolved and verified in the closure.

M3 Phase 2 may begin once remote CI is green and while the trust policy is respected.
Execution of untrusted repository code remains **NOT READY** and requires a validated
hardened runtime or disposable VMs.

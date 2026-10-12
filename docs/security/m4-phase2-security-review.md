# M4 Phase 2: security review (historical policy re-evaluation)

- **Date:** 2026-10-11
- **Scope:**
  - closure of ADR-0013 (accepted on the owner's instruction after remote CI #14 on
    `00d5e78`);
  - M4 Phase 2: Flyway V010, `PolicyReevaluationService`, the changes to
    `PolicyEvaluationService`, `PolicyService`, `PolicyController` and
    `OrganizationPermission`, three new endpoints, three new JSON Schemas and OpenAPI.
- **Design:** [ADR-0014](../adr/0014-historical-policy-re-evaluation.md) (Proposed),
  [threat model](../threat-model/policy-engine.md#m4-phase-2-historical-re-evaluation),
  [decision semantics](../architecture/policy-decision-semantics.md#historical-re-evaluation).
- **Method:** repository inspection of the V009 invariants, evaluation functions, evidence
  of record and authorization before design; then an adversarial pass over the
  implementation covering cross-tenant evidence and policy references, policy
  substitution, TOCTOU, races, idempotency bypass, record overwrites, unauthorized replay,
  unbounded history, evidence leakage, decision-semantics drift, policy downgrade, evidence
  deletion or corruption, engine-version ambiguity and audit tampering.
- **Code:** uncommitted changes on top of `00d5e78`.

## Design decisions with security impact

| Decision | Reason |
|---|---|
| Separate append-only tables instead of extending `policy.evaluations` | The V009 trigger `require_evaluation_record` accepts a scan decision when any evaluation row of the scan has that decision. A historical row in the same table would satisfy it; `UNIQUE(scan_id)` and the FK to the pin would have to be dropped. Separation keeps every gate invariant intact |
| Same engine and evidence reader as the gate | No second set of decision semantics; precedence and fail-closed behavior are shared code |
| As-of = original decision time | Determinism and idempotency; avoids reporting every historical scan as stale |
| Database-computed inputs fingerprint in the identity | Scan + version alone would hide engine or evidence changes behind an old record |
| Fingerprint recomputed under the scan lock | Closes the window between reading the evidence and recording the result |
| Unusable stored policy is a request failure | Recording `POLICY_INVALID` for an explicitly requested version would add a meaningless permanent record |
| ADMIN may request | Non-gating; ADMIN already drafts versions. OWNER-only would add no protection |

## Confirmed defects

No exploitable defect was confirmed in the implemented code. One design issue was found
during the review and corrected before the final verification run:

| ID | Severity | Issue | Root cause | Impact | Correction | Verification |
|---|---|---|---|---|---|---|
| M4P2-1 | Low (availability) | The record function first locked the scan row `FOR UPDATE` | The strongest row lock was chosen to serialize re-evaluations | `FOR UPDATE` conflicts with the `FOR KEY SHARE` locks that foreign-key checks take, so any insert that references the scan (for example a lifecycle event) would wait for a running re-evaluation. No integrity impact; bounded to one request's duration | `FOR NO KEY UPDATE`: it still serializes re-evaluations of a scan (identity, limit) but does not conflict with foreign-key checks | Concurrency and idempotency tests pass with the weaker lock (8 concurrent requests, one record). No dedicated lock-mode test: it would test PostgreSQL's lock matrix, not our code |

## Reviewed without defects

| Area | Evidence |
|---|---|
| **Cross-tenant evidence references** | Evidence is read only through `policy.job_evidence(scan)`; the function checks that every reference is evidence of record of a COMPLETED job of this scan (`EVIDENCE_NOT_OF_RECORD`); FKs to `scan_jobs (id, scan_id)`, `job_reports`, `result_artifacts` |
| **Forged policy IDs** | Resolved within the scan's organization (404 like nonexistent); `POLICY_VERSION_NOT_FOUND` in the function; composite FK refuses even a superuser insert (`crossTenantScansPoliciesAndRecordsAreRejectedAsNotFound`) |
| **Policy substitution** | `POLICY_MISMATCH`; FK `(policy_version_id, policy_sha256)` → `(id, definition_sha256)`; the stored text is re-validated against schema, canonical form and digest (`policy-version-unusable`) |
| **TOCTOU** | One REPEATABLE READ snapshot for context, fingerprint, policy and evidence; recomputation under lock (`INPUTS_CHANGED`); single retry (`PolicyReevaluationServiceTests`); purge between requests yields a new record (`purgedEvidenceYieldsANewRecordAndNeverRewritesTheEarlierOne`) |
| **Race conditions** | Eight concurrent identical requests: one `RECORDED`, seven `EXISTING`, one row (`repeatedAndConcurrentIdenticalRequestsYieldExactlyOneRecord`) |
| **Idempotency bypass** | The identity is server-derived; the caller controls only the version id. Engine version is a constant; the as-of and fingerprint are recomputed by the database (`AS_OF_MISMATCH`, `INPUTS_CHANGED`) |
| **Record overwrites** | No UPDATE/DELETE grants; `refuse_change` triggers refuse UPDATE, DELETE and TRUNCATE for the superuser through ordinary statements; same identity with a different result refused (`NONDETERMINISTIC`) |
| **Unauthorized replay** | Re-evaluation requires `REEVALUATE_SCANS` (ADMIN); VIEWER and MEMBER 403, outsiders 404, nothing recorded; replay of an existing identity also requires that permission |
| **Unbounded history** | 100 records per scan under the scan lock; pages ≤ 100, page ≤ 10,000; one evidence query per record type per page |
| **Sensitive evidence leakage** | Responses carry codes, counts and digests only; requester stored as `user:<uuid>` (CHECK); E2E test asserts the synthetic secret is absent from the history |
| **Inconsistent decision semantics** | Shared `PolicyEvaluator`; the database re-checks precedence, evidence of record, violation attribution and PASS backstops against the requested policy; re-evaluation under the pinned version reproduces the original record (`reEvaluatingUnderThePinnedVersionReproducesTheOriginalRecord`) |
| **Policy downgrade** | A permissive version produces a `HISTORICAL`, `gating: false` record naming its version and digest; the scan's decision, pin, original record and active policy are unchanged (`anOriginalPassBecomesAHistoricalFailUnderAStricterPolicyWithoutChangingTheScan`, E2E). Residual: misuse of a historical PASS by consumers (H5) |
| **Evidence deletion or corruption** | Evidence rows are `ON DELETE RESTRICT`-referenced; purged content is `EVIDENCE_PURGED`; an altered stored result is `EVIDENCE_INTEGRITY_FAILED / RESULT_DIGEST`; missing artifacts `EVIDENCE_MISSING`; unsupported schema `EVIDENCE_SCHEMA_UNSUPPORTED` |
| **Engine-version ambiguity** | Engine version stored and part of the identity; another engine version is a distinct record (forgery test with `sentinelpipe-policy/9.9.9`) |
| **Audit-log tampering** | Append-only for runtime roles; reasons digest CHECK; `recorded_by` session user; superuser and schema owner remain trusted (H1) |
| **Gate isolation** | The trigger `require_evaluation_record` reads only `policy.evaluations`; no code path writes `scans`, `scan_jobs`, `scan_policies`, `project_assignments`, `evaluations` or `outbox_events` (state-snapshot equality test, E2E outbox count) |
| **Database privileges** | New definer functions with pinned `search_path`, not executable by PUBLIC, granted to `sentinel_api` only; the fingerprint helper is owner-only; worker and operator denied (`DatabasePrivilegeIntegrationTests`, `FlywayMigrationIntegrationTests`) |
| **Migration** | V001–V009 unchanged (Flyway checksum validation); upgrade paths from pre-V006, V007 and fresh installations apply V010 |

## Residual risks (owner decision required)

ADR-0014 H1 to H8: database superuser trust; API process trust; integrity, not
authenticity, of historical evidence; old engine versions not executable; historical
decisions relative to the chosen version's accepted limitations (an ADMIN can obtain a
non-gating historical PASS from a permissive version); purged evidence cannot be
re-verified and records have no erasure procedure; no production authorization for
hostile repositories; no rate limiting. ADR-0013 R1 to R10 remain as accepted.

## Final verification (after the last code modification)

Local run on Windows 11, Docker 29.7.2, JDK 25 (compiling for Java 21), Python 3.14.6:

| Check | Result |
|---|---|
| `./mvnw clean verify` (API, Testcontainers) | 788 tests, 0 failures, 0 errors, 0 skipped (756 before Phase 2) |
| `./mvnw verify -Pe2e` with the synthetic Trivy image lock | 16 tests, 0 failures (all E2E, including both Trivy tests and the new re-evaluation test on real Gitleaks evidence) |
| `pytest -m "not sandbox"` (worker, unchanged) | 776 passed, 6 skipped (Windows only: symlinks ×4, FIFO, reserved names), 175 deselected |
| `pytest -m sandbox` with `SENTINEL_TEST_TRIVY_DB_DIR` (Gitleaks, Semgrep, Trivy real containers) | 174 passed, 1 skipped (Windows: symlink), 0 failed |
| Ruff check and format | clean (82 files formatted) |
| actionlint 1.7.12 (container) | clean |
| `docker compose --env-file .env.example config --quiet` | clean |
| OPA 1.21.1 `check --strict` and `test` | clean; 10/10 |
| JSON Schemas (meta-validation, references, OpenAPI examples) | `ContractIntegrationTests`, `OpenApiContractTests` pass; bundled runtime schemas byte-identical to `packages/contracts` |
| Flyway | V001–V010 apply in order; checksums validate; V001–V009 files unchanged; upgrade paths pass |
| Gitleaks 8.30.1 (pinned digest) over the 29 changed or added files | no leaks |

The synthetic Trivy database and image were reused from the M4 Phase 1 verification
after checking that the database provenance is `SYNTHETIC_FIXTURE`, its advisories digest
is `159db707…` (the committed fixtures) and the locked image id is present locally. Not run
locally: the Linux-only tests (symbolic links, FIFOs, reserved Windows names). Remote CI
has not run M4 Phase 2.

## Verdict

**Ready for the owner's manual commit and remote CI.** No open defect; M4P2-1 corrected
before the final run. ADR-0014 stays **Proposed** until the owner reviews it and remote CI
succeeds. Residual risks H1 to H8 require the owner's acceptance.

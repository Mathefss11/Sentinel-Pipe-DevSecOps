# M4 Phase 1: security review (security policy engine)

- **Date:** 2026-10-11
- **Scope:**
  - ADR closure for M3: ADR-0010, ADR-0011, ADR-0012 (conditional acceptance recorded);
  - the Semgrep ruleset integrity follow-up from the Slice 3 review;
  - the M4 Phase 1 policy engine: Flyway V009, `dev.sentinelpipe.api.policy`, the changes
    to `ScanService`, `ScanLifecycleService`, `OrganizationPermission`, contracts and
    OpenAPI.
- **Design:** [ADR-0013](../adr/0013-security-policy-engine.md),
  [threat model](../threat-model/policy-engine.md),
  [decision semantics](../architecture/policy-decision-semantics.md).
- **Method:**
  - repository inspection of the decision model, lifecycle functions, evidence storage and
    authorization before design;
  - an adversarial pass over the implementation: policy tampering, evidence substitution,
    cross-tenant references, unauthorized activation, TOCTOU, concurrency, stale policies,
    severity confusion, fail-open defaults, decision forgery, unbounded complexity,
    error-message leakage, audit mutation and transaction boundaries;
  - every confirmed defect has a fix and a regression test; mutation spot check (disabling
    the evidence-binding gate makes `aViolationInDiscardedEvidenceNeverCountsAsFail`
    fail).
- **Code:** uncommitted changes on top of `f0f6a83`.

## Confirmed defects

| ID | Severity | Defect | Root cause | Impact | Fix | Regression tests |
|---|---|---|---|---|---|---|
| M4-1 | **Medium** | **A PASS (or FAIL) could be recorded without any policy evaluation.** The API's database role could call `lifecycle.complete_evaluation(scan, 'PASS', 'POLICY_EVALUATED')` for any EVALUATING scan whose jobs completed | V007 enforced "PASS needs completed jobs and reason `POLICY_EVALUATED`", but the reason was only a label: nothing tied it to an evaluation | Any code path or holder of the API database credentials could approve a scan without evidence being judged; no record would explain the decision. Not reachable over HTTP (no endpoint called it with PASS) | V009 replaces the function: INCOMPLETE only, and refused for policy-pinned scans (`POLICY_EVALUATION_REQUIRED`). PASS and FAIL exist only through `policy.record_evaluation`, which refuses inconsistent records (decision vs reasons, pinned policy, evidence of record, PASS backstops). `ScanLifecycleService.completeEvaluation` refuses PASS/FAIL before calling the database | `passAndFailCannotBeRecordedWithoutAnEvaluationRecord`, `aScanWithAFailedJobIsIncompleteAndNeverPass`, `forgedOrInconsistentEvaluationRecordsAreRefusedByTheDatabase` (6 forgeries + the old path) |
| M4-2 | Low | **The accepted job result is stored without a database-level binding to its digest.** `lifecycle.job_reports.result` is JSONB (normalized), `result_sha256` is the digest of the submitted text; nothing checks them against each other | ADR-0008 kept the document for audit, but nothing consumed it until M4 | A database-level edit of a stored result (for example its artifact references) would go unnoticed by the database. A consumer trusting the stored document could be misled | The engine re-canonicalizes the stored result (byte-compatible with the worker's canonical JSON, verified against CPython) and requires its SHA-256 to equal `result_sha256`; otherwise `EVIDENCE_INTEGRITY_FAILED / RESULT_DIGEST` (INCOMPLETE). It also requires the result to reference exactly the artifact of record | `evidenceThatNamesAnotherJobOrAStoredResultThatWasAlteredIsNeverTrusted` (real database edit), `aStoredResultThatDiffersFromItsDigestOrReferencesOtherEvidenceIsIncomplete`, `CanonicalJsonTests` |
| M4-3 | Low | **The Semgrep ruleset in the input archive was not verified inside the sandbox** (recorded as a review item by the Slice 3 review) | The shared input verification covers `repo/` only; worker configuration in `config/` was trusted after extraction | Tampering between the worker and the extracted file (stdin channel or sandbox) could run an altered ruleset and silently under-report | The worker passes `RULESET_SHA256` as `$4`; the script checks `sha256sum` of `config/rules.json` before Semgrep starts (exit 72) | `test_the_ruleset_is_verified_inside_the_sandbox_before_semgrep_runs`, real container `test_an_altered_ruleset_never_runs` (removed rule, truncated file, whitespace change) |
| M4-4 | Informational | ADR-0010 stated a 64 MiB Gitleaks tmpfs; the code and runbook have used 96 MiB since `a79c2c5` | Documentation not updated with the implementation | None (the tmpfs counts against the 512 MiB memory limit) | Corrected and recorded in the ADR-0010 acceptance | — |

## Design issues found and corrected before they shipped

- **Unbounded request buffering.** The first implementation read the policy body as a
  `String` and checked the 16 KiB limit afterwards. The body is now read with
  `readNBytes(16 KiB + 1)` and decoded as strict UTF-8
  (`oversizedOrNonUtf8BodiesAreRefusedWithoutBeingStored`).
- **Validator paths could echo submitted key names.** Violation locations are rebuilt from
  schema property names and indexes only (`violationsNeverEchoSubmittedValues`).
- **Wall-clock dependency in tests.** Trivy fixtures in unit tests used the real clock;
  they now use the fixed evaluation time.
- **A real-container test rebuilt the Semgrep command by position** and dropped the new
  `$4` (ruleset digest) argument. Under `set -u` the script then stopped with exit 2,
  which the adapter maps to a scanner error (fail closed), so the test's expected exit 74
  was not reached. Found by the full sandbox run; the test now keeps every trailing
  argument (`test_oversized_output_and_reports_fail_explicitly`).

## Reviewed without defects

| Area | Result |
|---|---|
| **Policy tampering** | Versions immutable for every runtime role; triggers refuse UPDATE, DELETE and TRUNCATE for the owner through ordinary statements; CHECK recomputes the digest; the engine re-validates text, canonical form and digest before use |
| **Cross-tenant references** | Membership checked before reading; 404 indistinguishable from nonexistent; composite foreign keys refuse a cross-tenant assignment, pin or evaluation even for direct SQL |
| **Unauthorized activation** | OWNER-only; ADMIN receives 403; outsiders 404; nothing recorded |
| **TOCTOU** | Policy pinned in the scan's creating transaction; the record must reference the pinned version; evaluation reads and records under the scan row lock while every job is terminal |
| **Concurrency** | Six concurrent evaluators record exactly one decision and one `SCAN_COMPLETED` event; eight concurrent version creations number 1 to 8 without gaps |
| **Evidence substitution and fencing** | Only the accepted result of the current epoch and its artifacts are read; superseded attempts' evidence is never used; context binding and evidence-of-record checks in the engine and the database |
| **Severity confusion** | Per-scanner vocabularies in the schema and engine; foreign or missing labels are INCOMPLETE |
| **Fail-open defaults** | No defaults in policy.v1 (every field required); unknown scanners, versions and fields refused; engine errors, invalid stored policies and missing metadata are INCOMPLETE; `EMPTY_INPUT` and `NO_SUPPORTED_FILES` never acceptable |
| **Decision precedence** | FAIL > INCOMPLETE > PASS in the engine, the record function and a CHECK |
| **Unbounded complexity** | No expression language; closed schema; 16 KiB; bounded reasons (≤ 512) and evidence (≤ 16) in the database |
| **Information leakage** | Fixed messages; reasons hold codes, scanner types and counts only; the E2E test checks the synthetic secret never reaches the record |
| **Audit record mutation** | Records immutable (privileges and triggers); reasons digest CHECK |
| **Transaction boundaries** | Pinning with scan creation; evaluation inputs, engine and record in one transaction under the scan lock; a database refusal rolls back everything and leaves the scan EVALUATING |
| **Database privileges** | New functions are `SECURITY DEFINER` with a pinned `search_path`, not executable by PUBLIC, granted to `sentinel_api` only; internal helpers owner-only; worker and operator denied (extended `DatabasePrivilegeIntegrationTests`, `FlywayMigrationIntegrationTests`) |

## Accepted residual risks (owner decision required)

- **R1 Compromised control plane:** the API process evaluates; it can record a consistent
  but false evaluation.
- **R2 Database owner / superuser:** can rewrite policies, evidence, digests and records
  consistently; no external anchor yet.
- **R3 Integrity, not authenticity:** a compromised sandbox or worker can produce false
  clean evidence for its own job.
- **R4 PASS is relative** to the policy's explicitly accepted limitations and to
  non-comprehensive scanners; with local fixtures PASS requires accepting
  `COMMIT_NOT_VERIFIED`.
- **R5 Single evaluation,** no re-evaluation; stale-at-evaluation evidence is INCOMPLETE.
- **R6 Activation without a two-person rule;** no security exceptions yet.
- **R7 Architecture deviation:** an in-process engine instead of the roadmap's OPA/Rego
  (ADR-0013 alternatives).

## Verification

Local run on Windows 11, Docker 29.7.2, JDK 25 (compiling for Java 21), Python 3.14.6:

| Check | Result |
|---|---|
| `./mvnw clean verify` (API, Testcontainers) | 732 tests, 0 failures, 0 errors, 0 skipped |
| `./mvnw verify -Pe2e` without the two Trivy tests | 13 tests, 0 failures |
| `pytest -m "not sandbox"` (worker) | 776 passed, 6 skipped (Windows: symlinks, FIFO, reserved names), 175 deselected |
| `pytest -m sandbox` (real containers) | 110 passed, 65 skipped (64 Trivy cases without a synthetic database, 1 symlink case), 0 failed |
| `ruff check`, `ruff format --check` | clean |
| `actionlint` 1.7.12, `docker compose --env-file .env.example config --quiet`, OPA `check --strict` and `test` | clean; OPA 10/10 |
| Gitleaks 8.30.1 (pinned image) over the 62 changed or added files | no leaks |

Not run locally: the two Trivy end-to-end tests and the Trivy real-container tests (they
need the synthetic database built by `scripts/trivy/build-fixture-db.sh`), and the
Linux-only tests (symbolic links, FIFOs, reserved Windows names). Remote CI has not run
M4 Phase 1.

## Final adversarial review (2026-10-11)

A second, focused pass after the owner approved the direction of ADR-0013 (an in-process
engine instead of OPA/Rego; ADR status unchanged: Proposed). It started from the
hypothesis that every way a row can change, not only every function, must be covered.

### Confirmed defects

| ID | Severity | Root cause | Impact | Minimal fix | Regression tests |
|---|---|---|---|---|---|
| M4-5 | **Medium** | The API keeps `INSERT` on `scans` and `scan_jobs` for creation and planning, and the CHECK constraints admit any *consistent* state. V007 and the first M4 pass constrained the functions, not the rows: nothing required a new row to be in its initial state | The API's database login could insert a scan born `COMPLETED / PASS / POLICY_EVALUATED`, with no jobs and no evaluation record (verified with the real API login before the fix), or a job born `COMPLETED` or leased. Not reachable over HTTP; requires the API's database credentials or a code defect. Same preconditions as M4-1, which the first pass fixed only for the function path | V009: a `BEFORE INSERT` trigger on `scans` and `scan_jobs` requires the initial state (`QUEUED`, no decision or reason, no timestamps, no lease) for every role but a superuser; an `AFTER INSERT/UPDATE` trigger on `scans` requires an evaluation record with the same decision whenever PASS or FAIL, reason `POLICY_EVALUATED`, or `COMPLETED` on a pinned scan is set, also inside `SECURITY DEFINER` functions (owner context) | `PolicyDecisionInvariantIntegrationTests`: `theApiRoleCannotInsertAScanThatIsBornWithADecisionOrAlreadyRunning`, `theApiRoleCannotInsertAJobThatIsBornCompletedOrLeased`, `evenTheOwnerContextCannotSetAPolicyDecisionWithoutAMatchingEvaluation` |
| M4-6 | Low | The engine checked `coverage.complete` against the policy, but not that an incomplete coverage is explained by a limitation code (a worker guarantee, not an engine check) | Under a policy with `require_complete_coverage: false`, a document with `complete = false` and only accepted inherent limitations would PASS with an unnamed gap. Requires inconsistent evidence (worker defect or compromise for its own job) | `EVIDENCE_INCONSISTENT / COVERAGE` when `complete = false` without a gap-explaining limitation, or when `FILES_SKIPPED`, `FILES_NOT_ANALYZED` (and, for Trivy, its nine incompleteness codes) appear with `complete = true` | `incompleteCoverageWithoutAnExplainingLimitationIsInconsistentEvenUnderALaxPolicy`, `anExplainedGapIsAcceptedOnlyWhenThePolicyNamesItsLimitation` |
| M4-7 | Informational | Documentation overstated an invariant | ADR-0013, the API doc, `DecisionReason` and `scan.schema.json` said every decision of a pinned scan has an evaluation record; a pinned scan cancelled or failed during execution is `INCOMPLETE` with its own reason and no record (correct, fail-closed behavior) | Wording corrected to "every **COMPLETED** pinned scan" | — |

V009 has not been released or applied outside tests, so the fix is in V009 itself; no
applied migration was changed.

### Reviewed without new defects

| Area | Evidence |
|---|---|
| PASS/FAIL only with a persisted evaluation | Function path (M4-1), row path (M4-5) and owner context (trigger) covered; `record_evaluation` refuses six forgeries; concurrent evaluators record one decision |
| Activation versus scan creation | 24 concurrent scan requests and 12 concurrent activations of 3 versions: every scan has exactly one pin, to the assignment row it names, in its own project; a second pin and any pin update are refused (`everyScanIsPinnedToExactlyOneVersionWhileActivationsRaceWithScanCreation`). Activation locks the project row; the scan insert's foreign-key check waits for it, so each scan sees a committed assignment |
| FAIL never hidden, never from invalid evidence | Precedence tests (unit and database); violations in discarded evidence are INCOMPLETE; the mutation check still holds |
| Limitation acceptance | `COMMIT_NOT_VERIFIED`, `PARSE_COMPLETENESS_UNVERIFIED` and the S3-8 code (`PYPI_NAME_MATCHING_UNVERIFIED`) are acceptable only by explicit listing, visible in the definition and its digest; S3-8 with complete coverage required is always INCOMPLETE; every incompleteness is now a named limitation (M4-6) |
| Cross-tenant access and forged references | Policy and evaluation reads (404 for outsiders), activation (API and composite keys), forged pins (composite keys refuse every mix, even for a superuser), forged evaluation records (`POLICY_MISMATCH`, `EVIDENCE_NOT_OF_RECORD`) |
| Canonicalization and parsing | Exact inclusive bounds for every number; `1e2`, `0.0` and 26-digit integers refused; `-0` canonicalizes to `0`; 6,000-deep nesting refused as a validation error; Unicode escapes normalize before validation and look-alike characters are refused; duplicate keys, unknown fields, oversized and non-UTF-8 bodies refused; stored digest re-verified |
| Transactions, triggers, idempotency | Evaluation under the scan row lock in one transaction; a refused record rolls back completely; records and pins immutable (UPDATE, DELETE, TRUNCATE refused); a second evaluation is `NOT_EVALUATING` |
| Semgrep ruleset check | The change adds one worker constant as `$4` and two script lines that can only fail (exit 72). No change to the sandbox policy, mounts, environment, image or the shared input fragment; isolation tests and all 24 Semgrep real-container tests pass |
| M3 ADR acceptances | ADR-0010, ADR-0011 and ADR-0012 keep every documented residual risk and their production restrictions (synthetic fixtures only, refused in production by worker and API, runc not a boundary for hostile content, no automatic Trivy updater, S3-8 not implemented) |

### Residual risks added by the final review

- **R8 Transparency of accepted limitations.** An evaluation record does not list which
  accepted limitations the evidence carried; a PASS consumer must read the pinned policy
  (its digest is in the record) to see, for example, that `COMMIT_NOT_VERIFIED` was
  accepted. Recording accepted limitations as informational entries is proposed for a later
  slice.
- **R9 Trusted superuser.** The new triggers exempt superusers (needed by test fixtures and
  consistent with R2); the schema owner can also disable triggers.
- **R10 Historical rows.** The invariant triggers check changes from V009 onward; rows
  written before V009 are not re-validated (in this pre-release project no PASS or FAIL
  could exist before M4).

### Final verification (after the last modification)

| Check | Result |
|---|---|
| `./mvnw clean verify` | 756 tests, 0 failures, 0 errors, 0 skipped |
| `./mvnw verify -Pe2e` with the synthetic Trivy image lock | 15 tests, 0 failures (all E2E, including both Trivy tests) |
| `pytest -m "not sandbox"` | 776 passed, 6 skipped (Windows only: symlinks ×4, FIFO, reserved names), 175 deselected |
| `pytest -m sandbox` with `SENTINEL_TEST_TRIVY_DB_DIR` | 174 passed, 1 skipped (Windows: symlink), 0 failed |
| Trivy real-container and integration tests alone, `SENTINEL_REQUIRE_SANDBOX=1` | 64 passed |
| Ruff check and format; actionlint 1.7.12; Compose config; OPA check and test | clean; OPA 10/10 |
| Bundled runtime schemas | byte-identical to `packages/contracts` |
| Gitleaks 8.30.1 (pinned image) over every changed or added file | no leaks |

The synthetic Trivy database was not rebuilt (that needs the Go module proxy): a database
built earlier on 2026-10-11 by `scripts/trivy/build-fixture-db.sh` was reused after checking
that its provenance is `SYNTHETIC_FIXTURE` and its advisories digest equals the committed
fixtures (`159db707…`). The image was rebuilt locally with `sentinel-worker trivy-image
build` and matched an earlier independent build. Remote CI has not run M4 Phase 1.

## Verdict

**Ready for the owner's manual commit and remote CI.** No open defect remains: M4-1 to M4-3
and M4-5 to M4-6 are fixed with regression tests; M4-4 and M4-7 are corrected. The direction
of ADR-0013 (in-process engine instead of OPA/Rego) is approved by the owner; the ADR stays
**Proposed** until remote CI succeeds and the owner accepts it. Residual risks R1 to R10
remain and require the owner's acceptance.

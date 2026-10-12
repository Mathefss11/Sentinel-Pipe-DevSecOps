# M4 Phase 3: security review (security exceptions and independent approval)

- **Date:** 2026-10-11
- **Scope:**
  - acceptance of ADR-0014 (owner decision; the remote CI run is owner-reported, see below);
  - M4 Phase 3: Flyway V011, `ExceptionRequestService`, `EffectiveGateService`,
    `OriginalEvaluationVerifier`, `ExceptionController`, the engine's blocking-finding
    assessment (`PolicyEvaluator.assess`), the permissions `REQUEST_EXCEPTIONS` and
    `DECIDE_EXCEPTIONS`, eight endpoints, five JSON Schemas and OpenAPI.
- **Design:** [ADR-0015](../adr/0015-security-exceptions-and-independent-approval.md)
  (Proposed), [threat model](../threat-model/policy-engine.md#m4-phase-3-security-exceptions),
  [decision semantics](../architecture/policy-decision-semantics.md#security-exceptions-and-the-effective-gate).
- **Method:** repository inspection before design (V009/V010 invariants, evaluator, evidence
  of record, memberships and permissions, OpenAPI and test conventions); then an
  adversarial pass over the implementation covering self-approval, forged identities,
  cross-tenant access, SQL privilege bypasses, state-machine manipulation, races, TOCTOU
  around expiry, finding, evidence and policy substitution, approval replay, unauthorized
  revocation, history tampering, secret leakage, gate confusion, denial of service and
  superuser trust.
- **Code:** uncommitted changes on top of `c596a38`.

## Baseline verified before the change

| Item | Evidence |
|---|---|
| HEAD | `c596a38` "feat(policy): add immutable historical policy re-evaluation (M4 Phase 2)", working tree clean |
| ADR-0013 | Accepted (remote CI #14 on `00d5e78`, owner-reported in that ADR) |
| ADR-0014 | Proposed before this change; now Accepted on the owner's instruction |
| Remote CI for `c596a38` | **Not independently verified.** The only local CI log archive (`logs_103386494867.zip`, git-ignored, two identical copies) is for commit `7b2c42f` (M3): its checkout step prints `7b2c42fdb5b991a88f160ce95ed52e575e7aa3b8` and the API job ran 621 tests. ADR-0014 records the M4 Phase 2 run as owner-reported, without a run number |
| Violation codes | The engine's only VIOLATION reason is `BLOCKING_FINDINGS_EXCEEDED` (a per-scanner count), so an exception must remove identified findings from the count rather than waive a reason |

## Design decisions with security impact

| Decision | Reason |
|---|---|
| Exceptions bind to one finding of one scan's ORIGINAL evaluation | No verified cross-scan finding identity exists (fingerprints are location-based and worker-computed); a recurring exception would silently cover new evidence |
| The database derives the binding and finds the fingerprint in the stored bytes | A caller (or a compromised API) cannot name a fingerprint that is not exactly one blocking finding of the evaluated evidence |
| Two-person rule in API, function and CHECK | The CHECK `actor <> requested_by` holds for every writer using ordinary statements, including the owner and superusers |
| Approver role verified by a trigger against memberships | The role recorded with a transition cannot be asserted by the caller |
| Append-only transitions with `(request, seq)` key and self-referencing FK | One way out of each state, no return to REQUESTED, terminal states final, deterministic concurrency |
| Expiry derived on read, database clock only | No scheduler can fail to run; no client-supplied or backdated time |
| Effective gate computed, never stored | No cached authorization survives expiry or revocation |
| `RISK_ACCEPTED` instead of `PASS` | Accepted risk cannot be confused with compliance by a consumer testing for PASS |
| Reproduce the original evaluation before applying exceptions | Evidence purged, altered or substituted after approval closes the gate (fail closed) |
| `ENGINE_VERSION` unchanged | The engine additionally returns the identities of findings it already counted; decisions and reasons are identical (unit-tested) |

## Confirmed defects

Two defects were found during the adversarial pass and corrected before the final
verification run. Neither is exploitable for privilege escalation or gate bypass.

| ID | Severity | Issue | Root cause | Impact | Correction | Regression coverage |
|---|---|---|---|---|---|---|
| M4P3-1 | Low (availability) | A transition racing the expiry, or the 5-minute approval window, answered `500` | `policy.transition_exception` checks expiry with `clock_timestamp()`, then the trigger stamps a later `clock_timestamp()` and the CHECK `occurred_at < expires_at` refuses the row (SQLSTATE 23514), which reached the generic handler | A client saw an internal error instead of `409 exception-expired`; nothing was written (fail closed) | `ExceptionRequestService.write` maps the named CHECK violations to `409 exception-expired` / `exception-expires-too-soon` and the lifetime CHECK to `400 expiresAt`; any other refusal is still surfaced unchanged | `ExceptionRequestServiceTests` (expiry, approval window, other refusals not hidden) |
| M4P3-2 | Low (availability) | Justification or rationale text accepted by the API's pattern but refused by PostgreSQL's `[[:cntrl:]]` class answered `500` | The two character classes are defined by different libraries (Java `\p{Cc}`, `\p{Zl}`, `\p{Zp}` vs. the database locale) | Internal error instead of `400`; nothing written | `exception rejected: INVALID_ARGUMENTS` from either function is mapped to `400` on the text field; the API pattern was also tightened from `\p{Cntrl}` (ASCII only) to Unicode control and separator categories | `ExceptionRequestServiceTests` (`textTheDatabaseRefusesIsAValidationError...`); integration test with a BEL character (`400`) |

## Reviewed without defects

| Area | Evidence |
|---|---|
| **Self-approval** | API `403 self-decision-forbidden` before any database call; `policy.transition_exception` returns `SELF_DECISION`; CHECK `ck_exception_transitions_independent` refuses a superuser's direct insert (`nobodyApprovesOrRejectsTheirOwnRequestWhateverTheirRole`, `ownerSelfApprovalThroughDirectSqlIsRefusedByTheDatabase`) |
| **Forged identities** | Requester and actor are the caller's internal identity; bodies with `requestedBy`, `actor`, `approvedBy`, `status`, `evaluationId`, `ruleId` are `400`; a token without identity is `404`; recorded actor equals `user:<identity>` (`identitiesAreServerDerivedAndCannotBeSpoofed`) |
| **Role checks** | VIEWER and MEMBER cannot request or decide (`403`), ADMIN cannot decide or revoke (`403`), the trigger refuses a role the actor does not hold (`NOT_AUTHORIZED` for an ADMIN claiming OWNER and for a non-member) |
| **Cross-tenant access** | Non-members `404` for every operation; a request is reachable only through its own scan; another tenant's OWNER is `NOT_AUTHORIZED` in the database; the trigger and, with the trigger disabled, the composite foreign keys refuse a cross-tenant row (`crossTenantReferencesAreRejectedAsNotFound`, `EndpointProtectionCoverageTests`) |
| **SQL privilege bypass** | No INSERT, UPDATE or DELETE for `sentinel_api`; worker and operator have no access; helpers owner-only; definer functions with pinned `search_path` (`DatabasePrivilegeIntegrationTests`, `FlywayMigrationIntegrationTests`) |
| **State machine** | Second decision refused by the primary key, leaving an unentered state by the self-referencing FK, a return to REQUESTED by the CHECK; rejected and withdrawn requests cannot be approved (`duplicateRequestsNeverBypassApproval...`, `onlyTheRequesterWithdraws...`) |
| **Races** | Four concurrent decisions by two OWNERs: exactly one transition, the others `invalid-exception-transition` (`concurrentDecisionsProduceExactlyOneTransition`); requests serialized on the evaluation row (duplicates and limit) |
| **TOCTOU around expiry** | Database time stamped by trigger; CHECK `occurred_at < expires_at`; a backdated superuser insert is refused; status derived at read; gate computed in one snapshot with `validUntil` (`approvalAfterOrCloseToExpiry...`, `expiredExceptionsStopApplying...`) |
| **Finding substitution** | Random, non-blocking, other-scanner and other-scan fingerprints are `409 finding-not-exceptionable` and `FINDING_NOT_ELIGIBLE` in the function; a superuser cannot insert a request whose rule, severity or fingerprint differ from the evidence (`FINDING_NOT_VERIFIED`) (`forgedOrNonBlockingFingerprintsAreRejected...`) |
| **Evidence substitution** | Altered or purged evidence: request and approval refused (`evaluation-not-reproducible`, `EVIDENCE_UNAVAILABLE`); an approved exception stops applying (`ORIGINAL_NOT_REPRODUCIBLE`) (`alteredOrPurgedEvidence...`) |
| **Policy substitution** | Binding to the pinned version, digest and engine; a later activation or a permissive historical re-evaluation changes nothing; a request cannot reference a historical record (`policyOrFindingIdentityChangesNeverExpand...`) |
| **Scope** | One finding never hides another: two secrets with one excepted stay FAIL; an unexcepted Semgrep violation keeps the gate FAIL (`oneExceptionNeverHidesAnotherViolation`) |
| **Incomplete evidence** | Missing evidence, scanner failure, incomplete coverage and running scans are `scan-not-exceptionable`; FAIL with incomplete conditions and all violations excepted is `INCOMPLETE` (`missingIncompleteOrFailedEvidence...`, `anExceptedViolationNeverTurns...`) |
| **Approval replay and unauthorized revocation** | Repeated approve or revoke `409`; ADMIN, MEMBER, VIEWER revoke `403`; outsiders `404` |
| **History tampering** | UPDATE and DELETE denied to the API login; refused for a superuser by `policy.refuse_change` (`runtimeRolesCannotRewriteHistory`) |
| **Secret leakage** | Records, gate results and errors contain identifiers, digests and codes; no paths or evidence; E2E asserts the real synthetic token is absent; logs carry ids and outcomes only |
| **Gate confusion** | `RISK_ACCEPTED` with `exceptionBased: true`; PASS only for an original PASS; JSON Schema `if/then` pins these combinations; `Cache-Control: no-store` |
| **Original decision and historical records** | State snapshot (scan, jobs, pin, evaluation, evidence, historical records, events, evidence digests, outbox and job counts) equal before and after the full lifecycle |
| **No dispatch** | No scan job or outbox event is created by any exception operation (integration and E2E) |
| **Migration** | V001 to V010 unchanged (checksums validate); V011 applies on fresh installations, after V005 (legacy) and after V007; a V010 installation with V009 and V010 records accepts exceptions bound to them after the upgrade (`v011BindsExceptionsToRecordsWrittenUnderV009AndV010`) |

## Residual risks (owner decision required)

ADR-0015 E1 to E10: database superuser and schema owner trust; API process trust (a
compromised API can approve in the name of any current OWNER other than the requester); one
person with two identities; approvals surviving membership changes; dependence on the
database clock (rollback); finding integrity, not authenticity, and worker-computed
fingerprints; user-entered justification text; no rate limiting on gate computation;
single-OWNER organizations; no production authorization. ADR-0013 R1 to R10 (except that
R6's "no security exceptions" is now addressed; the two-person rule for activation is
still open) and ADR-0014 H1 to H8 remain as accepted.

## Final verification (after the last code modification)

Local run on Windows 11, Docker 29.7.2, JDK 25.0.4 (compiling for Java 21), Python 3.14.6:

| Check | Result |
|---|---|
| `./mvnw clean verify` (API, Testcontainers) | 831 tests, 0 failures, 0 errors, 0 skipped (788 before Phase 3) |
| `./mvnw verify -Pe2e` with the synthetic Trivy image lock | 17 tests, 0 failures (16 before; adds the real-Gitleaks exception test) |
| `pytest -m "not sandbox"` (worker, unchanged) | 776 passed, 6 skipped (Windows only: symlinks, FIFO, reserved names), 175 deselected |
| `pytest -m sandbox` with `SENTINEL_TEST_TRIVY_DB_DIR` (Gitleaks, Semgrep, Trivy real containers) | 174 passed, 1 skipped (Windows: symlink), 0 failed; no sandbox container left behind |
| Ruff check and format | clean (82 files) |
| actionlint 1.7.12 (pinned container) | clean |
| `docker compose --env-file .env.example config --quiet` | clean |
| JSON Schemas and OpenAPI (meta-validation, references, examples, endpoint parity) | `ContractIntegrationTests`, `OpenApiContractTests` pass; responses validated against the new schemas in integration and E2E tests |
| Flyway | V001 to V011 apply in order; checksums validate; V001 to V010 files unchanged; upgrade paths (pre-V006, V007, V010 with V009/V010 records) pass |
| Gitleaks 8.30.1 (pinned digest) over the 32 changed or added files | no leaks |

New tests: `SecurityExceptionIntegrationTests` (21), `ExceptionRequestServiceTests` (4), two
`PolicyEvaluatorTests`, one upgrade-path test, one E2E test, and extended privilege,
Flyway, authorization-matrix and endpoint-coverage tests.

The synthetic Trivy database and image were reused from the M4 Phase 2 verification after
checking that the database provenance is `SYNTHETIC_FIXTURE`, its advisories digest is
`159db707…` (the committed fixtures) and the locked image id is present locally. Not run
locally: the Linux-only worker tests. OPA was not exercised (no policy or Compose change).
Remote CI has not run M4 Phase 3.

## Verdict

**Ready for the owner's manual commit and remote CI.** No open defect; M4P3-1 and M4P3-2
were corrected before the final run. ADR-0015 stays **Proposed** until the owner reviews it
and remote CI succeeds. Residual risks E1 to E10 require the owner's acceptance; in
particular E2: the two-person rule holds against honest API code and runtime database
roles, not against a compromised control plane or a database superuser.

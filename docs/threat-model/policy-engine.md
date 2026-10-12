# Threat model: security policy engine (M4 Phases 1 to 3)

- **Scope:** policy versions, activation, scan pinning, evaluation and evaluation records
  ([ADR-0013](../adr/0013-security-policy-engine.md)); Flyway V009; the
  `dev.sentinelpipe.api.policy` module.
- **Method:** STRIDE per data flow; each threat names its control and its test.
- **Review:** [M4 Phase 1 security review](../security/m4-phase1-security-review.md).

## Data flows and trust boundaries

```text
 tenant user ──HTTPS(JWT)──▶ API: create version (ADMIN) / activate (OWNER) / read
                               │  strict parse, closed schema, canonical digest
                               ▼
                         PostgreSQL policy.* (append-only, CHECK digests, composite FKs)
                               ▲
 scan request (MEMBER) ──▶ API: scans INSERT + policy.pin_scan_policy (same transaction)

 worker (own DB login, lease) ──▶ worker.put_evidence / worker.submit_result (ADR-0008)
                                       │ evidence of record (current epoch only)
 supervisor (API process) ─────────────┘
   lock scan (FOR UPDATE SKIP LOCKED) → policy.evaluation_context + policy.job_evidence
   → PolicyEvaluator (pure) → policy.record_evaluation (DB re-checks, completes scan)
```

Trust boundaries: (1) the HTTP caller; (2) the worker and sandbox, trusted for their own
job only; (3) the API process (the evaluator); (4) the database owner (fully trusted,
not defended against).

## Threats

| ID | STRIDE | Threat | Controls | Tests | Residual |
|---|---|---|---|---|---|
| P1 | Tampering | Policy text altered after creation to weaken the gate | Versions immutable (no grants, triggers refuse UPDATE/DELETE/TRUNCATE); CHECK recomputes the digest; the engine re-validates the stored text, its canonical form and digest before use (`POLICY_INVALID`) | `policyRecordsAreImmutableEvenForTheDatabaseOwnerThroughOrdinaryStatements`, `storedDefinitionsAreReverifiedBeforeUse` | The owner can disable triggers and rewrite text and digest consistently (R2) |
| P2 | Elevation | A non-owner activates a lax policy | `ACTIVATE_POLICY` is OWNER-only; drafting (ADMIN) cannot activate | `onlyAnOwnerActivatesAndTheActivationIsReadableAndIdempotent`, `AuthorizationMatrixTests` | A single OWNER can draft and activate alone (no two-person rule yet) |
| P3 | Spoofing / info disclosure | Cross-tenant policy reference by UUID | Membership check before reading; 404 indistinguishable from nonexistent; `assign_project_policy` compares organizations; composite FKs | `aPolicyVersionOfAnotherTenantCanNeverBeActivated`, `EndpointProtectionCoverageTests` | — |
| P4 | Tampering (TOCTOU) | Policy changed between scan request and evaluation | The version is pinned in the scan's creating transaction; the record must name the pinned version (`POLICY_MISMATCH`, FK to `scan_policies`) | `aScanIsEvaluatedAgainstThePolicyInForceWhenItWasRequestedAndTheRecordStaysAuditable` | — |
| P5 | Tampering | Evidence substitution: another job's, tenant's or attempt's evidence used | Evidence read only from the accepted result of the job's current epoch; result re-canonicalized to its digest; context binding; DB checks every reference is evidence of record | `evidenceThatNamesAnotherJobOrAStoredResultThatWasAlteredIsNeverTrusted`, `evidenceFromASupersededLeaseIsNeverEvaluated`, `forgedOrInconsistentEvaluationRecordsAreRefusedByTheDatabase` | A worker can still produce false evidence for its own job (R3) |
| P6 | Tampering | Stored evidence or stored result altered at rest | Evidence bytes: CHECK + re-verification; result: re-canonicalized and compared with `result_sha256` | `anEvidenceDigestMismatchIsIncomplete`, `aStoredResultThatDiffersFromItsDigestOrReferencesOtherEvidenceIsIncomplete` | Consistent rewrite of content and digest by the owner (R2) |
| P7 | Repudiation / tampering | Decision forged without evaluation (old `complete_evaluation` path) | V009: `complete_evaluation` refuses PASS/FAIL and pinned scans; PASS/FAIL only via `record_evaluation` with backstops | `passAndFailCannotBeRecordedWithoutAnEvaluationRecord`, `forgedOrInconsistentEvaluationRecordsAreRefusedByTheDatabase` | A compromised API process can record a consistent but false evaluation (R1) |
| P8 | Tampering | Audit record changed or deleted | Records immutable for every runtime role; triggers; reasons digest CHECK | `aScanIsEvaluatedAgainstThePolicyInForceWhenItWasRequestedAndTheRecordStaysAuditable`, `DatabasePrivilegeIntegrationTests` | Owner (R2); no external append-only sink |
| P9 | Elevation (fail open) | Missing, failed, stale, unsupported or unparseable evidence read as clean | Six gates; every gap is an explicit INCOMPLETE reason; `EMPTY_INPUT`/`NO_SUPPORTED_FILES` never acceptable; unknown severities never guessed; engine errors and invalid stored policies recorded as INCOMPLETE | `PolicyEvaluatorTests` (26) | PASS depends on what the policy explicitly accepts (R4) |
| P10 | Tampering | A violation hidden by an incomplete scanner, or a violation derived from bad evidence | Precedence FAIL > INCOMPLETE > PASS (engine, function and CHECK); violations only from evidence that passed gates 1–5 | `aConfirmedViolationIsFailEvenWhenAnotherScannerIsMissingAndBothAreRecorded`, `aViolationInDiscardedEvidenceNeverCountsAsFail` | — |
| P11 | Denial of service | Huge or deeply complex policies; huge request bodies | 16 KiB bound read before parsing; closed schema (≤ 3 scanners, ≤ 24 limitations); no expressions | `oversizedOrNonUtf8BodiesAreRefusedWithoutBeingStored`, `oversizedDefinitionsAreRejectedBeforeParsing` | Evaluation reads ≤ 16 × 1 MiB evidence per scan in memory |
| P12 | Info disclosure | Error messages or reasons echo request values or finding content | Fixed messages; locations rebuilt from schema names; reasons hold codes and counts only; no exception chains with content | `violationsNeverEchoSubmittedValues`, `invalidDefinitionsAreRejectedWithoutEchoingTheirContent`, `reasonsNeverCarryFindingContent`, E2E secret check | — |
| P13 | Tampering (race) | Concurrent evaluators record two inconsistent decisions | Scan row lock (`FOR UPDATE SKIP LOCKED`), status check under lock, unique evaluation per scan | `concurrentEvaluationsRecordExactlyOneDecision` | — |
| P14 | Spoofing | Severity scale confusion (a Trivy label in Semgrep evidence) | Per-scanner vocabularies in the policy schema and in the engine | `scannerSpecificVocabulariesAreEnforced`, `unsupportedScannerSeveritiesAreReportedNeverGuessed` | — |
| P15 | Tampering / repudiation | A runtime role inserts a scan born `COMPLETED / PASS`, or a job born completed or leased (final review M4-5) | `BEFORE INSERT` triggers require the initial state for every role but a superuser; an `AFTER INSERT/UPDATE` trigger requires a matching evaluation record for any policy decision, also in owner context | `PolicyDecisionInvariantIntegrationTests` | Superusers exempt (R2) |
| P16 | Elevation (fail open) | Evidence reports incomplete coverage without naming the gap, and a lax policy passes it (final review M4-6) | Consistency check: incomplete coverage needs a gap-explaining limitation; gap-implying limitations need incomplete coverage | `incompleteCoverageWithoutAnExplainingLimitationIsInconsistentEvenUnderALaxPolicy` | — |
| P17 | Tampering (race) | A scan created while an activation commits is pinned to no version, two versions, or another project's | Activation locks the project row; the scan's foreign-key check waits; one immutable pin per scan, written once | `everyScanIsPinnedToExactlyOneVersionWhileActivationsRaceWithScanCreation` | — |

## Residual risks

- **R1 Compromised control plane.** The API process is the evaluator. It cannot record an
  internally inconsistent decision, but it can record a consistent, false one (for
  example PASS with clean-looking reasons over evidence it chose not to read). Needs
  independent re-verification or signed evaluation (future).
- **R2 Database owner / superuser.** Can rewrite policies, evidence, digests and records
  consistently. Out of scope until signed evidence and an external append-only audit
  sink exist (M6/M7).
- **R3 Integrity, not authenticity.** A compromised sandbox or worker can submit
  plausible clean evidence for its own job (ADR-0008, ADR-0009).
- **R4 PASS is relative.** It reflects the limitations the policy accepts and scanners
  that are not comprehensive; local fixtures require accepting `COMMIT_NOT_VERIFIED`.
- **R5 Single evaluation.** One gate evaluation per scan; evidence that is stale when
  evaluated (for example after a supervisor outage) leaves the scan INCOMPLETE; rescan.
  Since M4 Phase 2, a non-gating historical re-evaluation can show what another policy
  version says about the same evidence, but it never changes the gate decision.
- **R6 Clocks.** Evidence age uses the database clock; Trivy database age also uses
  worker-reported metadata, bounded by the database clock.
- **R7 Accepted limitations are not listed in the record.** A PASS consumer must read the
  pinned policy (its digest is in the record) to see which limitations were accepted.

## M4 Phase 2: historical re-evaluation

Scope: [ADR-0014](../adr/0014-historical-policy-re-evaluation.md), Flyway V010,
`PolicyReevaluationService`, the three new endpoints. Review:
[M4 Phase 2 security review](../security/m4-phase2-security-review.md).

```text
 ADMIN/OWNER ──HTTPS(JWT)──▶ API: authorize on the scan's organization (404 / 403)
   │ resolve policy version within that organization (404 otherwise)
   ▼ REPEATABLE READ snapshot: policy.historical_context (as-of, inputs fingerprint)
   │   + policy version + policy.job_evidence
   ▼ PolicyEvaluator (same engine) ──▶ policy.record_historical_evaluation
       lock scan (NO KEY UPDATE), recompute fingerprint, re-check record, append
```

| ID | STRIDE | Threat | Controls | Tests | Residual |
|---|---|---|---|---|---|
| H-T1 | Info disclosure / spoofing | Re-evaluating another tenant's scan by UUID | Membership checked on the scan's organization before reading; 404 like nonexistent | `crossTenantScansPoliciesAndRecordsAreRejectedAsNotFound`, `EndpointProtectionCoverageTests` | — |
| H-T2 | Spoofing | Forged policy reference (another tenant's version) | Version resolved within the scan's organization; function returns `POLICY_VERSION_NOT_FOUND`; composite FK refuses even a superuser insert | same | — |
| H-T3 | Tampering | Policy substitution (version id with another digest) | `POLICY_MISMATCH` in the function; FK `(policy_version_id, policy_sha256)` | `historicalRecordsCannotBeChangedAndTheDatabaseRefusesForgedOnes` | — |
| H-T4 | Tampering | Caller-supplied evidence, findings, decision or as-of | Request schema has only `policyVersionId`; unknown properties 400; as-of and fingerprint recomputed by the database (`AS_OF_MISMATCH`, `INPUTS_CHANGED`) | `scannerFindingsOrEvidenceAreNeverAcceptedFromTheCaller`, forgery test | — |
| H-T5 | Tampering (TOCTOU) | Evidence changes (purge, edit) between reading and recording | Inputs and fingerprint read in one snapshot; fingerprint recomputed under the scan lock; one retry, then 409 | `PolicyReevaluationServiceTests`, `purgedEvidenceYieldsANewRecordAndNeverRewritesTheEarlierOne` | — |
| H-T6 | Tampering (race) | Concurrent requests write duplicates or different answers | Scan row lock, identity unique constraint, `EXISTING`, `NONDETERMINISTIC` | `repeatedAndConcurrentIdenticalRequestsYieldExactlyOneRecord` | — |
| H-T7 | Tampering / repudiation | Historical record overwritten or deleted; original decision rewritten | Separate append-only tables; no UPDATE/DELETE grants; immutability triggers; the gate tables and scan are never written | `anOriginalPassBecomesAHistoricalFailUnderAStricterPolicyWithoutChangingTheScan`, `DatabasePrivilegeIntegrationTests` | Superuser (H1) |
| H-T8 | Elevation | A historical PASS used as approval (policy downgrade) | `gating: false`, `evaluationType: HISTORICAL`, version and digest in the record; scan decision unchanged; decision trigger reads only `policy.evaluations` | first test above | Consumers must use only the scan decision (H5) |
| H-T9 | Elevation | MEMBER or VIEWER triggers re-evaluations | `REEVALUATE_SCANS` (ADMIN) | `ownersAndAdminsMayRequestViewersAndMembersMayNotAndOutsidersSeeNothing`, `AuthorizationMatrixTests` | — |
| H-T10 | Denial of service | Unbounded history or records | 100 records per scan (database); pages ≤ 100, page ≤ 10,000 | `unfinishedScansUnknownForeignOrUnusableVersionsAndTheLimitFailExplicitly`, history test | No rate limiting (H8) |
| H-T11 | Info disclosure | Evidence or secrets leak through history or audit fields | Codes, counts and digests only; requester as internal UUID (CHECK) | history test, E2E secret check | — |
| H-T12 | Repudiation | Ambiguous engine version | Engine version stored and part of the identity; different results for one identity refused | forgery test (`sentinelpipe-policy/9.9.9`) | Old engines not executable (H4) |

Residual risks H1 to H8 are listed in ADR-0014.

## M4 Phase 3: security exceptions

Design: [ADR-0015](../adr/0015-security-exceptions-and-independent-approval.md);
review: [M4 Phase 3](../security/m4-phase3-security-review.md).

**New assets:** exception requests and their transitions (who accepted which risk until
when); the effective gate result. **New trust boundary:** the approver's identity and role,
derived by the API from the token and re-verified by PostgreSQL against current
memberships.

| Threat (STRIDE) | Mitigation | Residual |
|---|---|---|
| Self-approval (E) | API `403`; function `SELF_DECISION`; CHECK `actor <> requested_by` for APPROVED and REJECTED, also for superusers' ordinary statements | One human with two IdP identities (E3) |
| Forged requester or approver (S) | Identity from the validated token's `(iss, sub)` only; request bodies cannot carry identities (unknown properties `400`); trigger verifies `actor_role` against memberships | Compromised API can name any current OWNER (E2) |
| Cross-tenant references (I, E) | Authorization on the scan's organization before any read (`404`); requests reachable only through their scan; composite keys bind organization, project, scan, evaluation, policy and evidence; foreign members `NOT_AUTHORIZED` | Superuser (E1) |
| Forged or substituted finding (T) | The database finds the fingerprint exactly once, as a blocking finding, in the stored bytes; derived rule, category and severity; the gate re-checks all of them against a reproduced evaluation | Worker-computed fingerprints, integrity not authenticity (E6) |
| Evidence substitution after approval (T) | Gate requires the original evaluation to be reproducible with identical evidence references; otherwise `INCOMPLETE` | Superuser rewriting evidence and records consistently (E1) |
| Policy substitution (T) | Binding to the pinned version, its digest and engine version; historical records cannot be referenced (foreign key to `policy.evaluations` only) | — |
| Scope expansion (E) | One finding per request; per scan; no wildcard; only `BLOCKING_FINDINGS_EXCEEDED` coverable; duplicates of a fingerprint ineligible | — |
| Excepting incomplete evidence (E) | INCOMPLETE originals and reasons are never coverable; `INCOMPLETE_CONDITIONS_REMAIN` | — |
| State-machine manipulation, replay (T) | PK `(request, seq)`, self-referencing FK, CHECK on transitions; terminal states final; no return to REQUESTED; one open request per finding | — |
| Race conditions (T) | Row locks on the evaluation (requests) and request (transitions); unique keys as backstop; concurrent decisions: one wins | — |
| TOCTOU around expiry (E) | Database time set by trigger; CHECK `occurred_at < expires_at`; status derived at read; gate in one snapshot with `validUntil` | Clock rollback (E5) |
| Cached authorization (E) | Gate never stored; `Cache-Control: no-store`; `RISK_ACCEPTED` distinct from PASS | Consumers ignoring `validUntil` (future M5 work) |
| History tampering (T, R) | No UPDATE/DELETE grants; `refuse_change` triggers; `recorded_by` session user | Superuser and schema owner (E1) |
| Secret leakage (I) | Records hold identifiers, digests, codes; errors are fixed messages; logs carry ids and outcomes | Users pasting secrets into justifications (E7) |
| Denial of service (D) | 200 requests per scan; bounded pages and text | Gate recomputation on every read; no rate limiting (E8) |

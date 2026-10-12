# Policy decision semantics and precedence

Specification of how the policy engine (ADR-0013, M4 Phase 1) turns evidence of record
into `PASS`, `FAIL` or `INCOMPLETE`. The implementation is `PolicyEvaluator`; the
decision matrix is pinned by `PolicyEvaluatorTests`, and the database invariants by
`PolicyEvaluationIntegrationTests`.

## Principles

1. **Absence of findings is not proof of security.** PASS requires positive evidence:
   every mandatory scanner completed, its evidence is present, intact, bound to this scan,
   valid, fresh, and complete enough for the policy.
2. **FAIL needs valid evidence.** Only a document that passed every integrity, validity
   and binding gate can produce a violation.
3. **Nothing is guessed.** Unknown severity labels, missing coverage metadata, unknown
   schema versions and unexpected scanners are explicit INCOMPLETE reasons.
4. **Execution is not a decision.** A `COMPLETED` job or scan says nothing about security.
5. **Deterministic.** The same policy, context and evidence always give the same
   decision and the same ordered reasons; the only clock is the database clock, read once
   with the inputs.

## Inputs

- The policy version pinned to the scan when it was requested.
- The scan's organization, project and commit (authoritative rows).
- For each job: scanner type, status, failure reason, current lease epoch, completion time
  and, if it completed, the accepted result of that epoch and the artifacts it references.
  Results and evidence of earlier, superseded epochs are never read.
- The database clock (`now()` of the evaluating transaction).

## Gates per mandatory scanner

| # | Gate | Outcome when it fails | Evidence used? |
|---|---|---|---|
| 0 | The policy's scanner has a job in this scan | `REQUIRED_SCANNER_NOT_PLANNED` | — |
| 0 | The job's scanner is governed by the policy | `SCANNER_NOT_IN_POLICY` | — |
| 1 | Execution: job `COMPLETED` | `SCANNER_EXECUTION_FAILED` (subject: failure reason), `SCANNER_EXECUTION_CANCELLED`, `SCANNER_EXECUTION_UNFINISHED` | No |
| 2 | Presence: accepted result of the current epoch, referencing `findings.json` | `EVIDENCE_MISSING` (`RESULT`, `FINDINGS_ARTIFACT`) | No |
| 3 | Integrity: stored result re-canonicalizes to `result_sha256` | `EVIDENCE_INTEGRITY_FAILED` (`RESULT_DIGEST`, `RESULT_DOCUMENT`) | No |
| 3 | The result is bound to this job, scan, project, organization, commit, scanner and epoch, with outcome COMPLETED | `EVIDENCE_BINDING_MISMATCH` (`RESULT_CONTEXT`) | No |
| 3 | The result references the artifact of record (digest, size, media type) | `EVIDENCE_INTEGRITY_FAILED` (`RESULT_ARTIFACT`) | No |
| 3 | Media type `application/json`; content not purged; bytes match the PostgreSQL digest and size | `EVIDENCE_INVALID` (`MEDIA_TYPE`), `EVIDENCE_PURGED`, `EVIDENCE_INTEGRITY_FAILED` (`ARTIFACT_DIGEST`) | No |
| 4 | ≤ 1 MiB, strict JSON object | `EVIDENCE_INVALID` (`SIZE`, `JSON`) | No |
| 4 | `schema_version` accepted by the engine and the policy | `EVIDENCE_SCHEMA_UNSUPPORTED` (observed: the version) | No |
| 4 | Valid `findings.v1` | `EVIDENCE_INVALID` (`SCHEMA`) | No |
| 5 | `context` names this organization, project, scan, job and commit; `scanner.name` is the job's scanner | `EVIDENCE_BINDING_MISMATCH` (`FINDINGS_CONTEXT`, `SCANNER`) | No |
| 5 | Self-consistent: `finding_count`, `execution.status`, finding categories and scanner names, limitation vocabulary, empty input, coverage counts, skip counts, database freshness and source | `EVIDENCE_INCONSISTENT` (subject: which check) | No |
| 6 | Evidence age ≤ `max_age_seconds` | `EVIDENCE_STALE` (observed, limit) | Yes |
| 6 | Coverage complete (if required) | `COVERAGE_INCOMPLETE` | Yes |
| 6 | Every limitation accepted | `COVERAGE_LIMITATION_NOT_ACCEPTED` (subject: code), one per code | Yes |
| 6 | Required coverage metadata present (Semgrep and Trivy file coverage; Trivy dependency coverage and database block) | `COVERAGE_METADATA_MISSING` (subject: which) | Yes |
| 6 | Trivy database: not dated more than 1 h after job completion; age ≤ `max_database_age_seconds` | `VULNERABILITY_DATABASE_METADATA_INVALID`, `VULNERABILITY_DATABASE_TOO_OLD` (observed, limit) | Yes |
| 6 | Every finding has a label of the scanner's own scale (Semgrep, Trivy) | `UNSUPPORTED_SCANNER_SEVERITY` (observed: count) | Yes |
| 6 | Blocking findings ≤ `max_blocking_findings` | **`BLOCKING_FINDINGS_EXCEEDED`** (observed, limit): the only violation | Yes |

Gates 1 to 5 stop at the first failure for that scanner, and its evidence is discarded.
Gate 6 collects every applicable reason.

**Database age.** `max(age_seconds reported by the worker, job completion − updated_at)`:
the database clock and the verified metadata bound the worker's claim from below.

**Counting.** Findings are counted as distinct findings (fingerprints), not occurrences.
Gitleaks findings are all blocking. A Semgrep or Trivy finding is blocking when its label
is in `blocking_severities`, not blocking when its label is another label of the same
scale, and unsupported otherwise.

## Decision matrix

| Violations | Incomplete reasons | Decision | Meaning |
|---|---|---|---|
| 0 | 0 | **PASS** | Every mandatory scanner's valid, fresh evidence meets the policy, with only explicitly accepted limitations |
| ≥ 1 | 0 | **FAIL** | Valid evidence violates the policy; the evaluation is otherwise complete |
| ≥ 1 | ≥ 1 | **FAIL** | Valid evidence violates the policy, **and** the evaluation is incomplete (`incompleteCount > 0`) |
| 0 | ≥ 1 | **INCOMPLETE** | The policy cannot be shown to be satisfied; never approves a merge |

**Precedence: FAIL > INCOMPLETE > PASS.** A confirmed violation must not be hidden by
missing evidence from another scanner. INCOMPLETE reasons are still recorded beside it, so
consumers can tell "FAIL on complete evidence" from "FAIL, and more may be wrong". Both
block a merge; the precedence never weakens the gate.

The same rule is enforced twice: by `PolicyDecision.of` in the engine and by
`policy.record_evaluation` and a CHECK on `policy.evaluations` in the database.

## What PASS does not mean

- that the project is secure, or that the scanners are comprehensive (13 Semgrep
  patterns, the Gitleaks default rules, Trivy's data as of `updated_at`);
- that the scanned bytes are the commit, unless the policy refuses
  `COMMIT_NOT_VERIFIED` (which every current document carries, so such a policy is never
  PASS today);
- that evidence was produced honestly: integrity, not authenticity (ADR-0008).

## Reason record

Each reason is `{code, effect, scanner, subject, observed, limit}` with codes, scanner
types, counts and seconds only. No finding content, path, rule message, package name or
digest of raw material appears in reasons. Reasons are sorted by scanner, code, subject,
observed and limit, and stored as canonical JSON with a digest.

## Historical re-evaluation

M4 Phase 2 ([ADR-0014](../adr/0014-historical-policy-re-evaluation.md)) applies exactly
these semantics, with the same engine, to a completed scan's persisted evidence under an
explicitly chosen policy version. Only three inputs differ from the gate evaluation:

- **Policy:** the requested version of the scan's organization instead of the pinned one.
- **Clock:** the as-of instant is the original decision time (the original evaluation's
  `evaluated_as_of`, or the scan's `completed_at` when it had no policy), never the time of
  the request. Evidence age and stale-evidence reasons are therefore those of the
  original decision.
- **Evidence state:** the evidence of record as stored at re-evaluation time. If it was
  purged or altered since the original decision, the gates report it
  (`EVIDENCE_PURGED`, `EVIDENCE_INTEGRITY_FAILED`); nothing is fabricated or reused from
  the original record.

Re-evaluating under the pinned version on unchanged evidence reproduces the original
decision, reasons and evidence references. A historical record is never gating: the scan's
decision is always the `ORIGINAL` record's.

# Runbook: security policy engine (M4 Phases 1 and 2)

Operational notes for [ADR-0013](../adr/0013-security-policy-engine.md). Commands are
PowerShell-compatible; SQL is run with a read-only or administrative session as noted.

## 1. Lifecycle of a policy

1. An ADMIN creates a version: `POST /api/v1/organizations/{org}/policies` with a
   [policy.v1](../api/policy-contract-v1.md) document. Review the returned
   `definitionSha256` and the canonical `definition`.
2. An OWNER activates it for each project: `PUT /api/v1/projects/{project}/policy`.
3. Scans requested from then on are pinned to it and evaluated by the supervisor.

Versions cannot be edited or deleted. To change a policy, create a new version and
activate it. There is no deactivation in Phase 1: activate another version instead.

## 2. Reading a decision

- `GET /api/v1/scans/{scan}` shows the decision and `decisionReason`.
- `GET /api/v1/scans/{scan}/evaluation` shows the reasons, the policy digest and the
  evidence digests. `incompleteCount > 0` on a FAIL means other evidence was also missing
  or unusable.
- Reason codes are specified in [decision semantics](../architecture/policy-decision-semantics.md).

## 3. Operational limitations

- **No production effect yet.** Gitleaks, Semgrep and Trivy remain refused in production
  (local synthetic fixtures only), so policy-pinned scans can only exist in development and
  CI.
- **Accepted limitations are explicit.** Every current scanner document carries
  `COMMIT_NOT_VERIFIED` and scanner-specific inherent limitations. A policy that does not
  accept them is never PASS. This is intended; do not "fix" it by accepting limitations
  without review.
- **One gate evaluation per scan.** A scan evaluated INCOMPLETE stays INCOMPLETE; request
  a new scan. A historical re-evaluation (section 7) never changes the decision. In particular, if the supervisor was down longer than a
  policy's `max_age_seconds`, waiting scans are evaluated `EVIDENCE_STALE`.
- **Scans requested before activation** are not pinned and stay
  `INCOMPLETE / POLICY_EVALUATION_UNAVAILABLE`.
- **Scanners outside the policy:** a planned job of a scanner type the policy does not
  list (including `FIXTURE`) makes the evaluation INCOMPLETE (`SCANNER_NOT_IN_POLICY`).
  Plan exactly the policy's scanners.
- **Evidence retention:** evaluation reads evidence content; purged content is
  `EVIDENCE_PURGED`. Retention (90 days by default) is far longer than any allowed
  evidence age, so this matters only for manual purges.
- **Memory:** one evaluation reads at most 16 artifacts of 1 MiB per scan; the supervisor
  evaluates scans one at a time per pass.

## 4. Diagnosing a scan stuck in EVALUATING

A scan stays EVALUATING (decision PENDING, never mergeable) if the database refuses the
engine's record or the evaluation keeps failing. Symptoms:

- gauge `sentinel.execution.scans.evaluating` stays above zero;
- log `execution.evaluation_failed scan_id=… error_type=…` on every supervisor pass.

Read-only checks (administrative session):

```sql
SELECT s.id, s.execution_status, sp.policy_version_id
FROM scans s LEFT JOIN policy.scan_policies sp ON sp.scan_id = s.id
WHERE s.execution_status = 'EVALUATING';
```

A database refusal is reported as `evaluation rejected: <CODE>`
(`POLICY_MISMATCH`, `DECISION_INCONSISTENT`, `EVIDENCE_NOT_OF_RECORD`,
`VIOLATION_WITHOUT_EVIDENCE`, `PASS_NOT_JUSTIFIED`, `INVALID_*`). Each means the engine
produced a record the database considers inconsistent: treat it as a defect or a tampering
signal, preserve the database state, and escalate. Do **not** complete such a scan by hand;
`lifecycle.complete_evaluation` refuses policy-pinned scans by design. Cancelling the scan
(`POST /api/v1/projects/{project}/scans/{scan}/cancel`) records `INCOMPLETE` safely if it
must be closed.

## 5. Integrity checks

```sql
-- Every stored policy matches its digest (also enforced by a CHECK).
SELECT count(*) FROM policy.policy_versions
WHERE definition_sha256 <> encode(sha256(convert_to(definition, 'UTF8')), 'hex');

-- Every evaluation reason list matches its digest (also enforced by a CHECK).
SELECT count(*) FROM policy.evaluations
WHERE reasons_sha256 <> encode(sha256(convert_to(reasons, 'UTF8')), 'hex');

-- Triggers that keep policy records immutable are present and enabled.
SELECT tgrelid::regclass, tgname, tgenabled FROM pg_trigger
WHERE tgrelid::regclass::text LIKE 'policy.%' AND NOT tgisinternal ORDER BY 1, 2;
```

All counts must be `0` and every trigger enabled (`O`). A disabled trigger means someone
with owner privileges changed the schema: investigate (residual risk R2 of the
[threat model](../threat-model/policy-engine.md)).

## 6. Upgrading the engine

Changing evaluation semantics requires a new `PolicyEvaluator.ENGINE_VERSION`, an ADR
update, and updated decision-matrix tests. Changing the policy.v1 vocabulary or canonical
form is a contract change (see [policy contract](../api/policy-contract-v1.md#compatibility)):
stored versions must keep validating, or they evaluate as `POLICY_INVALID` (fail closed).

## 7. Historical re-evaluation

[ADR-0014](../adr/0014-historical-policy-re-evaluation.md). An ADMIN or OWNER asks what a
chosen policy version says about a **completed** scan's stored evidence:

```text
POST /api/v1/scans/{scan}/reevaluations   {"policyVersionId": "<uuid>"}
GET  /api/v1/scans/{scan}/evaluations     (history: ORIGINAL first, then HISTORICAL)
```

- The result is `HISTORICAL`, `gating: false`. It never changes the scan's decision. Do
  not report a historical PASS as approval; the gate decision is the scan's
  `securityDecision` and its `ORIGINAL` record.
- Evidence age is measured as of the original decision time, so old scans are not
  reported stale merely because time passed.
- Repeating the same request returns the existing record (`Idempotent-Replayed: true`).
  A new record appears only if the policy version, the engine version or the stored
  evidence changed (for example content purged by retention: `EVIDENCE_PURGED`).
- `409` codes: `scan-not-completed`, `policy-version-unusable`,
  `reevaluation-limit-reached` (100 per scan), `evaluation-inputs-changed` (retry).
- A `500` with a log line containing `evaluation rejected: <CODE>` (other than
  `INPUTS_CHANGED`) means the database refused a record the engine produced: treat it as a
  defect or tampering signal, as in section 4. `NONDETERMINISTIC` means the engine now
  gives a different answer for an identity it already recorded: check whether decision
  semantics changed without a new `ENGINE_VERSION`.

Integrity checks (administrative session):

```sql
-- Every historical reason list matches its digest (also enforced by a CHECK).
SELECT count(*) FROM policy.historical_evaluations
WHERE reasons_sha256 <> encode(sha256(convert_to(reasons, 'UTF8')), 'hex');

-- Every historical record names its policy version's digest (also a foreign key).
SELECT count(*) FROM policy.historical_evaluations h
JOIN policy.policy_versions v ON v.id = h.policy_version_id
WHERE v.definition_sha256 <> h.policy_sha256;
```

Both counts must be `0`; the triggers listed in section 5 include the two new tables.

# ADR-0015: Security exceptions and independent approval

- **Status:** Proposed (pending owner review and a successful remote CI run)
- **Date:** 2026-10-11
- **Milestone:** M4 Phase 3
- **Builds on:** [ADR-0013](0013-security-policy-engine.md) (policy engine, accepted),
  [ADR-0014](0014-historical-policy-re-evaluation.md) (historical re-evaluation, accepted),
  [ADR-0008](0008-result-integrity-and-evidence.md) (evidence of record),
  [ADR-0003](0003-identity-and-tenant-authorization.md) (identity and roles)
- **Addresses:** ADR-0013 residual risk R6 ("no security exceptions") for exceptions; the
  two-person rule for policy *activation* is not part of this ADR.
- **Specifications:** [policy API](../api/policy-evaluation-api.md#security-exceptions),
  [decision semantics](../architecture/policy-decision-semantics.md#security-exceptions-and-the-effective-gate)
- **Threat model:** [Policy engine](../threat-model/policy-engine.md#m4-phase-3-security-exceptions)
- **Security review:** [M4 Phase 3 review](../security/m4-phase3-security-review.md)
- **Runbook:** [Policy engine](../runbooks/policy-engine.md#8-security-exceptions)

## Context

A scan whose original evaluation is FAIL blocks a change. Sometimes a confirmed finding is
an accepted risk for a limited time: a synthetic credential in a fixture, a dependency
advisory with no fix yet. Without an exception mechanism the only options are to weaken the
policy for every scan (activate a laxer version) or to ignore the gate. Both are worse than
a narrow, temporary, audited acceptance decided by someone other than the person asking.

Four concepts must stay distinct:

| Concept | Where it lives | Changes? |
|---|---|---|
| **Finding detection** | `findings.v1` evidence of record (ADR-0008, ADR-0010) | Never |
| **Policy violation** | The scan's ORIGINAL evaluation (ADR-0013): `BLOCKING_FINDINGS_EXCEEDED` per scanner | Never |
| **Approved exception** | `policy.exception_requests` + `policy.exception_transitions` (this ADR) | Append-only |
| **Effective gate result** | Computed on request from the three above (this ADR) | Not stored |

The only violation reason the engine produces is `BLOCKING_FINDINGS_EXCEEDED`: an aggregate
count of blocking findings per scanner over the policy's limit. An exception therefore
cannot "waive a reason"; it must remove **identified findings** from that count.

## Decision

### 1. Scope: one verified blocking finding of one scan's original FAIL

A request names a scan, a scanner and a finding fingerprint, plus a justification and an
expiry. Everything else is derived from stored records and bound declaratively:

- the scan's **ORIGINAL** evaluation (never a historical one), its pinned policy version and
  digest and its engine version: composite foreign key to
  `policy.evaluations (id, scan_id, project_id, organization_id, policy_version_id,
  policy_sha256, engine_version)`;
- that evaluation's evidence of record for the scanner (job, lease epoch, artifact name and
  digest, result digest): composite foreign key to `policy.evaluation_evidence`;
- the finding's rule id, category and scanner severity, as found by PostgreSQL in the
  stored `findings.json` bytes.

**Per-scan, not recurring.** Fingerprints are location-based, computed by the worker, and
identical across tenants for the same rule and location; correlating findings across
commits is a later M4 slice that requires comparable coverage. A recurring exception would
need a verified cross-scan identity the platform does not have. Each new scan has new
evidence and needs its own exception.

**Eligibility.** The scan is `COMPLETED` with decision `FAIL`; the scanner has a
`BLOCKING_FINDINGS_EXCEEDED` violation in the original evaluation; the stored artifact is
present, bound to the job and scan, and contains **exactly one** finding with the
fingerprint, of the scanner's category, counted as blocking by the pinned policy (severity
in `blocking_severities`; every Gitleaks finding). Duplicate fingerprints in one document
make the finding ineligible.

**Never exceptable:** INCOMPLETE conditions (missing, purged, invalid, inconsistent or
unbound evidence; scanner failures, cancellations or missing scanners; incomplete coverage
or unaccepted limitations; stale evidence or databases; unsupported severities; engine
errors), non-blocking findings, wildcards, whole scanners, whole projects.

### 2. Lifecycle

```text
(none) -> REQUESTED              seq 0  requester (ADMIN or OWNER)
REQUESTED -> APPROVED            seq 1  an OWNER other than the requester
REQUESTED -> REJECTED            seq 1  an OWNER other than the requester
REQUESTED -> WITHDRAWN           seq 1  the requester
APPROVED  -> REVOKED             seq 2  an OWNER
```

Requests are immutable; transitions are append-only rows. The primary key
`(request_id, seq)` permits exactly one way out of each state; a self-referencing foreign
key `(request_id, from_state) -> (request_id, to_state)` proves the state being left was
entered; a CHECK lists the only allowed `(seq, from, to)` combinations. Terminal states
(REJECTED, WITHDRAWN, REVOKED) have no outgoing transition and nothing returns to
REQUESTED.

**Expiry is derived, not a transition.** `policy.exception_status` computes `status` from
the last transition and the database clock: `ACTIVE` only for an approval before
`expires_at`; `EXPIRED` for a REQUESTED or APPROVED request at or after it. No scheduler is
needed for an exception to stop applying. No transition is accepted at or after expiry
(CHECK `occurred_at < expires_at`), so an expired request can be neither approved nor
revoked (it already does not apply).

### 3. Independent approval (two-person rule)

Enforced in three places:

1. **API:** approve and reject require `DECIDE_EXCEPTIONS` (OWNER); the service refuses an
   actor equal to the requester (`403 self-decision-forbidden`) before calling the database.
2. **Database function** `policy.transition_exception`: re-checks state, expiry, the actor's
   **current** membership role and requester inequality under a row lock on the request.
3. **Table constraints and triggers**, for any writer including the owner or a superuser
   through ordinary statements:
   - CHECK `to_state NOT IN ('APPROVED', 'REJECTED') OR actor <> requested_by`, where
     `requested_by` is copied under a foreign key to the request;
   - CHECK on `actor_role` per transition (OWNER for decisions);
   - a BEFORE INSERT trigger verifies `actor_role` against `organization_memberships` at
     insert time, forces `occurred_at` to `clock_timestamp()` and `recorded_by` to
     `session_user`, enforces monotonic time per request, and re-verifies the finding for an
     approval.

Identities are server-derived internal references (`user:<uuid>` of `user_identities`),
never request values or token subjects. Two principals are distinct when their internal
identities differ. If the caller has no identity, the request fails closed (404).

**Role matrix**

| Operation | OWNER | ADMIN | MEMBER | VIEWER | Non-member |
|---|---|---|---|---|---|
| List / read requests and history, read gate | yes | yes | yes | yes | 404 |
| Request (`REQUEST_EXCEPTIONS`) | yes | yes | 403 | 403 | 404 |
| Withdraw own pending request | requester only | requester only | 403 | 403 | 404 |
| Approve / reject (`DECIDE_EXCEPTIONS`) | yes, never own | 403 | 403 | 403 | 404 |
| Revoke (`DECIDE_EXCEPTIONS`) | yes | 403 | 403 | 403 | 404 |

ADMIN may request but not decide: requesting and approving are separate duties. An OWNER
may request; another OWNER must decide. An organization with a single OWNER cannot approve
an OWNER's request (by design).

### 4. Effective gate

`GET /api/v1/scans/{scanId}/gate` computes, in one REPEATABLE READ snapshot:

| Situation | Effective decision | Reasons |
|---|---|---|
| Scan not COMPLETED | INCOMPLETE | `SCAN_NOT_COMPLETED` |
| COMPLETED without an original evaluation | INCOMPLETE | `ORIGINAL_EVALUATION_MISSING` |
| Original PASS | PASS | none |
| Original INCOMPLETE | INCOMPLETE | `ORIGINAL_INCOMPLETE` |
| Original FAIL not reproducible from current evidence | INCOMPLETE | `ORIGINAL_NOT_REPRODUCIBLE` |
| A violation remains after removing excepted findings | FAIL | `VIOLATION_NOT_EXCEPTED` (+ covered ones) |
| All violations covered, incomplete reasons remain | INCOMPLETE | `VIOLATION_EXCEPTED`…, `INCOMPLETE_CONDITIONS_REMAIN` |
| All violations covered, no incomplete reason | **RISK_ACCEPTED** | `VIOLATION_EXCEPTED`… |

- **Reproducibility.** Before any exception applies, the engine runs again over the
  current evidence of record with the pinned version, as of the original decision time.
  The original is reproducible only if engine version, decision, canonical reasons and
  evidence references are identical. Purged, altered or substituted evidence, an unusable
  stored policy or a new engine version fail closed.
- **Coverage.** For each `BLOCKING_FINDINGS_EXCEEDED` violation, an ACTIVE exception covers
  a finding only if it is bound to exactly this evaluation, policy, engine, job, epoch,
  artifact and result digests, and its fingerprint, rule, category and severity name a
  blocking finding occurring exactly once. The violation is covered when the remaining
  blocking count is within the policy's limit. Any other violation code is never covered.
- **RISK_ACCEPTED, not PASS.** A gate open only because of accepted risk is a distinct
  value with `exceptionBased: true` and `validUntil` (earliest expiry of the applied
  exceptions). A consumer that tests for `PASS` cannot mistake it; one that wants to honour
  accepted risk must opt in explicitly. PASS is returned only when the original decision is
  PASS.
- **Never persisted.** The result is computed on every request (`Cache-Control:
  no-store`). There is no cached gate result to reuse after expiry or revocation.
  `evaluatedAt` is the database time of the snapshot; a result must not be relied on after
  `validUntil`.
- **Not integrated.** No GitHub check, branch protection or deployment consumes the
  effective gate in this phase. The scan's `securityDecision` remains the original decision.

### 5. Persistence (Flyway V011)

- New tables `policy.exception_requests`, `policy.exception_transitions`, view
  `policy.exception_status`; new unique keys on `policy.evaluations` and
  `policy.evaluation_evidence` (supersets of existing keys) to serve as foreign-key targets.
  V001 to V010 are unchanged.
- Writes only through `policy.request_exception` and `policy.transition_exception`
  (SECURITY DEFINER, pinned `search_path`, EXECUTE for `sentinel_api` only). The API role has
  SELECT on the tables and view and no INSERT, UPDATE or DELETE. Worker and operator roles
  have nothing.
- `policy.refuse_change` triggers refuse UPDATE, DELETE and TRUNCATE on both tables, also
  for the owner and superusers through ordinary statements.
- Requests of one scan are serialized by `FOR NO KEY UPDATE` on its original evaluation row
  (duplicates, limit); transitions of one request by `FOR NO KEY UPDATE` on the request row.
  Concurrent decisions produce one transition; the others see the new state (`409`).

### 6. Time

| Rule | Value |
|---|---|
| Lifetime | at least 1 hour (the API requires 1 hour 1 minute to absorb request latency), at most 90 days, from the database time of the request |
| Approval window | at least 5 minutes of validity left (`409 exception-expires-too-soon`) |
| Transitions | refused at or after expiry (`409 exception-expired`) |
| Expiry during a gate computation | the snapshot's database time decides; `validUntil` bounds the result |
| Revocation | effective for every gate computed after the revocation commits |
| Clock | all timestamps from the database clock; callers cannot supply or backdate them |

### 7. Operational limits

At most 200 requests per scan (database-enforced); justification 20 to 2,000 characters,
rationale 1 to 1,000, no control characters, no leading or trailing whitespace; pages of
at most 100 (page index at most 10,000); unknown request properties rejected (`400`).

## Consequences

- A FAIL can be accepted narrowly, temporarily and visibly, without weakening the policy
  for other scans, and without rewriting any evidence or decision.
- Every request, approval, rejection, withdrawal and revocation is attributable (internal
  identity, verified role, database time, database login) and immutable for runtime roles.
- A new scan needs new exceptions; this is deliberate until finding correlation exists.
- Computing the gate re-runs the engine over up to 16 evidence artifacts of 1 MiB each per
  request.
- `ENGINE_VERSION` is unchanged (`sentinelpipe-policy/1.0.0`): the engine now also returns
  the identities of the blocking findings it counted, but decisions and reasons are
  identical (tested).

## Residual risks

- **E1 Database superuser and schema owner trust.** They can disable triggers, rewrite
  requests and transitions consistently, or forge an approval by another identity. Records
  are append-only for runtime roles, not tamper-proof (as H1, R2).
- **E2 API process trust.** A compromised API process holds the `sentinel_api` login and can
  call `policy.transition_exception` with any member's identity: the database verifies that
  the identity is a current OWNER other than the requester, but cannot verify that this
  OWNER actually made the request. Two-person approval is therefore enforced against honest
  API code and direct SQL by runtime roles, not against a compromised control plane.
- **E3 One person, two identities.** A human controlling two IdP identities that are both
  members can request and approve. The platform cannot detect this; IdP governance must.
- **E4 Membership changes after approval.** An approval stays active if the approver later
  loses OWNER or leaves the organization; another OWNER can revoke it.
- **E5 Database clock.** Expiry depends on the PostgreSQL host clock. A clock moved
  backwards can make an expired approval ACTIVE again; transitions keep their monotonic
  order, but status derivation cannot detect a rollback.
- **E6 Finding authenticity.** The finding is verified against the stored evidence, not
  against the repository: a compromised worker or sandbox can misreport its own job
  (integrity, not authenticity; H3, R3). Fingerprints are worker-computed and not
  recomputed by the control plane.
- **E7 Justification content.** Justifications and rationales are user text shown to every
  member who can read the scan; users could paste a secret. They are never logged, but
  they are stored indefinitely.
- **E8 No rate limiting.** Each gate read re-runs the engine; any member can request it
  repeatedly (as H8).
- **E9 Single-OWNER organizations** cannot approve an OWNER's request, and ADMIN requests
  need an OWNER. This is the intended trade-off.
- **E10 Non-production.** All restrictions of ADR-0013 and ADR-0014 hold: synthetic fixtures
  only, Trivy disabled in production, Docker/runc not a boundary for hostile repositories,
  domain API disabled by default and loopback-only. Neither an exception nor the effective
  gate can authorize a deployment.

## Alternatives considered

- **Mutating the evaluation or the scan decision on approval.** Rejected: original
  decisions are immutable (ADR-0013); the V009 trigger would refuse it anyway.
- **Reusing PASS for an exception-based gate.** Rejected: a consumer could not distinguish
  accepted risk from compliance. `RISK_ACCEPTED` is explicit.
- **Persisting effective gate results.** Rejected for this phase: a stored PASS-like result
  could be reused after expiry or revocation. Computing on read has no stale state. A
  future integration that needs a record should store snapshots labelled as historical,
  never as current authorization.
- **Recurring exceptions by fingerprint across scans.** Deferred: no verified cross-scan
  finding identity yet (location-based, worker-computed fingerprints).
- **Exceptions on reasons rather than findings.** Rejected: the only violation is an
  aggregate count; waiving it would hide every current and future finding of the scanner.
- **ADMIN approval.** Rejected: ADMIN already drafts policy versions; letting ADMIN approve
  would let two ADMINs bypass the OWNER entirely. Decisions stay OWNER-only.
- **A generic workflow engine or a separate service.** Rejected: four transitions fit in two
  tables, two functions and the existing modular monolith.
- **A background expiry job.** Not needed: status is derived from the database clock on
  every read.

## Remaining M4 roadmap (not implemented)

1. **Finding identity and comparison:** NEW / EXISTING / RESOLVED only when coverage is
   comparable; a verified cross-scan finding identity would be the prerequisite for
   recurring exceptions.
2. **Deterministic remediation knowledge base and reports** (Markdown, HTML, JSON),
   listing accepted risks separately from required fixes.
3. **Policy audit API** (activation history, exception history per organization) and
   policy listing.
4. **Two-person rule for policy activation** (ADR-0013 R6, still open).
5. **Signed evidence or attestations** and an external append-only audit sink (with M6/M7)
   to address E1, E2 and E6.

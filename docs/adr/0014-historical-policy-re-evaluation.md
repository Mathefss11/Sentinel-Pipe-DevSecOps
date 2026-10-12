# ADR-0014: Historical policy re-evaluation

- **Status:** Proposed (pending owner review and a successful remote CI run)
- **Date:** 2026-10-11
- **Milestone:** M4 Phase 2
- **Builds on:** [ADR-0013](0013-security-policy-engine.md) (policy engine, accepted
  2026-10-11), [ADR-0008](0008-result-integrity-and-evidence.md) (evidence of record),
  [ADR-0007](0007-database-authoritative-execution-leases.md) (lifecycle)
- **Amends:** ADR-0013's roadmap note "re-evaluation … (OWNER)": re-evaluation is granted
  to ADMIN and OWNER (see [Authorization](#7-authorization-and-tenant-isolation)). ADR-0013's
  decisions are otherwise unchanged.
- **Specifications:** [policy API](../api/policy-evaluation-api.md#historical-re-evaluation),
  [decision semantics](../architecture/policy-decision-semantics.md#historical-re-evaluation)
- **Threat model:** [Policy engine](../threat-model/policy-engine.md#m4-phase-2-historical-re-evaluation)
- **Security review:** [M4 Phase 2 review](../security/m4-phase2-security-review.md)
- **Runbook:** [Policy engine](../runbooks/policy-engine.md#7-historical-re-evaluation)

## Context

ADR-0013 records exactly one gate evaluation per scan, against the policy version pinned
when the scan was requested. Two questions then have no answer:

- "Would this already-judged evidence pass the stricter policy we are about to activate?"
- "A scan was requested before any policy existed (`INCOMPLETE /
  POLICY_EVALUATION_UNAVAILABLE`): what would the current policy say about its evidence?"

Re-running scanners answers a different question (new evidence). The question here is:
**given the exact evidence previously persisted for scan S, what decision would policy
version P produce?** The answer must never change the scan's gate decision, its pinned
policy or its original record, and it must itself be immutable and auditable.

## Decision

### 1. A separate, non-gating record type

Historical re-evaluations are stored in new append-only tables (Flyway V010):
`policy.historical_evaluations` and `policy.historical_evaluation_evidence`. The original
evaluation stays in `policy.evaluations`, unchanged.

A separate table was chosen over extending `policy.evaluations` because that table's V009
invariants are gate invariants:

- `UNIQUE (scan_id)`: one gating record per scan;
- a foreign key to `policy.scan_policies`: the record must use the pinned version;
- the trigger `policy.require_evaluation_record` accepts a scan decision only if *an*
  evaluation row of the scan has the same decision.

Mixing historical rows into that table would require dropping or weakening all three, and
a historical FAIL or PASS row would then satisfy the decision trigger for its scan. With a
separate table, no query, trigger or constraint can mistake a historical record for the
gate decision. The API presents both as one history with an explicit `evaluationType`
(`ORIGINAL`, `HISTORICAL`) and `gating` flag (true only for `ORIGINAL`).

### 2. Same engine, same semantics

The historical path reuses `PolicyEvaluator` (`ENGINE_VERSION` `sentinelpipe-policy/1.0.0`)
and the evidence reader of `PolicyEvaluationService` (`policy.job_evidence`): the same six
gates, the same precedence **FAIL > INCOMPLETE > PASS**, the same reason codes, the same
fail-closed handling of engine errors (`EVALUATION_ERROR`). There is no second engine and
no second set of decision semantics. Invalid evidence is discarded before gate 6, so it can
never establish a violation; a confirmed violation is never hidden by incomplete evidence.

### 3. Inputs: persisted evidence of record only

- **Evidence:** exactly what `policy.job_evidence` returns for the scan: for each job, the
  accepted COMPLETED result of its current lease epoch and the artifacts that result
  references. The request body contains only `policyVersionId`; evidence, findings,
  decisions and timestamps are never accepted from the caller (unknown properties are
  rejected with 400).
- **Eligible scans:** `COMPLETED` only. Every job is terminal and lease fencing prevents
  any worker from changing the evidence (ADR-0007/0008). `QUEUED`, `RUNNING`,
  `EVALUATING`, `FAILED` and `CANCELLED` scans are refused (`409 scan-not-completed`):
  failed and cancelled scans have no gate evaluation, and their decision is INCOMPLETE by
  definition.
- **Verification:** unchanged from ADR-0013, run against the current stored state:
  organization, project, scan, job and commit binding; scanner identity; result digest and
  artifact digest, size and media type; evidence schema version; `findings.v1` schema;
  evidence-to-job and evidence-to-scan binding; execution state; coverage limitations.
  Missing, purged, altered or unsupported evidence yields an INCOMPLETE record with the
  corresponding reason. Nothing is fabricated.

### 4. Policy version selection

- The caller names an explicit `policyVersionId`. The currently active policy is never
  substituted, and the scan's pin is never read for selection.
- **Eligible versions:** every stored version of the scan's organization, whether it was
  never activated, is active, or was superseded. policy.v1 has no draft state: every
  stored version passed strict validation at creation. Re-evaluation has no gating effect,
  so activation is not a precondition.
- A version of another organization, or one that does not exist, is `404 PolicyVersion`
  (indistinguishable). The database refuses it again (`POLICY_VERSION_NOT_FOUND`) and the
  composite foreign key `(policy_version_id, organization_id)` refuses it even for direct
  SQL.
- The stored definition is re-validated against its schema, canonical form and digest
  before use. Unlike the gate (which records `POLICY_INVALID`), a version requested
  explicitly that no longer validates is a **request failure** (`409
  policy-version-unusable`) and nothing is recorded.
- The record stores `policy_version_id` and `policy_sha256`; a foreign key
  `(policy_version_id, policy_sha256)` → `policy_versions (id, definition_sha256)` binds
  them declaratively (V010 adds the needed unique key).

### 5. Historical as-of time

The engine measures evidence age against an as-of instant. For a re-evaluation that
instant is the **original decision time**: the original evaluation's `evaluated_as_of`,
or the scan's `completed_at` when it has no original evaluation (no policy was pinned).
It is never the wall clock: otherwise every historical scan would become
`EVIDENCE_STALE`, and the answer would depend on when it was asked.

The record keeps both instants: `evaluatedAt` (as-of) and `recordedAt` (when the
re-evaluation was written). Consequence: re-evaluating under the pinned version reproduces
the original decision, reasons and evidence references (tested), unless the evidence
changed since.

### 6. Identity, idempotency and concurrency

- **Identity:** `(scan_id, policy_version_id, engine_version, inputs_sha256)`, enforced
  by a unique constraint. `inputs_sha256` is computed by PostgreSQL
  (`policy.historical_inputs_sha256`) over the as-of instant and every column of
  `policy.job_evidence`: job id, scanner, status, failure reason, lease epoch, completion
  time, result digest, digest of the stored result text, artifact name, media type,
  digest, size, and whether its content is present or purged. Content bytes are bound to
  their digest by `evidence.objects`' integrity CHECK.
- Scan and policy version alone are not a sufficient identity: evidence can change (for
  example retention purges content) and the engine can change. Either produces a new,
  distinguishable record; the earlier record is never rewritten.
- **Repeat:** an identical request returns the existing record (`200`,
  `Idempotent-Replayed: true`); nothing is written. The requester is not part of the
  identity: a replay by another administrator returns the first requester's record. No
  `Idempotency-Key` header is needed, because the identity is natural and server-derived.
- **Determinism check:** if a record with the same identity exists but the new result
  differs (decision or reasons digest), the database refuses with `NONDETERMINISTIC`
  instead of storing a second answer. A persisted decision never changes.
- **TOCTOU:** the API reads the context, the fingerprint, the policy version and the
  evidence in one `REPEATABLE READ` read-only transaction, evaluates, then calls
  `policy.record_historical_evaluation` in a separate transaction. The function locks the
  scan row (`FOR NO KEY UPDATE`: re-evaluations of one scan are serialized; foreign-key
  checks of rows referencing the scan are not blocked), recomputes the fingerprint and
  refuses the record if the inputs changed (`INPUTS_CHANGED`). The API retries once from
  a fresh snapshot, then answers `409 evaluation-inputs-changed`.
- **Concurrency:** concurrent identical requests produce exactly one record; the others
  receive it as `EXISTING` (tested with eight concurrent requests).
- **Bound:** at most 100 historical records per scan (`409 reevaluation-limit-reached`),
  checked under the same row lock.

### 7. Authorization and tenant isolation

| Operation | OWNER | ADMIN | MEMBER | VIEWER |
|---|---|---|---|---|
| `POST /api/v1/scans/{scanId}/reevaluations` | yes | yes | no | no |
| `GET /api/v1/scans/{scanId}/evaluations` (history, paginated) | yes | yes | yes | yes |
| `GET /api/v1/scans/{scanId}/evaluations/{evaluationId}` | yes | yes | yes | yes |

- New permission `REEVALUATE_SCANS` (ADMIN). Re-evaluation cannot change a gate decision,
  so it does not need `ACTIVATE_POLICY` (OWNER); it is still restricted beyond MEMBER
  because it writes durable audit records and consumes evaluation resources. ADR-0013's
  roadmap suggested OWNER only; ADMIN already drafts policy versions and can learn the
  same answer by other means, so the stricter restriction would add no protection.
- Membership is checked against the organization that owns the scan before anything is
  read; non-members receive `404` exactly as for a nonexistent scan. The policy version is
  then resolved only within that organization. A record of another scan is `404`.
- Reads use `VIEW_SCANS`, like the original evaluation record.
- No internal or unauthenticated endpoint exists; the endpoint coverage test includes the
  new operations.

### 8. Auditability

Each historical record answers: who (`requested_by`, the internal identity reference
`user:<uuid>`, never a name, e-mail address or token subject, enforced by a CHECK), which
scan, which policy version and digest, which evidence (`historical_evaluation_evidence`
with job, epoch, artifact and result digests, foreign keys to the evidence of record),
which decision and why (canonical reasons with a CHECK-recomputed digest), when
(`evaluated_as_of`, `recorded_at`), which engine (`engine_version`), and the database
login that wrote it (`recorded_by`).

Records are append-only: no UPDATE or DELETE grants for any runtime role, and
`policy.refuse_change` triggers refuse UPDATE, DELETE and TRUNCATE for the owner through
ordinary statements. Reads return records as stored; nothing is recalculated when read.
The API log line `policy.reevaluated` carries identifiers, the decision and the outcome
only.

### 9. Failure handling

| Condition | Result |
|---|---|
| Scan unknown, or caller not a member | `404 Scan` |
| Caller is a member below ADMIN | `403 insufficient-role` |
| Policy version unknown or of another organization | `404 PolicyVersion` |
| Scan not COMPLETED | `409 scan-not-completed` |
| Stored version no longer validates | `409 policy-version-unusable`, nothing recorded |
| Evidence changed twice during the request | `409 evaluation-inputs-changed` |
| 100 records already exist | `409 reevaluation-limit-reached` |
| Evidence missing, purged, altered, unsupported, inconsistent | `201`, INCOMPLETE record with reasons |
| Engine error | `201`, INCOMPLETE record (`EVALUATION_ERROR`) |
| Database refuses the record (any other `evaluation rejected: <CODE>`) | `500`, nothing recorded; a defect or tampering signal |

### 10. Retention and privacy

- Historical records keep identifiers, digests and reason codes only: no evidence
  content, finding text, paths or secrets. Responses never include raw evidence.
- Records are kept indefinitely (append-only). They reference evidence rows with
  `ON DELETE RESTRICT`; retention purges evidence **content** only, never the rows, so
  records stay valid after purging. A re-evaluation after a purge is a new record with
  `EVIDENCE_PURGED`.
- The only personal reference is the internal identity UUID of the requester. Erasing a
  user identity is not supported by any append-only audit table yet (as for
  ADR-0013's `created_by` and `assigned_by`); a future data-retention design must cover
  all of them together.

## Consequences

- Owners can assess the impact of a stricter or laxer policy on already-judged evidence,
  and judge scans that were requested before any policy was active, without rescanning.
- A historical PASS is **not** approval. It is relative to the named policy version (which
  need not be active and may have been written by an ADMIN for this purpose) and to that
  version's accepted limitations. Only the `ORIGINAL` record is gating. Later integrations
  (M5 GitHub Checks, PR comments) must use the scan's decision and never a historical
  record.
- **Engine-version reproducibility:** `ENGINE_VERSION` must change whenever decision
  semantics change. Old records keep their engine version; re-evaluating with a new engine
  creates new records. The API runs only the current engine: reproducing an old record
  bit for bit requires the source revision that produced it. The determinism check
  (`NONDETERMINISTIC`) detects a semantics change made without a version change only for
  identities that were already recorded.
- Storage grows by at most 100 records per scan, each bounded like an original record
  (≤ 512 reasons, ≤ 16 evidence references).
- No new service, queue, message or scanner execution. The supervisor is unaffected.

## Residual risks

- **H1 Database superuser trust.** A superuser or the schema owner can disable triggers
  and rewrite historical records, digests, evidence and policies consistently (as ADR-0013
  R2/R9). There is no external anchor; audit records are append-only for runtime roles,
  not tamper-proof.
- **H2 API process trust.** The API process runs the engine and chooses the engine version
  string. It cannot store a record the database finds inconsistent, but it can store a
  consistent, false one (ADR-0013 R1).
- **H3 Historical evidence authenticity.** Re-evaluation re-verifies integrity, not
  authenticity: evidence produced by a compromised worker or sandbox for its own job is
  re-judged as it is (ADR-0013 R3).
- **H4 Engine-version reproducibility.** Old engine versions cannot be executed by the
  running API; a semantics change without a version bump would be visible only through
  `NONDETERMINISTIC` on already-recorded identities.
- **H5 Policy limitations.** A historical decision is relative to the limitations the
  chosen version accepts, exactly like the original decision (ADR-0013 R4, R8). An ADMIN
  can create a permissive version and obtain a historical PASS; it is labelled
  non-gating, names its version and digest, and never changes the scan's decision.
- **H6 Retention of historical evidence.** Purged evidence cannot be re-verified; later
  re-evaluations are INCOMPLETE (`EVIDENCE_PURGED`). Records themselves are kept
  indefinitely; there is no erasure procedure for requester references.
- **H7 No production authorization for hostile repositories.** Unchanged: scanners run on
  local synthetic fixtures only, Trivy stays disabled in production, Docker/runc is not a
  boundary for hostile code, and the domain API stays disabled by default and
  loopback-only.
- **H8 No rate limiting.** An ADMIN can request up to 100 re-evaluations per scan, each
  reading up to 16 × 1 MiB of evidence; the API has no rate limiting yet.

## Alternatives considered

- **Extend `policy.evaluations` with an evaluation type.** Rejected: it would weaken the
  V009 gate invariants (section 1) and make every consumer filter by type to avoid treating
  a historical record as the decision.
- **Identity = (scan, policy version).** Rejected: a changed engine or changed evidence
  would either be hidden behind the old record or overwrite it.
- **Client `Idempotency-Key`.** Not needed: the result is a deterministic function of a
  server-derived identity; a key would add state without adding safety.
- **Evaluate as of the wall clock.** Rejected: every past scan would become
  `EVIDENCE_STALE`, and repeated requests would not be idempotent.
- **Accept evidence or findings in the request** (for example to "what-if" a finding).
  Rejected: evidence would no longer be evidence of record, and a caller could fabricate
  the input of an audit record.
- **Asynchronous re-evaluation through RabbitMQ.** Not needed: evaluation is bounded and
  synchronous like the gate's; a queue would add a message type and an outbox event for no
  isolation benefit (the engine already runs in the API process).
- **Allow FAILED and CANCELLED scans.** Deferred: their evidence is incomplete by
  construction and they have no gate evaluation to compare with; allowing them later needs
  only a reviewed change of the eligibility rule.

# Policy and evaluation API (M4 Phases 1 to 3)

Fifteen operations under `/api/v1`, documented in
[`sentinel-api-v1.yaml`](../../packages/contracts/openapi/sentinel-api-v1.yaml) (tag
`Policies` and `Security exceptions`) with JSON Schemas in `packages/contracts/schemas/v1`. Design:
[ADR-0013](../adr/0013-security-policy-engine.md) (policies, gate evaluation) and
[ADR-0014](../adr/0014-historical-policy-re-evaluation.md) (historical re-evaluation,
accepted) and [ADR-0015](../adr/0015-security-exceptions-and-independent-approval.md)
(security exceptions and the effective gate, proposed). Like the rest of the domain API, these
endpoints exist only when the domain API is enabled (loopback-only, ADR-0002).

## Authorization

Every operation requires a valid bearer token and is decided by server-side memberships of
the organization that owns the resource. Non-members receive `404` exactly as for a
resource that does not exist; members without the role receive `403`
(`insufficient-role`).

| Operation | OWNER | ADMIN | MEMBER | VIEWER |
|---|---|---|---|---|
| `POST /organizations/{organizationId}/policies` (create a version) | yes | yes | no | no |
| `GET /policy-versions/{policyVersionId}` | yes | yes | yes | yes |
| `PUT /projects/{projectId}/policy` (activate) | yes | no | no | no |
| `GET /projects/{projectId}/policy` | yes | yes | yes | yes |
| `GET /scans/{scanId}/evaluation` | yes | yes | yes | yes |
| `POST /scans/{scanId}/reevaluations` (historical re-evaluation) | yes | yes | no | no |
| `GET /scans/{scanId}/evaluations` (history) | yes | yes | yes | yes |
| `GET /scans/{scanId}/evaluations/{evaluationId}` | yes | yes | yes | yes |
| `POST /scans/{scanId}/exceptions` (request) | yes | yes | no | no |
| `GET /scans/{scanId}/exceptions`, `.../exceptions/{exceptionId}` | yes | yes | yes | yes |
| `POST .../exceptions/{exceptionId}/approve`, `/reject` | yes, never own | no | no | no |
| `POST .../exceptions/{exceptionId}/withdraw` | requester | requester | no | no |
| `POST .../exceptions/{exceptionId}/revoke` | yes | no | no | no |
| `GET /scans/{scanId}/gate` (effective gate) | yes | yes | yes | yes |

- Activation is OWNER-only because it can weaken the gate; drafting is ADMIN.
- Historical re-evaluation is ADMIN or above (`REEVALUATE_SCANS`): it never changes a
  gate decision.
- A policy version of another organization is reported as `404 PolicyVersion was not
  found.`, identical to a nonexistent one. The database refuses cross-tenant activation
  independently (composite foreign keys).
- There is **no** endpoint that records or changes a scan's **gate** decision. The
  supervisor evaluates scans once execution has finished; no internal evaluation endpoint
  exists that could bypass authorization. A requested historical re-evaluation is a
  separate, non-gating record (below).
- The audited actor of a creation or activation is the caller's server-side identity
  (`user:<identity id>`), never a request value. Activation history is kept in
  `policy.project_assignments`; there is no audit endpoint yet.

## Operations

### Create a policy version

`POST /api/v1/organizations/{organizationId}/policies`, body: a
[policy.v1](policy-contract-v1.md) document.

- `201` with `Location: /api/v1/policy-versions/{id}` and a `policy-version` body:
  `id`, `policyId`, `organizationId`, `name`, `version`, `schemaVersion`,
  `definitionSha256`, `definition` (canonical), `createdAt`.
- `400 validation-error` for an invalid definition, a body over 16 KiB or a body that is
  not UTF-8. Errors carry sanitized locations and fixed messages only.
- Versions are immutable. Creating a version does not activate it.

### Get a policy version

`GET /api/v1/policy-versions/{policyVersionId}` → `200 policy-version`.

### Activate a policy version for a project

`PUT /api/v1/projects/{projectId}/policy`, body `{"policyVersionId": "<uuid>"}` →
`200 project-policy` (`projectId`, `policyVersionId`, `policyId`, `name`, `version`,
`definitionSha256`, `assignedAt`). Activating the version already in force changes
nothing. Scans requested afterwards are pinned to it; earlier scans are not affected.

### Get the active policy of a project

`GET /api/v1/projects/{projectId}/policy` → `200 project-policy`, or `404` when no policy
is in force.

### Get the evaluation record of a scan

`GET /api/v1/scans/{scanId}/evaluation` → `200 policy-evaluation`:

| Field | Meaning |
|---|---|
| `decision` | `PASS`, `FAIL` or `INCOMPLETE`; equal to the scan's `securityDecision` |
| `violationCount`, `incompleteCount` | Reasons per effect; FAIL with `incompleteCount > 0` means "FAIL, and also incomplete" |
| `reasons[]` | `{code, effect, scanner, subject, observed, limit}`, sorted ([semantics](../architecture/policy-decision-semantics.md)) |
| `evidence[]` | Evidence of record relied on: `jobId`, `scannerType`, `leaseEpoch`, `name`, `sha256` (computed by PostgreSQL at upload), `resultSha256` |
| `policyVersionId`, `policySha256` | The pinned policy version and its digest |
| `engineVersion` | `sentinelpipe-policy/1.0.0` |
| `evaluatedAt` | Database time at which the inputs were read; all ages are measured against it |
| `recordedAt` | When the record was written |

`404` when the scan has no evaluation record: the scan is not evaluated yet, or it has no
pinned policy (then it is `INCOMPLETE` with `POLICY_EVALUATION_UNAVAILABLE`).

The scan representation (`GET /api/v1/scans/{scanId}`) is unchanged. A policy-pinned scan
that reaches `COMPLETED` has `decisionReason = POLICY_EVALUATED` for every decision,
including `INCOMPLETE`, and an evaluation record. A pinned scan that is cancelled or fails
during execution is `INCOMPLETE` with `CANCELLED_BY_USER`, `EXECUTION_DEADLINE_EXCEEDED` or
`EXECUTION_FAILED`, and has no evaluation record (`404`).

## Historical re-evaluation

Design: [ADR-0014](../adr/0014-historical-policy-re-evaluation.md).

### Request a re-evaluation

`POST /api/v1/scans/{scanId}/reevaluations`, body `{"policyVersionId": "<uuid>"}`
(`reevaluation-request` schema; any other property is rejected with `400`).

- Evaluates the scan's **persisted evidence of record** under the named version, with the
  same engine and precedence as the gate, **as of the original decision time** (the
  original evaluation's `evaluatedAt`, or the scan's completion time if it had no policy).
- Only `COMPLETED` scans. Any stored version of the scan's organization is eligible,
  active or not.
- `201` with `Location: /api/v1/scans/{scanId}/evaluations/{id}`,
  `Idempotent-Replayed: false` and a `scan-evaluation` body.
- `200` with `Idempotent-Replayed: true` and the existing record when the same
  re-evaluation (scan, version, engine version, evidence fingerprint) was recorded before.
  Nothing is written.
- `404` for an unknown scan or a non-member, and for an unknown or foreign policy version
  (`PolicyVersion was not found.`). `403 insufficient-role` for MEMBER and VIEWER.
- `409` with `code`: `scan-not-completed`, `policy-version-unusable` (the stored version no
  longer validates; nothing recorded), `reevaluation-limit-reached` (100 per scan),
  `evaluation-inputs-changed` (evidence changed during the request; retry).
- Never changes the scan, its decision, its pinned policy, its jobs, its original
  evaluation or the project's active policy; never runs a scanner or publishes a message.

### Read the evaluation history

`GET /api/v1/scans/{scanId}/evaluations?page=&size=` → `scan-evaluation-page`, oldest first
(recording time; the original before a re-evaluation recorded at the same instant; then
id). `size` ≤ 100. `GET /api/v1/scans/{scanId}/evaluations/{evaluationId}` →
`scan-evaluation`; a record of another scan is `404`.

`scan-evaluation` has every field of `policy-evaluation` plus:

| Field | Meaning |
|---|---|
| `evaluationType` | `ORIGINAL` (the gate evaluation) or `HISTORICAL` |
| `gating` | `true` only for `ORIGINAL`; a historical record never decides anything |
| `initiatedBy` | `supervisor`, or `user:<identity id>` of the requester (never a name or token subject) |
| `inputsSha256` | Fingerprint of the evidence and as-of instant a historical record was computed from; `null` for `ORIGINAL` |
| `evaluatedAt` | The as-of instant (for a re-evaluation: the original decision time) |
| `recordedAt` | When the record was written |

Records are returned as stored; nothing is recalculated when read. Evidence content,
finding text and paths are never returned.

## Example

```text
POST /api/v1/organizations/{org}/policies        (ADMIN)  → 201, version 1, sha256 S
PUT  /api/v1/projects/{project}/policy           (OWNER)  → 200, version 1 in force
POST /api/v1/projects/{project}/scans            (MEMBER) → 202, scan pinned to version 1
     … workers run the planned scanners; the supervisor evaluates …
GET  /api/v1/scans/{scan}                                  → COMPLETED / FAIL / POLICY_EVALUATED
GET  /api/v1/scans/{scan}/evaluation                       → reasons: BLOCKING_FINDINGS_EXCEEDED (GITLEAKS, observed 2, limit 0)
POST /api/v1/organizations/{org}/policies        (ADMIN)  → 201, version 2 (allows 2 secrets), not activated
POST /api/v1/scans/{scan}/reevaluations          (ADMIN)  → 201, HISTORICAL, gating false, PASS under version 2
GET  /api/v1/scans/{scan}                                  → still COMPLETED / FAIL / POLICY_EVALUATED
GET  /api/v1/scans/{scan}/evaluations                      → ORIGINAL (FAIL, version 1), HISTORICAL (PASS, version 2)
```

## Security exceptions

[ADR-0015](../adr/0015-security-exceptions-and-independent-approval.md) (proposed). An
exception accepts **one** verified blocking finding of a scan's **original FAIL**
evaluation until an expiry. It needs an OWNER other than the requester, never changes the
scan's decision, evidence or evaluations, and never covers an INCOMPLETE condition.

### Request

`POST /api/v1/scans/{scanId}/exceptions` (ADMIN or OWNER), body
`security-exception-request`:

```json
{"scanner": "GITLEAKS", "findingFingerprint": "<64 hex>",
 "justification": "Synthetic fixture credential, revoked; tracked in SEC-123.",
 "expiresAt": "2026-10-25T12:00:00Z"}
```

- The server re-runs the original evaluation over the current evidence of record and the
  database verifies that the fingerprint occurs **exactly once**, as a blocking finding of a
  scanner with a violation, in the stored `findings.json`. Evaluation, policy version and
  digest, engine version, job, evidence digests, rule, category and severity are derived,
  never accepted. Unknown properties (`requestedBy`, `status`, ...) are `400`.
- `expiresAt`: 1 hour 1 minute to 90 days after the request (database clock), else `400`.
- `201` with `security-exception` (state `REQUESTED`) and `Location`.
- `409`: `scan-not-exceptionable`, `evaluation-not-reproducible`,
  `finding-not-exceptionable` (deliberately not more specific), `exception-request-exists`
  (an open request or active exception exists for the finding), `exception-limit-reached`
  (200 per scan).

### Decide

`POST .../exceptions/{exceptionId}/approve | reject | withdraw | revoke`, body
`security-exception-decision` (`{"rationale": "..."}`, 1 to 1,000 characters), returns the
updated `security-exception`.

| Action | Transition | Who |
|---|---|---|
| approve | REQUESTED → APPROVED | an OWNER other than the requester (`403 self-decision-forbidden`) |
| reject | REQUESTED → REJECTED | an OWNER other than the requester |
| withdraw | REQUESTED → WITHDRAWN | the requester (`403 not-requester`) |
| revoke | APPROVED → REVOKED | an OWNER |

`409`: `invalid-exception-transition` (not in the state the action leaves, including
concurrent decisions: exactly one wins), `exception-expired`, `exception-expires-too-soon`
(approval with under 5 minutes left), `evaluation-not-reproducible` (approval when the
evidence changed or was purged).

### Read

`GET /api/v1/scans/{scanId}/exceptions?page=&size=` → `security-exception-page` (oldest
first, `size` ≤ 100); `GET .../exceptions/{exceptionId}` → `security-exception`. A request of
another scan is `404`.

| Field | Meaning |
|---|---|
| `state` | Last recorded transition |
| `status` | At the database clock (`statusAsOf`): `ACTIVE` only for an unexpired approval; `EXPIRED` for REQUESTED or APPROVED past `expiresAt` |
| `transitions` | Immutable history: sequence, from, to, actor (`user:<identity id>`), verified role, rationale, database time |
| `evaluationId`, `policyVersionId`, `policySha256`, `engineVersion`, `jobId`, `leaseEpoch`, `artifactSha256`, `resultSha256` | The binding |
| `finding` | Fingerprint, rule id, category, scanner severity; never paths or evidence content |

### Effective gate

`GET /api/v1/scans/{scanId}/gate` (VIEWER and above) → `effective-gate`, computed on every
request (`Cache-Control: no-store`), never stored. `effectiveDecision` is `PASS`, `FAIL`,
`INCOMPLETE` or `RISK_ACCEPTED` (never PASS; `exceptionBased: true`, `validUntil`). See
[decision semantics](../architecture/policy-decision-semantics.md#security-exceptions-and-the-effective-gate).
No integration consumes it yet; the scan's `securityDecision` remains the original
decision.

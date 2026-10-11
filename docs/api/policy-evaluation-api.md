# Policy and evaluation API (M4 Phase 1)

Five operations under `/api/v1`, documented in
[`sentinel-api-v1.yaml`](../../packages/contracts/openapi/sentinel-api-v1.yaml) (tag
`Policies`) with JSON Schemas in `packages/contracts/schemas/v1`. Design:
[ADR-0013](../adr/0013-security-policy-engine.md). Like the rest of the domain API, these
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

- Activation is OWNER-only because it can weaken the gate; drafting is ADMIN.
- A policy version of another organization is reported as `404 PolicyVersion was not
  found.`, identical to a nonexistent one. The database refuses cross-tenant activation
  independently (composite foreign keys).
- There is **no** endpoint that evaluates, re-evaluates or records a decision. The
  supervisor evaluates scans once execution has finished; no internal evaluation endpoint
  exists that could bypass authorization.
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

## Example

```text
POST /api/v1/organizations/{org}/policies        (ADMIN)  → 201, version 1, sha256 S
PUT  /api/v1/projects/{project}/policy           (OWNER)  → 200, version 1 in force
POST /api/v1/projects/{project}/scans            (MEMBER) → 202, scan pinned to version 1
     … workers run the planned scanners; the supervisor evaluates …
GET  /api/v1/scans/{scan}                                  → COMPLETED / FAIL / POLICY_EVALUATED
GET  /api/v1/scans/{scan}/evaluation                       → reasons: BLOCKING_FINDINGS_EXCEEDED (GITLEAKS, observed 2, limit 0)
```

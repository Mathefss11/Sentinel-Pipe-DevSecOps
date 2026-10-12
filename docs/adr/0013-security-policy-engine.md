# ADR-0013: Security policy engine

- **Status:** Accepted (2026-10-11; see [Acceptance](#acceptance)). Proposed until then.
- **Date:** 2026-10-11
- **Milestone:** M4 Phase 1 (first vertical slice)
- **Builds on:** [ADR-0007](0007-database-authoritative-execution-leases.md) (lifecycle and
  fencing), [ADR-0008](0008-result-integrity-and-evidence.md) (evidence of record),
  [ADR-0010](0010-scanner-adapters-repository-snapshots-and-findings.md) to
  [ADR-0012](0012-trivy-sca-with-an-embedded-verified-database.md) (`findings.v1`)
- **Amends:** ADR-0007 (`lifecycle.complete_evaluation` can no longer record PASS or FAIL)
- **Deviates from:** the original roadmap's "OPA/Rego policies" for M4. The repository
  owner approved this **direction** on 2026-10-11 as an intentional roadmap deviation (see
  [Roadmap deviation](#roadmap-deviation-an-in-process-engine-instead-of-oparego)). The ADR
  itself stays **Proposed** until the final security review and a successful remote CI run;
  the approval of the direction is not an acceptance of this ADR. The ADR was accepted on
  2026-10-11 after remote CI #14 succeeded (see [Acceptance](#acceptance)).
- **Specifications:** [policy.v1](../api/policy-contract-v1.md),
  [decision semantics](../architecture/policy-decision-semantics.md),
  [policy API](../api/policy-evaluation-api.md)
- **Threat model:** [Policy engine](../threat-model/policy-engine.md)
- **Security review:** [M4 Phase 1 review](../security/m4-phase1-security-review.md)
- **Runbook:** [Policy engine](../runbooks/policy-engine.md)

## Context

Since M3 every completed scan is `INCOMPLETE` with reason `POLICY_EVALUATION_UNAVAILABLE`:
scanners produce verified, normalized evidence (`findings.v1`), but nothing judges it. M4
must turn evidence into a gate decision without weakening the invariants built so far:

- execution status and security decision stay independent; `COMPLETED` never implies
  `PASS`;
- absence of findings is not proof of security: every scanner states what it did not
  cover, and the scanners are not comprehensive;
- evidence is tenant-scoped, lease-fenced and digest-verified by PostgreSQL (ADR-0008),
  but a worker is trusted only for its own job;
- severity scales differ per scanner (Gitleaks has none; Semgrep `ERROR`/`WARNING`/`INFO`;
  Trivy `CRITICAL`…`UNKNOWN`);
- PostgreSQL is the single authority for execution state (ADR-0007).

The repository inspection found one gap that M4 had to close first: the API's database
role could call `lifecycle.complete_evaluation(scan, 'PASS', 'POLICY_EVALUATED')` for any
EVALUATING scan whose jobs completed. A PASS needed no evaluation record at all
(security review M4-1).

## Decision

### 1. A small, deterministic engine in the control plane

The engine is a pure Java function (`PolicyEvaluator`) of three inputs, all read from
PostgreSQL in one snapshot under the scan row lock:

1. the scan's **pinned** policy version (canonical text and digest);
2. the authoritative scan context (organization, project, scan, commit) and the
   database clock;
3. every job of the scan with its evidence of record: the accepted `COMPLETED` result of
   the job's **current** lease epoch and the artifacts that result references.

It has no expression language, no `eval`, no scripts, no plugins and no network or clock
access of its own. It lives in the modular monolith (`dev.sentinelpipe.api.policy`); no
new service is introduced.

### 2. policy.v1: declarative, closed, canonical

A policy is a JSON document validated against a closed JSON Schema
(`packages/contracts/schemas/v1/policy-definition.schema.json`, bundled byte-identically
in the API):

- every scanner listed under `scanners` is **mandatory**;
- per scanner: `require_complete_coverage`, `accepted_limitations` (an explicit
  allowlist), `max_blocking_findings`, and, except for Gitleaks, `blocking_severities`
  from **that scanner's own** label set; Trivy also has `max_database_age_seconds`;
- global: accepted `findings_schema_versions` (only `1`) and `max_age_seconds` for evidence;
- unknown fields, other scanners, foreign severity labels, out-of-range numbers,
  non-integer literals, duplicate keys and trailing content are rejected;
- `EMPTY_INPUT` and `NO_SUPPORTED_FILES` can never be accepted (the scanner examined
  nothing);
- the definition is rebuilt from the validated model in canonical JSON (sorted keys and
  set-like arrays, no whitespace, ASCII) and identified by the SHA-256 of that text.

Bounded complexity: at most 3 scanners, 24 limitations each, 16 KiB per definition
(checked before parsing; the request body is read with a hard bound).

### 3. Immutable versions, owner-only activation, pinning at request time

- **Versions** (`policy.policy_versions`) are immutable. The database recomputes the
  definition digest in a CHECK. Versions are numbered per policy name without gaps under a
  row lock.
- **Activation** is an append-only assignment (`policy.project_assignments`); the latest
  row is in force. Composite foreign keys `(project, organization)` and
  `(policy_version, organization)` make a cross-tenant assignment impossible in the
  database, independently of the API.
- **Pinning:** `ScanService` calls `policy.pin_scan_policy` in the scan's creating
  transaction, so each scan is evaluated against the version in force when it was
  requested. Later activations never change an existing scan's evaluation. A scan without
  a policy keeps the M3 behavior: `INCOMPLETE`, `POLICY_EVALUATION_UNAVAILABLE`.
- **Permissions:** VIEWER and above read policies and evaluations (`VIEW_POLICIES`,
  `VIEW_SCANS`); ADMIN and above create versions (`MANAGE_POLICIES`); only OWNER activates
  (`ACTIVATE_POLICY`). Activation can weaken the gate, so drafting and activation are
  separate duties.

### 4. Evaluation gates and decision precedence

Per mandatory scanner, evidence passes six gates
([semantics](../architecture/policy-decision-semantics.md)):

1. **execution** (the job `COMPLETED`);
2. **presence** (an accepted result of the current epoch referencing `findings.json`);
3. **integrity**: the stored result re-canonicalizes to its recorded `result_sha256`, it
   references the artifact of record with the same digest, size and media type, and the
   artifact bytes match the digest PostgreSQL computed;
4. **validity** (strict JSON, accepted `schema_version`, the `findings.v1` schema);
5. **binding and consistency**: the document names this organization, project, scan,
   job, commit and scanner, and does not contradict itself;
6. **policy**: evidence age, coverage, accepted limitations, required coverage metadata,
   Trivy database age, severity labels and blocking findings.

A document that fails gates 1 to 5 is discarded. Only gate 6 produces violations, so a
FAIL is always established by valid evidence.

**Precedence:** any `VIOLATION` reason → `FAIL`; else any `INCOMPLETE` reason →
`INCOMPLETE`; else `PASS`. A confirmed violation is never hidden by missing evidence
elsewhere, and the record still lists every incomplete reason (`incompleteCount`), so
"FAIL, and also incomplete" is distinguishable from "FAIL on complete evidence". Both FAIL
and INCOMPLETE block a merge.

Severities are compared only within each scanner's own scale. A label outside that scale,
or a missing label where the scanner must provide one, is
`UNSUPPORTED_SCANNER_SEVERITY` (INCOMPLETE): never guessed and never silently ignored.

### 5. The database refuses inconsistent records

`policy.record_evaluation` writes the evaluation and completes the scan in one
transaction. It does not evaluate findings, but it refuses (SQLSTATE 22023,
`evaluation rejected: <CODE>`, nothing changed):

- a decision that does not follow from the reasons (`DECISION_INCONSISTENT`);
- a policy other than the pinned version and digest (`POLICY_MISMATCH`);
- an evidence reference that is not evidence of record of a `COMPLETED` job of this scan
  at its current epoch, with the recorded result and artifact digests
  (`EVIDENCE_NOT_OF_RECORD`);
- a violation attributed to a scanner without referenced evidence
  (`VIOLATION_WITHOUT_EVIDENCE`);
- PASS unless every job is `COMPLETED`, every job has an evidence reference, and the job
  scanners equal the policy's scanners (`PASS_NOT_JUSTIFIED`).

`lifecycle.complete_evaluation` is replaced in V009: it records only `INCOMPLETE` with
`POLICY_EVALUATION_UNAVAILABLE` or `SCANNER_EXECUTION_INCOMPLETE`, and refuses a scan with a
pinned policy (`POLICY_EVALUATION_REQUIRED`). Every **COMPLETED** policy-pinned scan therefore
has an evaluation record and reason `POLICY_EVALUATED` (for all three decisions). A pinned
scan that is cancelled or fails during execution (deadline, `fail_scan`) ends `CANCELLED` or
`FAILED` with decision `INCOMPLETE`, its own reason, and no evaluation record.

Since the final review (defect M4-5), two triggers make this a database invariant rather
than a property of the functions: scans and scan jobs written by any role other than a
superuser must be born in their initial state (`QUEUED`, no decision, no lease), and setting
PASS or FAIL, reason `POLICY_EVALUATED`, or `COMPLETED` on a pinned scan requires an
evaluation record with the same decision. The second check also applies inside `SECURITY
DEFINER` functions, which run as the schema owner.

### 6. Records, concurrency and failure handling

- `policy.evaluations` and `policy.evaluation_evidence` are immutable (no UPDATE or DELETE
  grant; triggers refuse UPDATE, DELETE and TRUNCATE even for the owner through ordinary
  statements). Reasons are stored as canonical JSON with a CHECK-recomputed digest. The
  record keeps the policy version and digest, the engine version
  (`sentinelpipe-policy/1.0.0`), the database time the inputs were read, and the evidence
  digests it relied on, so it stays auditable after later policy changes.
- One gate evaluation per scan (unique on `scan_id`). `ScanLifecycleService.evaluate`
  takes `SELECT … FOR UPDATE SKIP LOCKED` on the scan, so concurrent supervisors skip a
  scan being evaluated, and cancellation waits; the scan is EVALUATING, every job is
  terminal, and no worker can change its evidence (lease fencing, ADR-0007/0008).
- Fail closed: a pinned policy that no longer validates is recorded as `POLICY_INVALID`;
  an unexpected engine error as `EVALUATION_ERROR` (both INCOMPLETE). A record the database
  refuses leaves the scan EVALUATING (decision PENDING, never mergeable) and visible in
  the `sentinel.execution.scans.evaluating` gauge.

### 7. Trust boundary

| Party | Trusted for | Not trusted for |
|---|---|---|
| Worker (its database login, lease) | Uploading evidence and a result for its own leased job | Anything about another job, scan or tenant; the engine re-checks every identifier and discards mismatched evidence |
| Sandbox and scanner | Nothing beyond producing bytes the worker parses | Honest results: a compromised sandbox can misreport its own job (integrity, not authenticity) |
| PostgreSQL schema owner / superuser | Everything (as in ADR-0007/0008) | Not defended against: it can rewrite policies, evidence, digests and records consistently |
| API process and role | Evaluating (the engine runs here) | Recording an inconsistent decision: refused by `policy.record_evaluation` |

The digests prove that a stored item is the one recorded (integrity against corruption
and partial tampering, such as an altered stored result). They do not prove who produced
it: an attacker who can rewrite both the content and its digest is out of scope until
signed evidence and an external, append-only audit sink exist (M6/M7).

## Roadmap deviation: an in-process engine instead of OPA/Rego

The roadmap (README, project plan) named OPA/Rego for M4 policy evaluation. M4 Phase 1
deliberately uses a deterministic Java engine inside the control plane instead. The
repository owner approved this direction on 2026-10-11; it is recorded here so that the
deviation is visible and can be revisited.

**Rationale.**

- **No general-purpose policy language.** The required rules (mandatory scanners, blocking
  thresholds per scanner scale, accepted limitations, evidence and database age, schema
  versions) are expressible as a closed, data-only schema. Rego is a general language:
  tenant-authored Rego would be logic to review, bound and sandbox; platform-authored Rego
  would still need the same Java checks first.
- **Evidence verification must happen in the control plane anyway.** Integrity, binding to
  the scan and job, lease fencing and schema validation depend on database access and on
  the evidence-of-record model (ADR-0008). Those gates are most of the engine; the rule
  stage after them is small.
- **One transaction, one trust boundary.** Inputs, evaluation and the record are read and
  written under one scan row lock in one database transaction, and the database re-checks
  the record. An OPA call would add a network hop and a separately deployed component with
  its own availability, authentication (the Compose OPA does not authenticate clients) and
  version pinning, inside the decision path.
- **Determinism and auditability.** The engine is a pure function versioned by
  `ENGINE_VERSION`; the record stores the policy digest and the evidence digests.

**Trade-offs accepted.**

- Policy semantics live in Java code: changing them is a code change, a review and a new
  engine version, not a policy upload. Expressiveness is intentionally limited.
- Policy authors cannot express rules the schema does not offer (for example per-path or
  per-rule conditions); those need a reviewed schema extension.
- The project does not get OPA tooling (`opa test`, decision logs, bundles) for gate
  policies. Equivalent assurance comes from the decision-matrix tests and the evaluation
  records.
- OPA remains in the Compose stack for its current, unrelated use (the authorization
  policy test), so the stack keeps a component the gate does not use.

**Reconsider OPA/Rego when any of these holds:**

1. requirements need rules the closed schema cannot express without becoming a language
   (for example conditional logic across scanners, per-path or per-rule exceptions with
   predicates, organization-specific computed thresholds);
2. policies must be shared with or enforced by systems outside the control plane (for
   example CI-side or admission-control enforcement of the same decision);
3. a decision-logging or policy-distribution requirement appears that OPA bundles and
   decision logs would meet better than evaluation records.

Any reconsideration must keep, at minimum: evidence verification before policy input,
platform-owned (not tenant-authored) Rego unless a separate review approves otherwise,
pinned and digest-verified bundles, evaluation in the same trust boundary or an
authenticated call, the fail-closed precedence of this ADR, and records that remain
reproducible. It would be a new ADR.

## Consequences

- PASS is now possible. It means: the pinned policy's requirements were met by the
  evidence of record, **including the limitations the policy explicitly accepts**. With
  local fixtures, PASS requires accepting `COMMIT_NOT_VERIFIED`. PASS is never a statement
  that a project is secure; the scanners are not comprehensive, and their documented
  limits remain.
- The production restrictions are unchanged: Gitleaks, Semgrep and Trivy are still refused
  in production, so the engine has no production effect yet.
- `json-schema-validator` (networknt 3.0.8, already used in tests) is now a runtime
  dependency of the API.
- Scans requested before a policy is activated, and scans whose evidence is older than the
  policy allows when the supervisor evaluates them, stay INCOMPLETE; there is no
  re-evaluation yet (Phase 2).

## Acceptance

- **Decision:** Accepted.
- **Date:** 2026-10-11.
- **Decision owner:** the repository owner (recorded on the owner's instruction; no
  restriction is waived).
- **Supporting CI:** GitHub Actions run #14 on `main`, commit `00d5e78`, all six jobs
  green (5 min 4 s), as reported by the repository owner.
- **Basis:** the [M4 Phase 1 security review](../security/m4-phase1-security-review.md)
  (defects M4-1 to M4-7 fixed or corrected with regression tests; verdict: ready for commit
  and remote CI) and that CI run.
- **Accepted architectural deviation:** the deterministic in-process Java engine replaces
  the roadmap's OPA/Rego for gate decisions, under the rationale, trade-offs and
  reconsideration triggers recorded in
  [Roadmap deviation](#roadmap-deviation-an-in-process-engine-instead-of-oparego).
- **Residual risks accepted as documented** (security review R1 to R10, unchanged):
  - R1: a compromised control plane can record a consistent but false evaluation;
  - R2: the database owner or a superuser can rewrite policies, evidence, digests and
    records consistently; there is no external anchor;
  - R3: integrity, not authenticity: a compromised sandbox or worker can produce false
    clean evidence for its own job;
  - R4: PASS is relative to the policy's explicitly accepted limitations and to
    non-comprehensive scanners; with local fixtures PASS requires accepting
    `COMMIT_NOT_VERIFIED`;
  - R5: a single gate evaluation per scan; evidence stale at evaluation is INCOMPLETE;
  - R6: activation without a two-person rule; no security exceptions;
  - R7: the architecture deviation above;
  - R8: an evaluation record does not list the accepted limitations the evidence carried;
  - R9: the invariant triggers exempt superusers, and the schema owner can disable triggers;
  - R10: rows written before V009 are not re-validated by the invariant triggers.
- **Non-production restrictions:** unchanged. Gitleaks, Semgrep and Trivy scan local
  synthetic fixtures only and stay refused in production by worker and API; Trivy remains
  disabled in production; Docker/runc is not a boundary for hostile repositories; the
  domain API stays disabled by default and loopback-only. The engine therefore has no
  production effect. There is no production authorization of any kind.
- **Follow-up work for later milestones:** re-evaluation (M4 Phase 2,
  [ADR-0014](0014-historical-policy-re-evaluation.md), proposed), security exceptions with
  a two-person rule, finding comparison, remediation reports, a policy audit API, recording
  accepted limitations in evaluation records (R8), and signed evidence or attestations with
  an external append-only audit sink (M6/M7) to address R2 and R3.

## Remaining M4 roadmap (not implemented)

1. **Re-evaluation** under a later policy version as additional, non-gating records
   (OWNER), never rewriting the original decision.
2. **Security exceptions:** explicit scope, justification, approver, expiry and audit;
   expired exceptions never bypass a policy; a two-person rule for activation and
   exceptions.
3. **Finding identity and comparison:** NEW / EXISTING / RESOLVED only when coverage is
   comparable.
4. **Deterministic remediation knowledge base and reports** (Markdown, HTML, JSON).
5. **Policy audit API** (activation history) and policy listing.
6. **Signed evidence or attestations** to move from integrity to authenticity (with M6).

## Alternatives considered

- **OPA/Rego (the roadmap's original plan).** Not chosen for Phase 1 (approved direction;
  see [Roadmap deviation](#roadmap-deviation-an-in-process-engine-instead-of-oparego)). Rego is a general
  policy language: tenant-authored Rego would be arbitrary logic to review and bound; a
  platform-owned Rego bundle would still need the same evidence verification in Java
  before data reaches it; and the decision would cross a network boundary to a separate
  OPA service (or need an embedded evaluator). The closed policy.v1 schema covers the
  required rules with no expressions at all. OPA stays available (Compose) and could
  evaluate platform-owned rules over already-verified, normalized inputs later; that would
  be a new decision for the owner.
- **Evaluating findings in PL/pgSQL.** Would make the database the evaluator, but
  re-implementing strict JSON Schema validation and the gates in SQL is error-prone. The
  database instead enforces the invariants of the record (section 5).
- **Policy at evaluation time instead of pinning at request time.** Rejected: a policy
  change between request and evaluation would change the outcome (TOCTOU), and the record
  would be harder to reproduce.
- **A universal severity scale.** Rejected: mapping Semgrep `ERROR` onto Trivy `HIGH`
  invents equivalence. Each scanner keeps its own labels.
- **Treating INCOMPLETE as dominant over FAIL.** Rejected: it would hide a confirmed
  violation behind an unrelated missing scanner.

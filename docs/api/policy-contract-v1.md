# Policy contract v1 (`policy.v1`)

- **Schema:** [`packages/contracts/schemas/v1/policy-definition.schema.json`](../../packages/contracts/schemas/v1/policy-definition.schema.json)
  (JSON Schema 2020-12). The API bundles a byte-identical copy
  (`services/sentinel-api/src/main/resources/contracts/`), checked by
  `PolicyDocumentsTests`.
- **Design:** [ADR-0013](../adr/0013-security-policy-engine.md);
  [decision semantics](../architecture/policy-decision-semantics.md).
- **Validation and canonicalization:** `PolicyDocuments` (API). The database re-checks the
  structure and recomputes the digest (`policy.create_policy_version`, Flyway V009).

## Document

```json
{
  "schema_version": 1,
  "name": "baseline",
  "evidence": { "findings_schema_versions": [1], "max_age_seconds": 86400 },
  "scanners": {
    "GITLEAKS": {
      "require_complete_coverage": true,
      "accepted_limitations": ["ARCHIVES_NOT_SCANNED", "COMMIT_NOT_VERIFIED", "GIT_HISTORY_NOT_SCANNED", "RULESET_DEFAULT_ONLY"],
      "max_blocking_findings": 0
    },
    "SEMGREP": {
      "require_complete_coverage": true,
      "accepted_limitations": ["COMMIT_NOT_VERIFIED", "PARSE_COMPLETENESS_UNVERIFIED", "PATTERN_MATCHING_ONLY", "RULESET_MINIMAL", "UNSUPPORTED_FILES_PRESENT"],
      "blocking_severities": ["ERROR", "WARNING"],
      "max_blocking_findings": 0
    },
    "TRIVY": {
      "require_complete_coverage": true,
      "accepted_limitations": ["ADVISORY_DATA_POINT_IN_TIME", "COMMIT_NOT_VERIFIED", "REACHABILITY_NOT_ANALYZED"],
      "blocking_severities": ["CRITICAL", "HIGH"],
      "max_blocking_findings": 0,
      "max_database_age_seconds": 172800
    }
  }
}
```

| Field | Meaning |
|---|---|
| `schema_version` | `1`. Any other value is rejected |
| `name` | `^[a-z0-9][a-z0-9-]{0,62}$`. Versions of the same name in an organization form one policy, numbered 1, 2, … |
| `evidence.findings_schema_versions` | Accepted `findings.v1` schema versions: exactly `[1]` in this engine |
| `evidence.max_age_seconds` | 60 s to 30 days. A job's evidence older than this at evaluation (job completion to evaluation, database clock) is `EVIDENCE_STALE` |
| `scanners` | 1 to 3 of `GITLEAKS`, `SEMGREP`, `TRIVY`. **Every listed scanner is mandatory**; a scan job of an unlisted scanner type is `SCANNER_NOT_IN_POLICY` |
| `require_complete_coverage` | When `true`, `coverage.complete = false` is `COVERAGE_INCOMPLETE` |
| `accepted_limitations` | Allowlist of `coverage.limitations` codes the policy accepts. Every other code in the evidence is `COVERAGE_LIMITATION_NOT_ACCEPTED`. Per-scanner vocabularies below; `EMPTY_INPUT` and `NO_SUPPORTED_FILES` can never be accepted |
| `blocking_severities` | Semgrep and Trivy only, at least one: **the scanner's own** labels whose findings are blocking. Forbidden for Gitleaks, which has no severity (every Gitleaks finding is blocking) |
| `max_blocking_findings` | 0 to 1000. More distinct blocking findings than this is `BLOCKING_FINDINGS_EXCEEDED` (a violation: FAIL) |
| `max_database_age_seconds` | Trivy only, required, 1 hour to 7 days |

### Per-scanner vocabularies

| Scanner | Severity labels | Acceptable limitations |
|---|---|---|
| `GITLEAKS` | none | `FILES_SKIPPED`, `COMMIT_NOT_VERIFIED`, `GIT_HISTORY_NOT_SCANNED`, `ARCHIVES_NOT_SCANNED`, `RULESET_DEFAULT_ONLY` |
| `SEMGREP` | `ERROR`, `WARNING`, `INFO` | `FILES_SKIPPED`, `COMMIT_NOT_VERIFIED`, `FILES_NOT_ANALYZED`, `UNSUPPORTED_FILES_PRESENT`, `RULESET_MINIMAL`, `PATTERN_MATCHING_ONLY`, `PARSE_COMPLETENESS_UNVERIFIED` |
| `TRIVY` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` | `FILES_SKIPPED`, `COMMIT_NOT_VERIFIED`, `FILES_NOT_ANALYZED`, `ADVISORY_DATA_POINT_IN_TIME`, `REACHABILITY_NOT_ANALYZED`, `VULNERABILITY_DB_STALE`, `SYNTHETIC_VULNERABILITY_DATABASE`, `PARTIAL_DEPENDENCY_RESOLUTION`, `UNRESOLVED_DEPENDENCY_VERSIONS`, `DEPENDENCY_LOCKFILE_MISSING`, `UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT`, `BINARY_ARTIFACTS_NOT_ANALYZED`, `PACKAGE_VALUES_REDACTED`, `PYPI_NAME_MATCHING_UNVERIFIED`, `DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED` |

Severity labels are **not** a shared scale. Semgrep's `ERROR` is a rule author's label,
Trivy's `HIGH` is selected by Trivy from advisory sources, and Gitleaks has none. Trivy's
`UNKNOWN` is a real label (an advisory without a severity); a policy blocks it only by
listing it.

Every current scanner document carries limitations it cannot avoid (for example
`COMMIT_NOT_VERIFIED` for local fixtures, `RULESET_MINIMAL` for Semgrep,
`ADVISORY_DATA_POINT_IN_TIME` for Trivy). A policy that should ever PASS must accept them
**explicitly**; that acceptance is visible in the stored definition and its digest.

## Validation rules

- Strict parsing: duplicate keys, trailing content, `NaN` and non-JSON input are refused.
- The closed schema: unknown fields at any level, unknown scanners and values outside the
  vocabularies are refused.
- Integers must be integer literals (`86400.0` is refused even though JSON Schema's
  `integer` would admit it).
- At most 16 KiB; the API reads the request body with that bound and never buffers more.
- Errors are RFC 9457 `validation-error` problems. Each lists a location rebuilt from
  schema property names (anything else becomes `*`) and a fixed message. Submitted values
  and unknown key names are never echoed.

## Canonical form and digest

The stored definition is rebuilt from the validated model:

- keys sorted by code point, no whitespace, ASCII output (`json.dumps(sort_keys=True,
  separators=(",", ":"), ensure_ascii=True)` compatible, verified against CPython);
- set-like arrays (`accepted_limitations`, `blocking_severities`,
  `findings_schema_versions`) sorted.

`definitionSha256` is the SHA-256 of that text. Equivalent definitions (different key
order, array order or formatting) have the same digest; any semantic change changes it.
PostgreSQL recomputes the digest in a CHECK on every stored version. Before each
evaluation the engine re-validates the stored text and requires it to be canonical and to
match its digest; otherwise the evaluation is `POLICY_INVALID` (INCOMPLETE).

## Compatibility

- The version is in `schema_version` (and the file name). The engine rejects unknown
  versions.
- Compatible changes within v1: none planned. New scanners, labels or limitation codes
  need explicit vocabulary changes, reviewed like any rule change.
- Changes that need v2: new rule types, defaults, or anything that changes the meaning of
  an existing definition. The canonical form is part of v1: changing it would make stored
  versions fail re-validation (fail closed).

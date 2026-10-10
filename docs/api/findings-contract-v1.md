# Findings contract v1 (`findings.v1`)

- **Schema:** [`packages/contracts/messages/v1/findings.v1.schema.json`](../../packages/contracts/messages/v1/findings.v1.schema.json)
  (JSON Schema 2020-12, `$id` `https://sentinelpipe.dev/schemas/messages/v1/findings.v1.schema.json`)
- **Producer:** the worker, from one scanner run ([ADR-0010](../adr/0010-scanner-adapters-repository-snapshots-and-findings.md))
- **Transport:** the evidence artifact `findings.json` (`application/json`) of a
  `job-result.v1` result. It is stored through `worker.put_evidence`: digest computed by
  PostgreSQL, tenant-scoped and bound to the lease (ADR-0008).

## Semantics

- A findings document records **observations**, not a decision:
  - an empty `findings` array does not mean `PASS`;
  - a non-empty one does not by itself mean `FAIL`;
  - gate decisions require versioned policy evaluation (M4).
- Only successful scanner runs produce a document. A failed run (scanner error, timeout,
  limits) produces none, and the job is `FAILED` with its reason.
- Every document states what it **does not** cover (`coverage.limitations`) and whether
  scannable content was skipped (`coverage.complete`).

## Structure

| Field | Meaning |
|---|---|
| `schema_version` | `1` |
| `scanner` | `name`, `version`, digest-pinned `image` |
| `context` | Organization, project, scan, job and commit from the **database lease** |
| `input.kind` | `LOCAL_FIXTURE` (only kind in v1) |
| `input.commit_verified` | Whether the bytes were proven to be `context.commit_sha`; `false` for local fixtures |
| `input.content_sha256` | SHA-256 over `path NUL sha256(content) LF` for every scanned file in path order |
| `input.files_scanned`, `input.bytes_scanned` | Size of the snapshot |
| `input.paths_redacted` | Number of scanned files whose stored path contains a redacted component |
| `input.skipped` | Counts per reason: `symlink`, `special_file`, `hardlink`, `oversized`, `unsupported_name` (each makes coverage incomplete); `vcs_metadata`, `suppression_file` (excluded by design) |
| `coverage.complete` | `false` when scannable files were skipped |
| `coverage.limitations` | Subset of `FILES_SKIPPED`, `EMPTY_INPUT` (nothing was scanned), `COMMIT_NOT_VERIFIED`, `GIT_HISTORY_NOT_SCANNED`, `ARCHIVES_NOT_SCANNED`, `RULESET_DEFAULT_ONLY` |
| `execution` | `status` (`NO_FINDINGS` / `FINDINGS_DETECTED`), the scanner's `exit_code` (Gitleaks script: 0, 41 content, 42 file names, 43 both), and `raw_report_sha256` (the native reports are parsed but not stored) |
| `finding_count` | Number of distinct findings (≤ 1000) |
| `findings[]` | See below; sorted by path, start line, start column, rule id, fingerprint |

### Finding

| Field | Meaning | Gitleaks |
|---|---|---|
| `id` | UUIDv5 of `"<job id>/<fingerprint>"`; deterministic per job | ✓ |
| `fingerprint` | SHA-256 of the canonical JSON array `["sentinelpipe.finding.v1", scanner, rule_id, target, safe path, start_line, end_line, start_column, end_column]` | ✓ |
| `scanner` | `name`, `version` | ✓ |
| `rule_id` | Scanner rule (`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`) | e.g. `github-pat` |
| `category` | `SECRET` (v1) | ✓ |
| `description` | Scanner-provided, sanitized, ≤ 512 characters, or `null` | Rule description |
| `location` | `target` (`FILE_CONTENT` or `FILE_PATH`); `path`, the **safe** relative POSIX path of a snapshot file (redacted components appear as `[redacted-N]`, ≤ 1024 characters, no control characters or backslashes); `path_redacted`; `start_line`, `end_line` (1-based), `start_column`, `end_column`. All four are `null` for `FILE_PATH`, which the schema enforces | ✓ |
| `severity` | `null` unless the scanner provides one | `null` (not provided) |
| `confidence` | `null` unless the scanner provides one | `null` (not provided) |
| `evidence` | `redacted` and `excerpt`. **For `SECRET`, the schema requires `{redacted: true, excerpt: null}`** | Always redacted, no excerpt |
| `remediation` | `null`, or `summary` and `references` when a scanner or the knowledge base (M4) provides them | `null` |
| `status` | `OPEN`: detected in this run, not triaged | `OPEN` |
| `occurrences` | Identical fingerprints merged in this run | ≥ 1 |

## Paths are sensitive

File and directory names are repository content and can contain credentials. Paths are
persisted only in a safe form:

- **Components replaced by a `[redacted-N]` label:**
  - components that the scanner detected in a scan of the path manifest. These are also
    reported as `FILE_PATH` findings;
  - components a heuristic flags (credential prefixes, long high-entropy runs of
    letters and digits).
- **Labels:** numbered per snapshot in the sorted order of the distinct redacted
  components, so identical snapshots produce identical documents. A redacted component
  is redacted wherever it occurs.
- **Limits:** redaction of names is best-effort. It over-redacts some harmless names
  (for example long content hashes), and cannot recognize a secret that matches no rule
  and looks low-entropy.

## Determinism and deduplication

- **Same bytes for the same input.** The same snapshot scanned for the same job yields
  byte-identical documents: canonical JSON (sorted keys, no whitespace, ASCII escapes),
  deterministic order and ids. This is independent of the scanner's output order, which
  is concurrent for Gitleaks.
- **What a fingerprint means.** Fingerprints are identical across jobs and tenants for
  the same rule and (safe) location. They contain **no secret value and no raw path**;
  the secret is deliberately not hashed, because a hash of a weak secret can be
  brute-forced.
- **Digests over raw material.** `input.content_sha256` and `execution.raw_report_sha256`
  are computed over material that may contain secrets (contents, raw names). They cannot
  be inverted, but they can confirm a complete guess. Do not publish them outside the
  tenant without review.
- **Within one run,** findings with the same fingerprint are merged and counted in
  `occurrences`.
- **Across runs,** fingerprints are location-based: a finding that moves gets a new
  fingerprint. Correlating findings across commits, and the `NEW` / `EXISTING` /
  `RESOLVED` states, require valid, comparable coverage and belong to M4.

## Bounds

- At most 1000 findings, and 1 MiB for the canonical document (the evidence artifact
  limit).
- Strings and arrays are bounded by the schema.
- A run exceeding a bound fails with `RESOURCE_LIMIT_EXCEEDED`; findings are never
  truncated.

## Compatibility

- The version lives in the file name, the `$id` and `schema_version`. Consumers must
  reject unknown versions.
- **Compatible changes within v1:** new scanner names, categories, limitation codes and
  input kinds, documented in advance. Consumers must treat unknown enum values as
  unsupported, not as clean.
- **Changes that need v2:** removing or renaming fields, changing the fingerprint
  algorithm, or relaxing the redaction rule.
- **Validation:** the Python worker validates every document before upload. The Java
  tests validate the schema against the 2020-12 meta-schema, validate its example, and
  validate the documents produced in the end-to-end tests.

## Sample (redacted)

From a Gitleaks 8.30.1 run of a synthetic repository (identifiers and digests shortened;
fields updated to the reviewed contract):

```json
{
  "schema_version": 1,
  "scanner": {"name": "gitleaks", "version": "8.30.1", "image": "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…bbb7f"},
  "context": {"organization_id": "…", "project_id": "…", "scan_id": "…", "job_id": "…", "commit_sha": "aaaa…"},
  "input": {"kind": "LOCAL_FIXTURE", "commit_verified": false, "content_sha256": "101e6dc3…4786",
            "files_scanned": 2, "bytes_scanned": 148, "paths_redacted": 0,
            "skipped": {"symlink": 0, "special_file": 0, "hardlink": 0, "oversized": 0,
                        "unsupported_name": 0, "vcs_metadata": 0, "suppression_file": 1}},
  "coverage": {"complete": true,
               "limitations": ["ARCHIVES_NOT_SCANNED", "COMMIT_NOT_VERIFIED", "GIT_HISTORY_NOT_SCANNED", "RULESET_DEFAULT_ONLY"]},
  "execution": {"status": "FINDINGS_DETECTED", "exit_code": 41, "raw_report_sha256": "31284e6b…6dfb"},
  "finding_count": 3,
  "findings": [
    {"id": "2f1b8519-c42b-5085-a2e3-e6a4a70417fc",
     "fingerprint": "345e9fee064d9ba9ca2f40cb623321cf59639c02b1ca0c2fb51108b086c1212b",
     "scanner": {"name": "gitleaks", "version": "8.30.1"},
     "rule_id": "github-pat", "category": "SECRET",
     "description": "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
     "location": {"target": "FILE_CONTENT", "path": "app.py", "path_redacted": false,
                  "start_line": 1, "end_line": 1, "start_column": 10, "end_column": 49},
     "severity": null, "confidence": null,
     "evidence": {"redacted": true, "excerpt": null},
     "remediation": null, "status": "OPEN", "occurrences": 1}
  ]
}
```

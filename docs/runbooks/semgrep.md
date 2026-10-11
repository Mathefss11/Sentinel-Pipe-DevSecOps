# Runbook: Semgrep scanner

Design: [ADR-0011](../adr/0011-semgrep-sast-with-a-bundled-ruleset.md). Threat model:
[Semgrep scanner](../threat-model/semgrep-scanner.md). General operations:
[execution runbook](execution.md); shared input mechanics: [Gitleaks runbook](gitleaks.md).

**Scope in this version:** development and CI only. Semgrep scans synthetic repositories
from a local fixture directory. The worker refuses it in `production`, and the API
refuses `SEMGREP` in `planned-scanners` under production profiles.

## 1. Pinned image and ruleset

| | |
|---|---|
| Version | Semgrep **1.179.0** (Community Edition CLI) |
| Image | `semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b` (same index digest as `returntocorp/semgrep:1.179.0`; linux/amd64 only) |
| Ruleset | `sentinel_worker/scanners/semgrep-rules.json`: 13 rules authored in this repository (Java, Python, JavaScript, TypeScript). SHA-256 `d52217f6e2fd6af5c0e609c8cfdb4652751e86ba193abc38a409280f01516a1f` (`RULESET_SHA256`) |
| Defined in | `SEMGREP_IMAGE` and `IMAGE_ENVIRONMENT` (`sandbox/policy.py`); CI pre-pulls the same digest |

Provision the image on every worker host, then verify the host:

```powershell
docker pull semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b
.\.venv\Scripts\sentinel-worker.exe sandbox-check --profile semgrep
```

## 2. Running a Semgrep worker locally

Use the same fixture layout as Gitleaks: `<root>/<owner>/<name>`, matching the project's
repository owner and name. Plan the scanner in the API with
`SENTINEL_EXECUTION_PLANNED_SCANNERS=SEMGREP` (`local` profile), then start the worker:

```powershell
$env:SENTINEL_WORKER_SEMGREP_ENABLED = "true"
$env:SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR = "C:\sentinel-fixtures"
.\.venv\Scripts\sentinel-worker.exe execute --idle-timeout 60
```

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_WORKER_SEMGREP_ENABLED` | `false` | Execute `SEMGREP` jobs (refused in `production`) |
| `SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR` | none | Shared with Gitleaks |
| `SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS`, `_CPUS`, `_RUNTIME` | 300, 1, runc | Shared |

The memory (1 GiB; Semgrep's per-file limit 256 MiB), PID (64), tmpfs (128 MiB), stdin (32 MiB) and stdout (2 MiB)
limits are fixed in code. They come from measurements: peak 220–280 MiB, 7 processes, a
few seconds for inputs up to the snapshot limits on 1 CPU. Semgrep, Gitleaks and the
FIXTURE can run in one worker.

## 3. Reading results

Each completed job stores one `findings.json` (`findings.v1`,
[contract](../api/findings-contract-v1.md)):

- `execution.status`: `FINDINGS_DETECTED` (script exit 41) or `NO_FINDINGS` (exit 0).
- `findings[]`:
  - `category = CODE_PATTERN`;
  - `rule_id` (`sentinelpipe.<language>.<pattern>`);
  - the rule's static description;
  - `scanner_severity` (Semgrep's ERROR, WARNING or INFO, verbatim);
  - `classification` (CWE, OWASP);
  - a safe location.

  `severity`, `confidence` and `remediation` are `null`. There is **never** a source
  excerpt.
- `coverage`:
  - `files_supported`, `files_analyzed`, `files_not_analyzed`, `files_unsupported`;
  - `complete` is false whenever a supported file was not fully analyzed;
  - `not_analyzed_reasons` gives counts for `scanner_skipped`, `parse_error`,
    `resource_limit` and `unverifiable_encoding`;
  - limitations always include `RULESET_MINIMAL`, `PATTERN_MATCHING_ONLY`,
    `PARSE_COMPLETENESS_UNVERIFIED` and `COMMIT_NOT_VERIFIED`.

A finding is a suspicious pattern, **not proof of a vulnerability**. A clean result is
not a security pass. Scans stay `INCOMPLETE` until policy evaluation exists (M4).

## 4. Failures

Worker logs carry sanitized codes (`scanner.failed`, `scanner.input_rejected`). They
never contain source code, report content or host paths.

| Log code | Job result | Meaning and action |
|---|---|---|
| `SEMGREP_FAILED` (70) | `SCANNER_ERROR` (retried) | Semgrep exited with an error (configuration, rule or fatal error). Run `sandbox-check --profile semgrep`; check the image digest |
| `SEMGREP_ERROR` | `SCANNER_ERROR` | The report contains an error that is not a per-file warning (for example a rule problem) |
| `RULES_SKIPPED` | `SCANNER_ERROR` | Semgrep skipped a bundled rule. The ruleset or engine is not as reviewed |
| `UNEXPECTED_VERSION`, `UNKNOWN_RULE`, `INVALID_REPORT`, `UNKNOWN_PATH`, `INCONSISTENT_EXIT_CODE`, `INVALID_OUTPUT` | `SCANNER_ERROR` | The output does not match the reviewed format. Repeated occurrences indicate a wrong or compromised image: **incident** |
| `INPUT_REJECTED` (75), `INPUT_VERIFICATION_FAILED` (72) | `SCANNER_ERROR` | The sandbox did not receive exactly the snapshot, or the archive contained a disallowed entry: **incident** (the worker never builds such archives) |
| `REPORT_TOO_LARGE` (74), `FINDINGS_LIMIT_EXCEEDED` | `RESOURCE_LIMIT_EXCEEDED` | Report over 1 MiB, over 5000 results or over 1000 distinct findings. Nothing is truncated |
| Worker start fails with `RulesetError` | — | The bundled ruleset is not the reviewed one. Never edit it without updating `RULESET_SHA256` through review (§5) |

Coverage problems (parse errors, timeouts, skipped files) are **not** failures. They
appear as `FILES_NOT_ANALYZED` with counts.

## 5. Changing the ruleset or upgrading Semgrep

**Ruleset changes:**
1. Edit `semgrep-rules.json` using only the allowed keys and operators. Messages must be
   static text without `$`; metadata is limited to `cwe` and `owasp`.
2. Add a vulnerable and a clean fixture for each new rule to `tests/semgrep_support.py`.
   The real-container tests assert exact rule ids and lines.
3. Update `RULESET_SHA256`, and the rule count in `test_the_bundled_ruleset_is_the_reviewed_one`.
4. Record the change in ADR-0011 (coverage table). If upstream rules are considered,
   record their license and provenance first.

**Semgrep upgrades** are security changes. Re-verify on the new image, and update the
digest in `policy.py`, `ci.yml`, this runbook, `VERSION` and the tests:
- that both repository names publish the same index digest;
- the image's `ENV` (`IMAGE_ENVIRONMENT`);
- `.semgrepignore` discovery (root, nested, default list) and the effect of an empty
  root file;
- `--disable-nosem`, `--no-git-ignore` and the explicit `--config` behavior;
- the extension mapping;
- the JSON report keys (the parser refuses unknown keys) and the `check_id` prefix;
- whether `extra.lines` carries source;
- exit codes;
- resource use (re-measure).

Then run `sandbox-check --profile semgrep`, `pytest -m sandbox` with
`SENTINEL_REQUIRE_SANDBOX=1`, and the E2E profile.

## 6. Limitations

- 13 pattern rules in four languages; no taint tracking; no cross-file analysis. Not
  comprehensive SAST.
- Unsupported files, including `.pyw`, `.mts`, `.cts` and shebang scripts, are counted
  but not analyzed.
- Semgrep's error-tolerant parsers recover silently from many syntax errors.
  - Python files are checked independently (`ast.parse` in the sandbox).
  - Java, JavaScript and TypeScript cannot be checked, hence
    `PARSE_COMPLETENESS_UNVERIFIED`.
  - UTF-16/UTF-32 and NUL-containing sources are never counted as analyzed.
- Files inside a directory named `.semgrepignore` are skipped (`unsupported_name`).
- Known rule false negatives are listed in ADR-0011 (Consequences).
- Paths are redacted only heuristically (no secret rules run over names in this scanner).
- The raw report digest is not reproducible across runs; findings, ids, fingerprints and
  coverage are.
- The image is linux/amd64 only.
- Semgrep under runc is acceptable for synthetic content only (ADR-0009).

# ADR-0011: Semgrep SAST with a bundled, reviewed ruleset

- **Status:** Proposed (pending owner review)
- **Date:** 2026-10-11
- **Milestone:** M3 Phase 2 (Slice 2: Semgrep)
- **Builds on:** [ADR-0010](0010-scanner-adapters-repository-snapshots-and-findings.md)
  (scanner adapters, snapshots, `findings.v1`; itself still **Proposed**)
- **Threat model:** [Semgrep scanner](../threat-model/semgrep-scanner.md)
- **Security review:** [Slice 2 review](../security/m3-phase2-slice2-security-review.md)
  (defects S2-1 to S2-7 fixed; this ADR reflects the fixed design)
- **Runbook:** [Semgrep](../runbooks/semgrep.md)

## Context

Semgrep is the second real scanner and the first that reads source code semantically.
Compared with Gitleaks it adds new concerns:

- **Configuration discovery.** Semgrep can download rules (`--config auto`, registry
  references), read rules from environment variables (`SEMGREP_RULES`), and obey ignore
  files and comments that the scanned repository controls.
- **Telemetry and network.** It sends metrics and checks for new versions by default,
  and its official image declares tracing-related environment variables.
- **Source excerpts in output.** Its output can contain source text: rule messages
  interpolate matched metavariables, and results carry the matched lines.
- **Partial coverage.** It analyzes only some languages, and it can skip or partially
  parse files without failing the run.
- **Resources.** It needs more memory than Gitleaks.

The trust model is unchanged (ADR-0009):
- Semgrep is a reviewed tool parsing hostile content under runc;
- this is acceptable only for synthetic local fixtures until stronger isolation and
  verified commit snapshots exist.

## Decision

### 1. Image and version

| | |
|---|---|
| Version | Semgrep **1.179.0** (Community Edition CLI; released 2026-10-02). 1.180.0 (2026-10-07) was not selected because it was only three days old at review |
| Image | `semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b` (OCI index) |
| Provenance | The identical index digest is published as `semgrep/semgrep:1.179.0` and `returntocorp/semgrep:1.179.0`. Image labels: revision `8fa217f1…`, base `alpine:3.23`. **linux/amd64 only** (no arm64 manifest) |
| Allowlist | `SEMGREP_IMAGE` in `sandbox/policy.py`; pulled only by digest; `--pull never` |

### 2. A bundled, reviewed ruleset authored in this repository

- **Upstream rules are not vendored.** The Semgrep registry rules
  (`semgrep/semgrep-rules`) are distributed under the *Semgrep Rules License v1.0*,
  which restricts use in products and services. That license is not compatible with
  redistribution in this open-source repository without legal review. The Slice 2
  ruleset is therefore **authored here**, small and auditable:
  `scanners/semgrep-rules.json`, 13 rules, published under this repository's license.
- **Coverage:**

  | Language | Rules (CWE) |
  |---|---|
  | Java | SQL built by concatenation and executed (CWE-89); non-constant `Runtime.exec` or `sh -c` (CWE-78); `ObjectInputStream` (CWE-502); MD2/MD4/MD5/SHA-1 (CWE-328) |
  | Python | `shell=True` or `os.system`/`os.popen` with a non-constant command (CWE-78); non-constant `eval`/`exec` (CWE-95); `pickle`, `marshal`, unsafe `yaml.load` (CWE-502); SQL built by `%`, `+`, `.format`, f-string and executed (CWE-89); MD5/SHA-1 without `usedforsecurity=False` (CWE-328) |
  | JavaScript and TypeScript | non-constant `eval`/`Function` (CWE-95); non-constant `child_process.exec`/`execSync` (CWE-78); non-constant `innerHTML`/`outerHTML`/`document.write` (CWE-79); MD5/SHA-1 `createHash` (CWE-328) |

- **Integrity.**
  - The ruleset is **JSON**, which Semgrep reads as YAML, so the worker can validate it
    with the standard library and no new dependency.
  - It is pinned by SHA-256 (`RULESET_SHA256`, currently `d52217f6…01516a1f`, after the
    security review's rule fixes).
  - It is validated structurally when the worker starts; any violation fails closed at
    startup. The validation allows only:
    - keys and pattern operators from an allowlist. This excludes `pattern-where-python`
      (which executes Python), rule-level `paths` (file exclusion), `fix`, and taint or
      extract modes;
    - the four languages;
    - static printable messages **without `$`**, so no message can interpolate matched
      source;
    - CWE and OWASP identifiers as the only metadata.
- **Verification.** Every rule is exercised by real-container tests with one vulnerable
  and one clean fixture per language. The tests check exact rule ids and lines, plus
  negative cases such as literal arguments, `execFile` and `usedforsecurity=False`.
- **No coverage claims.** This is not comprehensive SAST. The rules are pattern-based
  (no taint tracking), and every findings document says so (`RULESET_MINIMAL`,
  `PATTERN_MATCHING_ONLY`).

### 3. Input: same snapshot channel, Semgrep-specific control files removed

- **Shared input path.** The snapshot is streamed on stdin through the shared, reviewed
  script fragment (`scanners/sandbox_input.py`), which was factored out of the Gitleaks
  adapter without behavior change: archive listing checks before extraction, exact count
  and `sha256sum` verification after.
- **New adapter hook.** Adapters now declare `prepare(snapshot)`, the files the scanner
  receives. Semgrep's removes **every** `.semgrepignore`, root or nested. Each is counted
  under `skipped.suppression_file`, and the script refuses to scan if one is present.
- **Verified against 1.179.0:**
  - **Repository `.semgrepignore` files are obeyed at every depth.** A root file
    containing `src/` silently skipped every vulnerable fixture.
  - **Without any `.semgrepignore`, Semgrep applies a default ignore list.** It skips
    `tests/`, `node_modules/`, `vendor/`, `*.min.js` and more, which a repository author
    controls by naming files. The script therefore writes the worker's **empty**
    `.semgrepignore` at the scan root, which disables the default list.
  - `.semgrep.yml` and `.semgrep/` in the repository are not loaded when `--config` is
    explicit.
  - `.gitignore` is not consulted with `--no-git-ignore`.
  - Inline `nosemgrep` is ignored with `--disable-nosem`.

### 4. Execution

The constant script runs:

```text
env -i PATH=… HOME=/tmp/home PYTHONIOENCODING=utf8 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  semgrep scan --config /tmp/input/config/rules.json --json --output … --metrics=off \
  --disable-version-check --disable-nosem --no-git-ignore --oss-only --max-target-bytes 2000000 \
  --max-memory 256 --jobs 1 --timeout 30 --timeout-threshold 0 --error /tmp/input/repo
```

- **Clean environment.** `env -i` removes the image's declared variables (including
  `DD_SERVICE` and `DOCKER_OTEL_RESOURCE_ATTRIBUTES`) and any `SEMGREP_*` configuration
  variable.
- **Writable state.** Semgrep writes `~/.semgrep/semgrep.log`, `settings.yml` and
  `~/.gitconfig`; with `HOME` in the sandbox tmpfs this works under the read-only root.
- **No network.** The sandbox has none. Metrics and version checks are disabled anyway.
- **Never used:** registry configs, login or app tokens, `--pro` features,
  secret-validator network calls (`--allow-untrusted-validators`), autofix, or
  dependency or build tooling. Semgrep does not execute repository code.
- **Sandbox self-check.** The isolation probe accepts, per image, only the variables
  the image itself declares (`IMAGE_ENVIRONMENT`, pinned against the real image config
  by a test). Without that, it would reject Semgrep's image. Host variables are still
  refused, so `sandbox-check --profile semgrep` verifies all 13 controls.

### 5. Measured resource limits

All measurements were taken under the sandbox flags on 1 CPU.

| Input | Wall time | Peak memory (cgroup, incl. tmpfs) | Peak PIDs | tmpfs |
|---|---|---|---|---|
| 8 small fixtures | 2 s | 220 MiB | 7 | < 1 MiB |
| 2000 files, 13.4 MiB | 3–5 s | 253 MiB | 7 | 16 MiB |
| 4800 files, 7 MiB | 4 s | 266 MiB | 7 | 19 MiB |

The limits are explicit and Semgrep-specific, with headroom:
- 1 GiB memory, plus Semgrep's own 256 MiB per-file limit (security review S2-7):
  - The original 768 MiB with a 400 MiB per-file limit was **not** enough. A single
    960 KB-line file within the snapshot limits peaked at up to about 700 MiB, varying
    between runs, and occasionally OOM-killed the whole sandbox.
  - With 256 MiB per file, peaks stayed at about 265 MiB over repeated runs, and that file
    fails alone as a per-file `Out of memory` (`resource_limit`).
  - The per-file limit bounds Semgrep's engine per file, not the container. The container
    limit remains the backstop: exceeding it fails the scan explicitly
    (`RESOURCE_LIMIT_EXCEEDED`), never silently;
- 64 PIDs and 128 MiB tmpfs (the staged archive is up to 32 MiB);
- 2 MiB stdout, a 1 MiB report and 32 MiB stdin;
- the shared timeout and CPU settings.

Global sandbox protections are unchanged.

### 6. Exit codes and failure classification

| Code | Meaning | Result |
|---|---|---|
| 0 | Semgrep ran, no findings | `COMPLETED`, `NO_FINDINGS` |
| 41 | Semgrep ran, findings (Semgrep exit 1 with `--error`) | `COMPLETED`, `FINDINGS_DETECTED` |
| 70 | Semgrep failed (any exit code but 0 or 1: configuration, rule, fatal error) | `FAILED SCANNER_ERROR` |
| 71, 72, 75 | Input staging, verification, archive refusal (shared) | `FAILED SCANNER_ERROR` |
| 73, 74 | Report missing or over 1 MiB (shared) | `SCANNER_ERROR` / `RESOURCE_LIMIT_EXCEEDED` |
| Other 1–127, ≥ 128 | Unexpected or killed | `SCANNER_ERROR` / `SANDBOX_ERROR` |

The report is then checked; any of the following fails closed:
- the version must be exactly `1.179.0` (`UNEXPECTED_VERSION`);
- top-level keys, result keys and `extra` keys come from closed sets;
- rule ids must be `tmp.input.config.` followed by a catalog id (`UNKNOWN_RULE`);
- severities must match the catalog;
- paths must be snapshot files of a supported language (`UNKNOWN_PATH`);
- positions must be valid integers;
- a non-empty `skipped_rules` (`RULES_SKIPPED`), or any error that is not a per-file
  warning about a snapshot file (`SEMGREP_ERROR`), is a failure;
- the exit code must agree with the results.

Timeouts, OOM, PID and output limits, and cancellation map as for every sandbox.

### 7. Coverage and limitations

- **Supported files** (Semgrep 1.179.0, verified):
  - Java: `.java`;
  - Python: `.py`, `.pyi`;
  - JavaScript: `.js`, `.jsx`, `.mjs`, `.cjs`;
  - TypeScript: `.ts`, `.tsx`, including `.d.ts`.

  Not scanned: `.pyw`, `.mts`, `.cts` and extensionless scripts with a shebang.
- **Not analyzed.** A supported file counts as **not analyzed**, `coverage.complete`
  is false and `FILES_NOT_ANALYZED` is set when any of these applies (reported per reason
  in `coverage.not_analyzed_reasons`; a file can count under several):

  | Reason | Detection |
  |---|---|
  | `scanner_skipped` | Missing from Semgrep's `paths.scanned`, whatever the cause. Any skip mechanism, known or not, shows up as incomplete coverage |
  | `parse_error` | Semgrep reported a per-file parse error (`Syntax error`, `PartialParsing`, …), **or** the independent Python syntax check failed |
  | `resource_limit` | Semgrep reported a per-file `Timeout` or `Out of memory` |
  | `unverifiable_encoding` | NUL bytes, or a UTF-16/UTF-32 byte order mark |

- **Parser recovery** (security review S2-1, S2-2):
  - Semgrep's error-tolerant parsers recover from syntax errors, often **without
    reporting them**. This was verified for all four languages: in 18 malformed files with
    the vulnerable call inside or after the broken region, every call was still found or a
    parse error reported, but 7 of them had unreported syntax errors.
  - **UTF-16** source is reported as analyzed with no finding and no error, a **false
    clean** (verified). The worker's encoding check closes this.
  - **For Python**, an independent check runs `ast.parse` inside the sandbox with the
    image's Python 3.12 (`env -i python3 -I -S`). Parsing never executes code. Python 2
    syntax and syntax newer than 3.12 are conservatively counted as `parse_error`.
  - **For Java, JavaScript and TypeScript** there is no independent parser in the image,
    so silent recovery **cannot be detected**. Every Semgrep document therefore carries
    `PARSE_COMPLETENESS_UNVERIFIED`. "Analyzed" means Semgrep processed the file without
    reporting a problem, not that every construct was understood.
  - Files with no rule keyword are skipped by Semgrep's prefilter, which is correct: no
    rule could match them.
- **Counts:** `files_supported`, `files_analyzed`, `files_not_analyzed`,
  `files_unsupported` and `not_analyzed_reasons` are reported.
- **Limitations:**
  - `UNSUPPORTED_FILES_PRESENT` and `NO_SUPPORTED_FILES` flag files outside the
    supported languages;
  - `RULESET_MINIMAL`, `PATTERN_MATCHING_ONLY`, `PARSE_COMPLETENESS_UNVERIFIED` and
    `COMMIT_NOT_VERIFIED` are always set.
- **Control files as directories** (S2-3). Files inside a directory named
  `.semgrepignore` are skipped as `unsupported_name`, so coverage is incomplete and the
  scan still completes.

### 8. Normalization and sensitive output

- **The catalog is authoritative.** Semgrep's `extra.message` (which can interpolate
  source), `extra.lines` (source excerpts; `"requires login"` in this version) and
  `extra.metadata` are never read. Error messages are never read.
- **Taken from the catalog:**
  - the description, which is the rule's static message;
  - the classification (CWE, OWASP);
  - `scanner_severity`, Semgrep's own label (ERROR, WARNING, INFO), kept verbatim.
- **Not normalized.** The normalized `severity` stays `null`, because Semgrep's scale
  is not a policy decision (M4). Confidence and remediation stay `null`.
- **Evidence.** Category `CODE_PATTERN`. `evidence = {redacted: true, excerpt: null}`,
  enforced by the schema for both categories.
- **Paths** are stored in safe form only. For Semgrep this means heuristic redaction,
  because no secret rules run over names in this scanner. The heuristic flags credential
  prefixes, high-entropy runs and, since the review, invisible Unicode format characters.
  - **Not detected:** letters-only or digits-only random strings, short passwords, and
    secrets split by ordinary separators.
  - **Not reused: Gitleaks' path detection.** Reusing it would mean running Gitleaks in
    every Semgrep job, or coupling jobs through the database, or porting Go RE2 rules to
    Python regular expressions applied to untrusted names in the worker (a ReDoS risk).
    A per-scan, sandboxed name-classification pass shared by all scanners is a possible
    future design and needs approval.
- **Raw output.** The report is parsed in memory, bounded, and only its SHA-256 is kept.
  Errors are raised without exception context, and logs carry codes and counts only.

### 9. Contract changes (`findings.v1`, backward compatible)

The changes are only optional properties and new enum values, so Gitleaks documents
are byte-identical to before:
- scanner `semgrep`;
- category `CODE_PATTERN`;
- optional finding fields `scanner_severity` and `classification`;
- optional coverage counts and `not_analyzed_reasons`;
- limitation codes `FILES_NOT_ANALYZED`, `UNSUPPORTED_FILES_PRESENT`,
  `NO_SUPPORTED_FILES`, `RULESET_MINIMAL`, `PATTERN_MATCHING_ONLY` and
  `PARSE_COMPLETENESS_UNVERIFIED`;
- `maxItems` for limitations raised to 16.

### 10. Control plane

- `SEMGREP` is executable (`EXECUTABLE_SCANNERS`).
- Like `GITLEAKS`, it is refused in `planned-scanners` under production profiles
  (`LOCAL_FIXTURE_SCANNERS`).
- Workers refuse `SENTINEL_WORKER_SEMGREP_ENABLED=true` in `production`.
- No database change: `SEMGREP` was already a valid scanner type.

## Consequences

- **Findings are suspicious patterns, not proof.** A Semgrep finding means code matches
  a pattern associated with a vulnerability class. It does not prove that untrusted
  data reaches the sink, that the code is reachable, or that it is exploitable. A clean
  result means only that none of 13 patterns matched in the analyzed files. Neither is
  a decision; until M4, scans stay `INCOMPLETE`.
- **The raw report digest is not reproducible across runs.** Semgrep's report contains
  run-varying data. Findings, ids, fingerprints and coverage are reproducible.
- **Upgrading Semgrep is a reviewed change** (runbook §5). That covers the report keys,
  ignore behavior, extension mapping, check-id prefix, version string, image
  environment and limits.
- **Extending the ruleset changes the pinned checksum** and requires fixtures and
  real-container tests for each new rule.
- **Known false negatives** are pinned by a characterization test
  (`test_documented_false_negatives_are_still_accurate`) and proposed as separate ruleset
  work:
  - `String.format` SQL (Java);
  - `Runtime` held in a variable;
  - `shell=1`;
  - `builtins.eval`;
  - a query built into a variable before `execute` (needs dataflow);
  - `hashlib.new('md5')`;
  - `window.eval`;
  - `insertAdjacentHTML`.

## Alternatives considered

- **Vendoring registry rules (`p/security-audit`, `p/owasp-top-ten`).** Rejected: the
  Semgrep Rules License, and the rules would add network-oriented config references to
  review.
- **YAML ruleset with a YAML parser in the worker.** Rejected: a new dependency for
  parsing only. JSON is valid Semgrep configuration.
- **Using Semgrep's messages and metadata.** Rejected: messages interpolate matched
  source; the catalog is trusted and static.
- **Mapping ERROR/WARNING/INFO onto the normalized severity.** Rejected: that is a
  policy choice (M4), not scanner data.
- **`--project-root` to control `.semgrepignore` discovery.** Not needed: removing
  repository ignore files and supplying an empty one at the scan root is simpler and was
  verified. The option is also marked experimental in this version.
- **Bind-mounting the ruleset.** Rejected: the no-mount policy stands. The ruleset
  travels in the same verified archive as the snapshot.

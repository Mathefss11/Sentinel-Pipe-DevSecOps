# M3 Phase 2, Slice 2: security review (Semgrep integration)

- **Date:** 2026-10-11
- **Scope:** the Semgrep integration of [ADR-0011](../adr/0011-semgrep-sast-with-a-bundled-ruleset.md)
  and the Slice 2 changes to shared components:
  - the sandbox-input fragment and adapter `prepare` hook;
  - the image environment allowlist;
  - the `findings.v1` extension;
  - Gitleaks regressions.
- **Method:**
  - every claim was re-tested against the pinned Semgrep 1.179.0 image in the real
    sandbox; nothing was assumed from earlier results;
  - each confirmed defect has a fix and a regression test;
  - synthetic data only.
- **Code:** uncommitted Slice 2 changes on top of `a79c2c5`
- **Threat model:** [Semgrep scanner](../threat-model/semgrep-scanner.md) (S1–S14)

## Confirmed defects

| ID | Severity | Defect | Root cause | Impact | Fix | Regression tests |
|---|---|---|---|---|---|---|
| S2-1 | **Medium** | **False clean for UTF-16 source.** UTF-16 (BOM or not) Java, JS and TS files with sinks were reported analyzed, with no finding and no error, and coverage `complete` | Semgrep matches keyword prefilters on bytes; UTF-16 text never contains them. The worker trusted `paths.scanned` | A repository author can hide code from SAST behind a "complete" coverage claim (javac `-encoding UTF-16`, `tsc` and browsers accept it) | Supported files with NUL bytes or a UTF-16/UTF-32 BOM count as not analyzed (`unverifiable_encoding`). A byte check in the worker; nothing is parsed there | `test_unverifiable_encodings_are_never_counted_as_analyzed` (6 cases), `test_latin1_and_utf8_bom_sources_remain_analyzable`, real `test_silent_parser_recovery_and_utf16_are_reported_as_not_analyzed` |
| S2-2 | Low | **Silent parser recovery counted as full analysis.** 7 of 18 malformed test files had syntax errors Semgrep never reported. In every case the sink was still found, but completeness cannot be proven | Semgrep's error-tolerant parsers. "Scanned without error" was presented as "analyzed" | Overstated coverage; potential misses in unparsed regions (none reproduced) | Python: independent `ast.parse` check inside the sandbox (`env -i python3 -I -S`, no execution) counts failures as `parse_error`. Java/JS/TS: no independent parser, so every document now carries `PARSE_COMPLETENESS_UNVERIFIED`. Per-reason coverage (`not_analyzed_reasons`) | `test_python_syntax_check_failures_make_files_not_analyzed_but_keep_findings`, `test_per_file_errors_are_classified_by_reason`, `test_the_python_check_artifact_is_validated` (6 cases), `test_the_script_checks_python_syntax_in_the_sandbox_without_executing_code`, real recovery test |
| S2-3 | Low | **A directory named like a control file broke scans.** `.semgrepignore/` (root or nested) for Semgrep and a root `.gitleaksignore/` for Gitleaks made scans fail permanently with exit 72, which the runbooks classify as a security incident | `prepare()` and the walker removed only *files* with those names | A repository can permanently prevent its own scan, and operators get a false incident | Files under such directories are skipped as `unsupported_name` (coverage incomplete); the scan completes. Affects Gitleaks too (Slice 1 latent) | `test_semgrepignore_directories_are_skipped_as_unsupported_names`, `test_a_root_gitleaksignore_directory_is_skipped_as_unsupported_names`, real tests for both scanners |
| S2-4 | Low | **Rule false positives:** a SQL string concatenated only from constants; `yaml.load(b, yaml.SafeLoader)` with the loader passed positionally | Missing `pattern-not` cases | Noise; erodes trust in findings | Two narrow `pattern-not` additions | `test_audited_rule_defects_stay_fixed` (real) |
| S2-5 | Low | **Rule false negatives for sinks the rules already target:** fully qualified `java.io.ObjectInputStream` and `java.security.MessageDigest`; destructured `require('child_process')`; the `node:child_process` specifier | Patterns covered only unqualified names and some import forms | Missed findings for common code shapes | Qualified-name and import-form alternatives (same sinks; no new vulnerability classes) | `test_audited_rule_defects_stay_fixed` (real); the per-language fixtures still match exactly |
| S2-6 | Informational | **Invisible format characters in file names were stored verbatim.** Zero-width and bidirectional controls can split a secret so no rule matches, or spoof how a path is displayed | The heuristic considered only token runs | Possible name-secret leakage; display spoofing in future reports | Names containing Unicode format characters (category Cf) are redacted, for both scanners | `test_names_with_invisible_format_characters_are_redacted` (5 cases), `test_ordinary_unicode_names_are_not_redacted`; Gitleaks hostile-name test updated to assert redaction |
| S2-7 | Low | **One pathological file could OOM-kill the whole Semgrep sandbox.** A 960 KB single-line file peaked at 253–703 MiB across runs, so the 768 MiB limit was occasionally exceeded | Semgrep's `--max-memory 400` bounds the engine per file, not the container; the ADR claimed otherwise | Nondeterministic whole-scan `RESOURCE_LIMIT_EXCEEDED` (fail closed, explicit) for a legitimate repository within the snapshot limits | Per-file limit 256 MiB (peaks about 265 MiB over 12 runs; the file then fails alone as `resource_limit`); container 1 GiB. ADR corrected | `test_per_file_memory_limits_are_reported_not_silent` (repeated 5 times after the fix), `test_memory_exhaustion_is_a_resource_failure` |

The ruleset checksum changed with S2-4 and S2-5 (`d52217f6…01516a1f`). No Critical or
High defect was found, and no existing guarantee was weakened.

## Reviewed without defects

| Area | Result |
|---|---|
| **Suppression** | Every mechanism was verified on the image as unable to suppress findings: root and nested `.semgrepignore`; the default ignore list; `.gitignore`; `nosemgrep`, `nosem`, rule-specific and block-comment variants in all four languages; repository `.semgrep.yml`, `semgrep.yml`, `.semgrep/` and `.semgrepconfig.yml`; `SEMGREP_*` environment (cleared); rule exclusions (never passed); scan-target redirection (fixed target; links and traversal refused before extraction). The rule-id prefix, version and severities are checked against the catalog |
| **Coverage** | Hidden directories, dotfiles, nested directories, `node_modules/`, `vendor/`, tests, minified files, empty files, misleading extensions (parse error reported, so not analyzed), shebang scripts and `.pyw`, `.mts`, `.cts` (counted unsupported), large files (analyzed or `resource_limit`), Unicode names: all correctly classified. Normalization-equivalent names (NFC and NFD) are distinct snapshot paths and are scanned separately |
| **Sensitive output** | Semgrep's `extra.lines` is `"requires login"` in this version, and no source marker appeared even in sandbox stdout. Messages, metadata and severity come from the catalog; error messages and stderr are never read; no exception chains; logs carry codes only; fingerprints use safe paths. Evidence, results and audit rows were searched for markers in integration and E2E tests |
| **Sandbox** | The digest re-verified today under both repository names. `sandbox-check --profile semgrep` passes 13/13. Both scanner processes (Semgrep and the Python check) were shown to run with exactly the expected cleared environment, with no host or image variables, even when the host sets `SENTINEL_*` or an image-declared variable name (`test_scanner_processes_run_with_a_cleared_environment`) |
| **Image environment allowlist** | It is not a weakening. It is keyed by image digest, names only, and pinned against the real image config; `SENTINEL_*` must still be absent; no code path passes `-e`/`--env`. Even so, scanners run under `env -i`. Residual: the probe checks names, not values |
| **Resources and concurrency** | Concurrent scans are isolated. Timeout during parsing gives `EXECUTION_TIMEOUT`. A memory-starved sandbox gives `RESOURCE_LIMIT_EXCEEDED`. More than 1000 distinct findings gives `RESOURCE_LIMIT_EXCEEDED` (never truncated). Cancellation during extraction leaves no container and no writer thread |
| **Tenant isolation and evidence** | Cross-tenant evidence separation, lease fencing (crash retry, stale lease, cancellation), database-computed digests and `INCOMPLETE` decisions were all re-verified in integration and E2E tests |
| **Gitleaks** | All Gitleaks adversarial tests pass after the shared refactor and the review fixes. The vendored ruleset is intact (derivation checksum unchanged). A Gitleaks-only worker never imports the Semgrep module (`test_a_gitleaks_only_worker_never_imports_the_semgrep_module`) |

## Ruleset audit

All 13 rules were exercised with 53 targeted cases (positives with aliases, qualified
names and evasions; negatives) against the real engine, plus the per-language fixtures.
After S2-4 and S2-5:
- **Messages and metadata:** every message is static text without `$`. Metadata is
  CWE/OWASP only. No rule uses code-executing or file-excluding features (enforced at
  worker start).
- **Documented false negatives** (pinned by
  `test_documented_false_negatives_are_still_accurate`):
  - `String.format` SQL;
  - `Runtime` held in a variable;
  - `shell=1`;
  - `builtins.eval`;
  - a query built into a variable before `execute`;
  - `hashlib.new('md5')`;
  - `window.eval`;
  - `insertAdjacentHTML`.
- **Proposed, separately (not implemented):**
  - typed-metavariable `Runtime` rules;
  - `String.format`/`concat` SQL;
  - truthy `shell=` values;
  - `builtins.eval` and `window`/`globalThis.eval`;
  - `hashlib.new` with weak names;
  - `insertAdjacentHTML`;
  - taint-mode SQL rules, with coverage reporting.

## Accepted residual risks

- **Hostile code:** runc shares the host kernel. Semgrep is restricted to synthetic local
  fixtures (refused in production by worker and API).
- **Unverifiable parsing:** silent parser recovery in Java, JavaScript and TypeScript
  cannot be detected (`PARSE_COMPLETENESS_UNVERIFIED`).
- **Python check conservatism:** the Python check flags Python 2 or post-3.12 syntax as
  `parse_error`.
- **File-name redaction is heuristic** for Semgrep. Not detected: letters-only or
  digits-only random strings, short passwords, secrets split by ordinary separators.
  Reusing Gitleaks' path detection would need a cross-scanner design (approval
  required).
- **Digests:** `content_sha256` and `raw_report_sha256` can confirm a complete guess of
  the input.
- **Ruleset scope:** 13 pattern rules. Not comprehensive, no taint tracking, and
  findings are not proof of exploitability.
- **Integrity, not authenticity:** a compromised sandbox can misreport its own job.
- **Platform:** the image is amd64 only.

## Verification results

See the final report of this review for exact counts. Tests that run only on Linux CI:
- the symlink tests (3 snapshot, 1 Gitleaks real container);
- the FIFO test;
- control-character and backslash names;
- the POSIX-only file names in the hostile-name tests.

Remote CI has not run Slice 2.

## ADR recommendations

- **ADR-0010: Accept with documented conditions.** The design was implemented, reviewed
  twice and hardened, and its decisions hold under adversarial testing. Conditions:
  - remote CI green;
  - the documented residual risks accepted, in particular runc for synthetic fixtures
    only and the vendored-ruleset derivation.
- **ADR-0011: Accept with documented conditions.** The review fixes are reflected in the
  ADR. Conditions:
  - remote CI green, including the Linux-only tests;
  - acceptance of `PARSE_COMPLETENESS_UNVERIFIED` and the heuristic-only name redaction
    for Semgrep;
  - the ruleset licensing decision recorded (authored rules; registry rules not used);
  - the false-negative proposals tracked as separate work.

## Verdict

**Ready for the owner's manual commit**, conditional on remote CI. No open defect
remains; all seven confirmed defects are fixed and covered by regression tests.

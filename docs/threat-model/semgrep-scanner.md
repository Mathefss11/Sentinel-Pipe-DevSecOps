# Threat model: Semgrep scanner integration

Scope:
- repository source code crossing into a Semgrep sandbox;
- Semgrep's report crossing back into the worker;
- normalized findings stored as evidence.

Builds on the [Gitleaks threat model](gitleaks-scanner.md) (shared snapshot channel,
G1, G2, G13, G14), the [execution sandbox](execution-sandbox.md) and ADR-0009's trust
policy. Design: [ADR-0011](../adr/0011-semgrep-sast-with-a-bundled-ruleset.md). Status:
M3 Phase 2, Slice 2 (local synthetic repositories only), updated after the
[Slice 2 security review](../security/m3-phase2-slice2-security-review.md).

## Assets

| Asset | Why it matters |
|---|---|
| Repository source code | Proprietary; may embed credentials or personal data. Must not spread into evidence, logs or metrics |
| The ruleset | Decides what is detected; must be exactly the reviewed one |
| Coverage statements | A silently skipped file is a false clean |
| Worker credentials, host files | Must never reach the sandbox |

## Data flow

```text
worker: snapshot ─prepare (drop .semgrepignore)─▶ tar (repo/ + config/rules.json) ─▶ stdin
  ─▶ [sandbox: stage, list, extract, verify count + sha256sum, write empty .semgrepignore,
      env -i semgrep scan --config rules.json …] (UNTRUSTED)
  ─▶ stdout: sandbox-output.v1 { semgrep-report.json } ─▶ worker: strict parse, catalog lookup,
      coverage cross-check, safe paths ─▶ findings.json ─▶ worker.put_evidence
```

## Threats

| # | STRIDE | Threat | Controls | Verified by | Residual risk |
|---|---|---|---|---|---|
| S1 | Tampering | Repository-controlled suppression: root or nested `.semgrepignore`, Semgrep's **default** ignore list (`tests/`, `node_modules/`, `vendor/`, `*.min.js`), `nosemgrep` comments, `.gitignore`, `.semgrep.yml`/`.semgrep/` | All `.semgrepignore` removed from the input and refused by the script; worker's empty root `.semgrepignore` disables the default list; `--disable-nosem`; `--no-git-ignore`; explicit `--config` | `test_repository_controlled_suppression_is_ignored` (real container, 10 mechanisms), `test_repository_semgrepignore_files_are_removed_at_every_depth`, `smuggled-semgrepignore` archive case, E2E | Future versions may add discovery mechanisms. The coverage cross-check (S4) turns any unknown skip into `FILES_NOT_ANALYZED` |
| S2 | Tampering, elevation | A rule source the worker did not review: registry (`--config auto`, `p/…`), `SEMGREP_RULES`, rules executing code (`pattern-where-python`), rule-level `paths` exclusions, a modified bundled file | Bundled JSON ruleset pinned by SHA-256 and structurally validated at worker start (allowlisted keys and operators; no `$` in messages; CWE/OWASP metadata only); constant command; `env -i` | `test_the_bundled_ruleset_is_the_reviewed_one`, `test_a_ruleset_that_is_not_the_reviewed_one_is_refused`, `test_disallowed_ruleset_features_are_refused` (14 cases), `test_the_command_is_constant_hardened_and_takes_only_worker_values` | The rules are authored here; their quality is a review responsibility (each has fixtures) |
| S3 | Information disclosure | Source excerpts or secrets leak through Semgrep output: `extra.lines`, interpolated `extra.message`, `extra.metadata`, error messages, stderr | Those fields are never read; descriptions, classification and severity come from the catalog; messages have no metavariables; report not stored (digest only); stderr kept inside the sandbox; errors without exception context | `test_findings_take_message_metadata_and_severity_from_the_catalog_only`, `test_source_excerpts_never_leave_the_worker_and_never_reach_evidence` (real: not even in sandbox stdout for 1.179.0), integration and E2E database scans, `test_errors_never_carry_source_text_or_exception_chains` | `content_sha256` and `raw_report_sha256` can confirm a complete guess of the input (not invertible) |
| S4 | Spoofing (false clean) | A file is skipped or only partly parsed (size, ignore, parse error, timeout, memory) and the scan looks clean | Cross-check: every supported snapshot file must be in `paths.scanned` without a per-file error, otherwise `FILES_NOT_ANALYZED` and `complete = false`; non-file errors and skipped rules fail the run; `--max-target-bytes` above the snapshot's file limit; `--timeout-threshold 0` | `test_supported_files_missing_from_the_scan_make_coverage_incomplete`, `test_per_file_errors_are_partial_coverage_never_silent`, `test_unsupported_languages_and_parse_errors_are_reported_as_partial_coverage`, `test_silent_parser_recovery_and_utf16_are_reported_as_not_analyzed`, `test_per_file_memory_limits_are_reported_not_silent` (real) | Silent parser recovery in Java, JavaScript and TypeScript cannot be detected (`PARSE_COMPLETENESS_UNVERIFIED`); Python is checked independently; UTF-16/32 and NUL-containing sources are never "analyzed" |
| S5 | Spoofing (false clean) | Files in other languages are presented as "scanned" | Per-language counts; `UNSUPPORTED_FILES_PRESENT`, `NO_SUPPORTED_FILES`; supported extensions pinned to the verified mapping | `test_a_repository_without_supported_files_is_flagged` (unit and real) | `.pyw`, `.mts`, `.cts` and shebang scripts are unsupported in this version |
| S6 | Information disclosure | Telemetry, version checks or tracing contact external services | No network in the sandbox; `--metrics=off`, `--disable-version-check`; `env -i` removes `DD_SERVICE` and `DOCKER_OTEL_RESOURCE_ATTRIBUTES`; image environment pinned | `test_every_isolation_control_holds_under_the_semgrep_policy` (`no_network`), `test_the_image_declares_exactly_the_reviewed_environment` | — |
| S7 | Elevation of privilege | Hostile source exploits a Semgrep parser (OCaml or Python) | Sandbox controls unchanged (no network, read-only root, `noexec` tmpfs, uid 65534, no capabilities, seccomp, limits); trusted-tool workload only | `sandbox-check --profile semgrep` (13/13) | runc shares the host kernel. **Not acceptable for hostile production code** (ADR-0009) |
| S8 | Denial of service | Large or pathological input exhausts memory, time or processes | Measured, explicit limits (1 GiB, 64 PIDs, 128 MiB tmpfs); Semgrep per-file `--max-memory 256` (S2-7: 400 MiB let one file OOM-kill a 768 MiB sandbox) and `--timeout 30`; `--jobs 1`; sandbox timeout; cancellation kills the container | Measurements (ADR-0011 §5); `test_oversized_output_and_reports_fail_explicitly`; `test_cancellation_kills_a_running_scan_and_leaves_nothing_behind`; `test_per_file_memory_limits_are_reported_not_silent`, `test_memory_exhaustion_is_a_resource_failure`, `test_a_timeout_during_parsing_is_an_execution_timeout`, `test_more_distinct_findings_than_supported_fail_explicitly`, `test_cancellation_during_extraction_leaves_nothing_behind`, `test_concurrent_scans_are_isolated` | A report over 1 MiB fails the scan (`RESOURCE_LIMIT_EXCEEDED`) rather than truncating |
| S9 | Tampering | A malformed report injects rules, paths or fields | Closed key sets; exact version; `tmp.input.config.` prefix plus catalog id; catalog severity match; paths must be supported snapshot files; integer positions; result and error bounds | `test_malformed_reports_fail_closed` (10 cases), `test_unexpected_results_are_refused` (11 cases) | A compromised sandbox can omit or invent findings for its own job (integrity, not authenticity) |
| S10 | Information disclosure | Secrets in file names reach findings | Safe paths with heuristic redaction, including names with invisible format characters | `test_secret_shaped_file_names_are_redacted_in_findings`, `test_secret_shaped_and_unicode_file_names_are_safe` (real), E2E | Heuristic only: no secret rules run over names in this scanner, so a name secret that is not credential-shaped or high-entropy is persisted |
| S11 | Spoofing | Stale, crashed or cancelled attempts get findings accepted | Lease fencing and evidence binding (ADR-0007/0008) | `test_a_crashed_attempt_is_retried_and_only_the_new_lease_is_accepted`, `test_lost_leases_and_cancelled_scans_never_get_findings_accepted` | — |
| S13 | Spoofing (false clean) | UTF-16 encoded source hides code (Semgrep reports it analyzed, no finding, no error) | Encoding check: NUL bytes or UTF-16/32 BOM, counted as `unverifiable_encoding` | `test_unverifiable_encodings_are_never_counted_as_analyzed` (6 cases), real-container recovery test | — |
| S14 | Denial of service, false alarm | A directory named `.semgrepignore` or `.gitleaksignore` made scans fail as an input "incident" | Such files are skipped as `unsupported_name` (coverage incomplete); the scan completes | `test_semgrepignore_directories_do_not_break_the_scan`, `test_a_root_gitleaksignore_directory_does_not_break_the_gitleaks_scan` | — |
| S12 | Tampering (supply chain) | The image is replaced | Digest-pinned allowlist; `--pull never`; same index digest under two repository names; pinned image environment | Policy and image tests; CI pre-pull by digest | amd64 only; no signature verification yet (M6) |

## Detection is not proof

- **What a finding means.** Code matches a pattern associated with a vulnerability
  class (CWE). It does **not** establish that attacker-controlled data reaches the sink,
  that the code is reachable or deployed, or that it is exploitable. The rules are
  intraprocedural patterns without taint tracking (`PATTERN_MATCHING_ONLY`).
- **What a clean scan means.** None of 13 patterns matched in the analyzed files. It
  says nothing about other vulnerability classes, other languages or unanalyzed files
  (`RULESET_MINIMAL`).
- **Decisions.** Turning findings into a gate decision, with exceptions and severity
  policy, is M4. Until then every scan is `INCOMPLETE`.

## Required before scanning real repositories

The requirements of the [Gitleaks threat model](gitleaks-scanner.md#required-before-remote-repository-scanning)
apply:
- verified commit snapshots fetched with scoped credentials;
- a stronger isolation boundary (gVisor, Kata or VMs);
- staged large snapshots;
- escaping in report rendering.

Additionally:
1. A broader, reviewed ruleset with a licensing decision (authored rules, or a
   compatible upstream source).
2. A decision on taint-mode rules and their cost and coverage reporting.
3. A decision on arm64 workers (the pinned image is amd64 only).

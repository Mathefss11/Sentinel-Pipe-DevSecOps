# Threat model: Gitleaks scanner integration

Scope:
- repository content crossing into a Gitleaks sandbox;
- the Gitleaks report crossing back into the worker;
- the normalized findings stored as evidence.

Builds on the [execution sandbox threat model](execution-sandbox.md) and the
[M3 Phase 1 assessment](../security/m3-phase1-threat-assessment.md) (threats A5 and A6),
as required by the Phase 2 entry criteria. Design: [ADR-0010](../adr/0010-scanner-adapters-repository-snapshots-and-findings.md).
Status: M3 Phase 2, Slice 1 (local synthetic repositories only), updated after the
[Slice 1 security review](../security/m3-phase2-slice1-security-review.md).

## Assets

| Asset | Why it matters |
|---|---|
| Secrets in repository content | The thing Gitleaks finds; must not spread into evidence, logs or metrics |
| Host files and worker credentials | Must never enter a snapshot or the sandbox |
| Findings evidence | Basis of future gate decisions (M4); must be complete or say that it is not |
| Coverage statements | A false "clean" is worse than a failure |

## Data flow and trust boundaries

```text
fixture dir (host, untrusted content) ──read once, validated──▶ worker (trusted)
   worker: RepositorySnapshot ─▶ deterministic tar (repo/, config/ ruleset, meta/paths.txt) ─▶ stdin
     ─▶ [sandbox: stage, list and refuse unsafe entries, extract into tmpfs, verify count + sha256sum digest,
         gitleaks over repo/ and over meta/paths.txt] (UNTRUSTED)
   sandbox stdout: sandbox-output.v1 { content report, paths report } ─▶ worker: strict parse, redaction check,
     safe paths, normalize
   worker ─▶ worker.put_evidence(findings.json) ─▶ PostgreSQL (digest computed, tenant-scoped, lease-bound)
```

Repository content crosses the sandbox boundary **only as data on stdin**. No host path is
mounted or otherwise visible to the container.

## Threats

| # | STRIDE | Threat | Controls | Verified by | Residual risk |
|---|---|---|---|---|---|
| G1 | Information disclosure | A symlink, junction or hard link in the repository pulls a host file (credentials, `.env`, SSH keys) into the scan | Links never followed (`lstat`, `O_NOFOLLOW`, reparse-point check); hard links skipped; containment re-check per directory; opened-file identity check | `test_symlinks_never_pull_host_files_into_the_snapshot`, `test_windows_junctions_are_never_followed`, `test_hard_links_are_skipped`, `test_symlink_escapes_never_reach_the_scanner` (real container) | Concurrent modification of the source by an attacker who already has host access is detected only for files (identity check), not proven for every directory race. Fixture directories are operator-controlled |
| G2 | Elevation of privilege | Lease values (`owner/name`) select a host directory outside the fixture root | Values from the database lease only; strict name pattern; every component a real directory; realpath containment; root must be absolute and not a link | `test_lease_repository_values_cannot_escape_the_root` (10 cases), `test_a_linked_repository_directory_is_refused` | — |
| G3 | Tampering | Repository-controlled suppression hides real secrets: `.gitleaks.toml` (root or nested), `.gitleaksignore`, `gitleaks:allow`, `GITLEAKS_CONFIG*`, and **file names matched by the default ruleset's path allowlists** (`*.png`, `node_modules/`, any path containing `gitleaks.toml`, …) | Worker ruleset without path allowlists (derived from the pinned upstream, SHA-256 checked); `--config`; root `.gitleaksignore` excluded and refused by the script; `--ignore-gitleaks-allow`; constant command; no environment, and an image-ENV guard | `test_repository_controlled_suppression_is_ignored`, `test_nested_suppression_files_are_inert`, `test_file_names_cannot_hide_secrets_from_the_ruleset` (12 hiding places), `test_the_image_sets_no_gitleaks_environment`, `test_the_ruleset_has_no_path_allowlists_and_keeps_every_upstream_rule`, E2E | The line-based allowlists of `generic-api-key` and `kubernetes-secret-yaml` remain: content on the same line can suppress those two generic rules. Future versions may add new suppression inputs (review on upgrade, runbook §5) |
| G4 | Spoofing (false clean) | A missing, empty, truncated or altered input makes Gitleaks exit 0 with `[]` | The script verifies the extracted file count, types and a `sha256sum` digest over every name and content against the worker's snapshot; exit codes must agree with both reports; an empty snapshot is flagged `EMPTY_INPUT`; fail closed | `test_truncated_or_tampered_input_never_yields_a_scan`, `test_input_that_does_not_match_the_snapshot_is_never_a_clean_scan`, `test_exit_codes_must_agree_with_both_reports`, `test_an_empty_repository_is_flagged_not_clean` | Gitleaks' own internal behavior (for example decoding depth) is trusted as reviewed |
| G5 | Information disclosure | Raw secrets, including **secrets in file and directory names**, persisted in evidence, fingerprints, logs, metrics, audit records or exception chains | `--redact=100` at the source; unredacted entries refused; `Match`/`Secret` never copied; schema forbids excerpts for secrets; reports not stored (digest only); **safe paths** (names scanned with the same rules, then redacted, plus a heuristic); fingerprints over safe paths; codes-only logging; errors raised without exception context | `test_a_secret_in_a_file_name_becomes_a_redacted_path_finding`, `test_fingerprints_use_only_the_safe_path`, `test_secrets_in_file_and_directory_names_are_detected_and_redacted` (real), `test_secrets_in_file_names_are_never_stored` (integration: evidence, results, audit), E2E (evidence, results, audit, worker output), `test_scanner_errors_carry_no_content_and_no_exception_chain`, `test_scanner_stderr_is_never_logged`, `test_logs_never_contain_file_names` | Name redaction is best-effort: a secret that matches no rule and looks low-entropy stays in its path. `content_sha256` and `raw_report_sha256` can confirm a complete guess of the input. A compromised sandbox could place repository content into kept fields (rule id within its pattern, sanitized description) |
| G6 | Tampering | A malicious or broken report (malformed JSON, duplicate keys, deep nesting, unknown fields, foreign paths, huge counts) corrupts findings or exhausts the worker | Strict parser: exact key set, types, ranges, rule-id pattern, paths must be snapshot files, Git metadata fields must be empty, entry and finding caps, document schema validation | `test_malformed_output_fails_closed_with_a_code`, `test_unexpected_report_entries_are_refused`, `test_only_files_of_the_snapshot_can_be_reported`, `test_findings_beyond_the_supported_bounds_fail_explicitly` | A compromised sandbox can still report false or omit true findings for its own job (integrity, not authenticity; ADR-0008, M6) |
| G7 | Elevation of privilege | Hostile file content exploits a Gitleaks parser bug | Sandbox controls unchanged (no network, read-only root, `noexec` tmpfs, uid 65534, no capabilities, seccomp, limits); `--max-archive-depth 0`; no environment or credentials inside | `sandbox-check --profile gitleaks` (13/13), `test_every_isolation_control_holds_under_the_gitleaks_policy` | Code execution inside the sandbox; escape requires a kernel or runtime exploit (ADR-0009, A7). **Not acceptable for hostile production content under runc** |
| G8 | Injection | File names that look like shell syntax or options (`$(...)`, backticks, leading `-`, quotes, RTL override) | Constant script; names never interpolated; the archive is data; Gitleaks receives a directory, not names | `test_unusual_and_hostile_file_names_are_scanned_as_data` (real container), `test_unusual_unicode_and_shell_like_names_are_kept_verbatim` | Unicode display tricks (RTL override, homoglyphs) survive into findings paths. Report renderers (M4) must escape them |
| G9 | Denial of service | Huge repositories, many files, huge files or reports, output floods, slow scans | Snapshot limits (fail on file or total overflow); stdin, stdout, tmpfs, memory, CPU, PID and time limits; report size check in the sandbox; finding caps; cancellation kills the sandbox | `test_exceeding_the_input_limits_fails_explicitly`, `test_an_oversized_report_fails_explicitly`, `test_output_beyond_the_stdout_limit_is_a_resource_failure`, `test_cancellation_kills_a_running_scan_and_leaves_nothing_behind` | The snapshot is held in worker memory (≤ 16 MiB of content plus the archive) |
| G10 | Repudiation | Disputed findings | Findings bound to job, lease, tenant and commit (as claimed); content digest of the scanned input; digest of the native report; execution events | Integration and E2E tests | The input is not proven to be the commit (`commit_verified = false`) |
| G11 | Spoofing | Stale, crashed or cancelled attempts get findings accepted | Lease fencing and evidence binding (ADR-0007/0008) unchanged | `test_a_crashed_attempt_is_retried_and_only_the_new_lease_is_accepted`, `test_a_lost_lease_never_gets_findings_accepted`, `test_a_cancelled_scan_never_gets_findings_accepted` | — |
| G12 | Tampering (supply chain) | The Gitleaks image or ruleset is replaced | Digest-pinned allowlist; `--pull never`; same index digest cross-checked on ghcr.io and docker.io at review; ruleset vendored and derived only from the reviewed upstream file (SHA-256 checked) | Policy tests; ruleset invariant test; CI pre-pull by digest | No signature or provenance verification yet (M6) |
| G13 | Tampering, elevation within the sandbox | A malformed archive (a builder bug) overwrites files, escapes the input directory via links or traversal, or creates devices or FIFOs | Snapshot invariants on construction (safe, unique, sorted paths; no file/directory conflict); archive builder refuses unsafe or duplicate entries; the sandbox lists the staged archive and refuses anything but plain files and directories with safe, unique names under `repo/`, `config/`, `meta/` (exit 75); extraction confined to the sandbox's tmpfs | `test_hostile_archive_members_are_refused_before_extraction` (10 real cases), `test_snapshots_refuse_unsafe_or_ambiguous_paths`, `test_archives_cannot_overwrite_or_escape` | Relies on BusyBox `tar -tv` output format (pinned image) |
| G14 | Denial of service | The stdin transfer blocks forever (a sandbox or runtime CLI that never reads), leaking threads or memory | Writer thread per run; stop, timeout or exit kills the container and closes the pipe; the writer is joined; the input size is checked before start | `test_a_sandbox_that_exits_without_reading_stdin_never_blocks_the_writer`, `test_stopping_during_the_transfer_kills_the_sandbox_and_releases_the_writer`, `test_a_runtime_cli_that_exits_without_reading_stdin_releases_the_writer`, `test_oversized_stdin_is_refused_before_anything_starts` | Peak worker memory per job is about the snapshot plus its archive (≤ 16 MiB of content, archive ≤ 32 MiB) plus the stdout buffer |

## What Gitleaks does and does not tell us

- **Detects:** secrets matching its built-in rules (provider-specific token formats,
  private keys, generic high-entropy assignments) in the working-tree files of the
  snapshot.
- **Does not detect:**
  - secrets in Git history;
  - secrets inside archives;
  - secrets whose surrounding line matches the line-based allowlists of the two generic
    rules;
  - secrets in encodings beyond its decoding depth;
  - secrets with no matching rule;
  - secrets in skipped files (links, oversized files, unsupported names);
  - whether a detected secret is valid or still active.
- **Findings do not automatically mean FAIL.** Test fixtures, revoked credentials and
  false positives exist. Turning findings into a gate decision, with exceptions and
  expiry, is the job of versioned policies (M4).
- **A clean run does not mean PASS.** Coverage is bounded, and the decision requires
  policy evaluation. Until M4 every scan is `INCOMPLETE`.

## Required before remote repository scanning

1. A repository source that fetches the leased commit in an **isolated fetch step** with
   a short-lived, repository-scoped credential (GitHub App installation token or Actions
   OIDC, M5), never the worker's credentials. It must export Git objects without running
   hooks, filters, LFS or submodules.
2. Verified binding of the snapshot to the commit and tree (`commit_verified = true`).
3. A **stronger isolation boundary** for attacker-controlled content (gVisor or Kata
   validated with `sandbox-check`, or disposable VMs per job), per the ADR-0009 trust
   policy. Dedicated worker hosts.
4. Snapshot staging for repositories above the in-memory limits (object storage with
   control-plane-verified digests, ADR-0008).
5. Report rendering (M4) that escapes paths and descriptions, including bidirectional
   and control characters.
6. A decision on whether to also scan history (`gitleaks git`), with its coverage and
   cost.

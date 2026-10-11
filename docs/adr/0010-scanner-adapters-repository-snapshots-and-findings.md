# ADR-0010: Scanner adapters, repository snapshots and normalized findings

- **Status:** Accepted with conditions (2026-10-11; see [Acceptance](#acceptance)).
  Previously Proposed.
- **Date:** 2026-10-10
- **Milestone:** M3 Phase 2 (Slice 1: Gitleaks)
- **Builds on:** [ADR-0007](0007-database-authoritative-execution-leases.md) (leases),
  [ADR-0008](0008-result-integrity-and-evidence.md) (verified evidence),
  [ADR-0009](0009-isolated-ephemeral-sandbox-execution.md) (sandbox)
- **Amends:** ADR-0009 (the sandbox may receive one bounded input archive on stdin)
- **Threat model:** [Gitleaks scanner](../threat-model/gitleaks-scanner.md)
- **Security review:** [Slice 1 review](../security/m3-phase2-slice1-security-review.md)
  (defects D1–D4 fixed; this ADR reflects the fixed design)

## Context

M3 Phase 1 built a sandbox that runs only the harmless FIXTURE, which reads no repository
content. Real scanners must read untrusted repository files, run as reviewed tools under
the same isolation, and turn their native output into evidence that later policy
evaluation (M4) can use. This slice integrates the first scanner, Gitleaks. The design
has to carry over to Semgrep and Trivy.

The constraints from Phase 1 still apply:
- scanners get no credentials, network or host files;
- results leave the sandbox only as data (`sandbox-output.v1`);
- evidence is verified by the database (ADR-0008);
- execution status is separate from the security decision, and `PASS` is impossible
  without policy evaluation.

No remote cloning or GitHub credentials are allowed in this slice.

## Decision

### 1. Scanner adapters

A scanner is integrated as an adapter (`sentinel_worker/scanners/adapter.py`) that owns
everything scanner-specific:

| Concern | Gitleaks |
|---|---|
| Identity and version | `gitleaks` 8.30.1 |
| Image | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…bbb7f` (the multi-platform index digest; the same digest is published on docker.io), in the sandbox image allowlist |
| Sandbox policy | Phase 1 controls unchanged; 512 MiB memory, 128 PIDs, 96 MiB tmpfs (corrected at acceptance; see below), 2 MiB stdout, 32 MiB stdin |
| Input | Snapshot archive on stdin (decision 2) |
| Command | `/bin/sh -c <constant script>` with two validated integers as positional arguments |
| Output | `sandbox-output.v1` carrying the native JSON report as one artifact |
| Exit codes | 0 clean, 41/42/43 leaks found in content, file names or both, 70–75 script failures, anything else a failure |
| Normalization | Strict report parsers (content and path reports) → `findings.v1`, safe paths only |
| Evidence | One `findings.json` artifact. The native report is parsed in memory and only its digest is kept |
| Failure classification | Sanitized codes mapped onto the existing `job-result.v1` reasons |

`ScannerExecutor` runs any adapter. It:
- builds the snapshot from the lease's repository;
- runs the sandbox;
- maps non-exit outcomes (timeout, OOM, PID and output limits, cancellation, runtime
  failure) exactly as for the FIXTURE;
- hands a normal exit to the adapter.

`DispatchingExecutor` lets one worker serve several scanner types. No other abstraction
was added.

### 2. Repository input: snapshots on stdin, no mounts

The no-mount policy of ADR-0009 is **kept**. Instead of bind-mounting a directory, the
worker:

1. Reads the repository once into an in-memory snapshot
   (`sentinel_worker/repository/snapshot.py`):
   - regular files only;
   - relative POSIX paths, sorted;
   - bounded: 5000 files, 1 MiB per file, 16 MiB in total, 1024-byte paths, depth 32.
2. Serializes the snapshot as a deterministic GNU tar:
   - fixed owner, modes and timestamps;
   - files and directories only.
3. Writes the archive to the container's stdin (`--interactive`), bounded by the
   policy's `max_stdin_bytes`. Stdin is closed by default (`max_stdin_bytes = 0`) and
   refused for any policy that does not allow it.
4. The constant script stages the archive in the sandbox's own `noexec` tmpfs, refuses it
   unless every entry is a plain file or directory with a safe name, extracts it, and
   verifies the extracted content against the snapshot before scanning (decision 3).

While reading, the worker treats the filesystem as hostile:

| Entry | Handling |
|---|---|
| Symbolic links, Windows junctions, other reparse points | Never followed; skipped and counted |
| Hard-linked files (`st_nlink > 1`) | Skipped: a hard link to a file outside the repository cannot be distinguished by path |
| FIFOs, devices, sockets | Skipped (could block or expose host resources) |
| Names with control characters or backslashes, non-UTF-8 names, overlong paths, excessive depth | Skipped as `unsupported_name` |
| Files over the size limit | Skipped as `oversized` |
| More files or bytes than allowed | The snapshot **fails** (`INPUT_TOO_LARGE`); nothing is truncated |
| Files opened during the walk | Opened with `O_NOFOLLOW`; the opened file must be the inspected one (device, inode, type, size), otherwise `INPUT_CHANGED` |
| Directories descended into | Must still resolve inside the root |
| `.git` directories | Excluded by design (`vcs_metadata`) |
| Root `.gitleaksignore` | Excluded by design (`suppression_file`, decision 4) |

Skips other than the two by-design exclusions make coverage **incomplete**. This is
recorded in the findings document (`coverage.complete = false`, `FILES_SKIPPED`), never
hidden.

**Why not a read-only bind mount?**
- A mount exposes a host path to the runtime and depends on correct symlink and
  hard-link handling by the source.
- It cannot bound the size of what the scanner reads.
- It would weaken the `no_host_mounts` control that `sandbox-check` verifies.

With stdin:
- the sandbox never learns or reaches a host path;
- a malicious repository cannot change the source;
- the existing isolation probe stays valid unchanged. `sandbox-check --profile gitleaks`
  verifies all 13 controls under the Gitleaks image and limits, and a test confirms that
  attaching input adds no mount.

A read-only mount alone would not protect against malicious content anyway: the content
is parsed by the scanner in either case.

**Source selection.** `LocalFixtureRepositorySource` is the only source in this version.
It holds synthetic repositories under `SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR`
(development and CI):
- The job's repository `owner/name` comes from the **database lease**, never from a
  message.
- It selects `<root>/<owner>/<name>`. Both values must be GitHub-style names (no `..`,
  separators or leading dots).
- Every component must be a real directory, not a link, and the result must resolve
  inside the root.

The findings document says `input.kind = LOCAL_FIXTURE` and `commit_verified = false`:
the content is not proven to be the leased commit.

**Evolution towards commit snapshots.** A later source builds the same
`RepositorySnapshot` from a verified commit instead of a local directory:
1. An isolated fetch step runs with a short-lived, repository-scoped credential (GitHub
   App installation token or Actions OIDC, M5), never the worker's credentials. It
   resolves the leased commit SHA and exports its tree from Git objects
   (`git archive`-like, so no checkout, hooks, filters or submodules run).
2. The snapshot records the commit and tree identity next to the content digest, and the
   findings document sets `commit_verified = true`.
3. Large snapshots are staged in the S3-compatible evidence backend and referenced by
   digest instead of being streamed through the worker.

The scanner side (stdin archive, verification script, adapter) does not change.

### 3. Gitleaks execution

- **Hardened script.** The script is a constant (`sentinel_worker/scanners/gitleaks.py`).
  Its only arguments are the expected file count and the report size limit, both
  integers generated by the worker. There is no shell interpolation of repository data.
- **Archive checks before extraction** (exit 75 when refused):
  - every entry is a regular file or directory. Symbolic and hard links, devices and
    FIFOs are refused. BusyBox lists a hard link as a file with a `-> target` suffix, so
    each long-listing line must end with exactly its entry name;
  - names are relative, contain no `..`, are unique (no overwrites), and live under
    `repo/`, `config/` or `meta/`.

  BusyBox would otherwise create links, and a symlink entry followed by `link/file`
  would write outside the input directory.
- **Input checks after extraction, before scanning** (exit 72 on mismatch):
  - `repo/`, the worker's config and the path manifest exist;
  - `repo/` holds only files and directories, exactly the expected number of files, and
    no root `.gitleaksignore`;
  - the `sha256sum` digest over every extracted file's name and content equals the
    worker's `extraction_sha256`. The scanner provably sees exactly the snapshot, and a
    partial or altered extraction cannot pass.

  This closes a verified false-clean path: Gitleaks reports a missing target as exit 0
  with `[]`.
- **Two scans.** Gitleaks runs over `repo/` (content) and over `meta/paths.txt`, a
  worker-generated list of the snapshot's paths, so the same rules detect secrets in file
  and directory names (decision 5).
- **Flags:** `--config` (worker-controlled), `--gitleaks-ignore-path`,
  `--ignore-gitleaks-allow`, `--max-archive-depth 0`, `--redact=100`,
  `--report-format json`, `--exit-code 42`, `--log-level error`, `--no-banner`. Gitleaks'
  stdout is discarded; the script alone writes the envelope.
- **Exit codes:**

  | Code | Meaning | Result |
  |---|---|---|
  | 0 | Both scans ran, no leaks | `COMPLETED`, no findings |
  | 41 / 42 / 43 | Leaks in content / file names / both | `COMPLETED` with findings (**not** a failure) |
  | 70 | Gitleaks failed (exit code 1 = error, or any other code) | `FAILED SCANNER_ERROR` (retried) |
  | 71 | Input could not be staged or extracted | `FAILED SCANNER_ERROR` |
  | 72 | Extracted input differs from the snapshot | `FAILED SCANNER_ERROR` |
  | 73 | Report missing | `FAILED SCANNER_ERROR` |
  | 74 | Content report over 1 MiB or path report over 256 KiB | `FAILED RESOURCE_LIMIT_EXCEEDED` (final) |
  | 75 | Archive refused before extraction | `FAILED SCANNER_ERROR` |
  | Other 1–127 | Unexpected | `FAILED SCANNER_ERROR` |
  | ≥ 128 | Killed | `FAILED SANDBOX_ERROR` |

  A code that disagrees with either report (for example 0 with findings, or 41 with
  path findings) fails closed. A scanner error is never interpreted as a clean scan.

### 4. Repository-controlled suppression is disabled

Each of these was verified against the pinned 8.30.1 image before it was designed in, and
is covered by real-container tests:

| Mechanism | Default Gitleaks behavior | Control |
|---|---|---|
| `.gitleaks.toml` in the scanned directory (or nested) | The root file is loaded automatically and can allowlist everything; nested files are not loaded | `--config` with the worker's ruleset |
| **Path allowlists in the default ruleset** | The global allowlist skips files by name, for example `*.png`, `*.exe`, `*.pdf`, `go.sum`, lockfiles, `node_modules/`, `vendor/…`, and any path containing `gitleaks.toml` (unanchored). Three rule-level allowlists also match paths, for example `@octokit/auth-token/README.md` for GitHub tokens. A repository author controls all of these by naming files | The worker's ruleset is the pinned upstream v8.30.1 default **without path-based allowlists** (`scanners/gitleaks-rules.toml`, generated by `scripts/dev/derive-gitleaks-rules.py`, which checks the upstream SHA-256). Value-based allowlists (global regexes and stopwords, and rule-level regexes) are kept |
| `GITLEAKS_CONFIG` / `GITLEAKS_CONFIG_TOML` | Override the configuration | The sandbox receives no environment |
| `.gitleaksignore` at the root of the scanned directory | **Always loaded**; suppresses findings by fingerprint (nested files are not loaded) | Excluded from the snapshot; the script refuses to scan if one is present |
| Inline `gitleaks:allow` comments | Suppress the line | `--ignore-gitleaks-allow` |
| CLI options (`--baseline-path`, `--enable-rule`, `--max-target-megabytes`, …) | Narrow what is reported | The command is constant; its only arguments are worker-generated integers and a digest |
| Line-based regex allowlists of `generic-api-key` and `kubernetes-secret-yaml` | Skip a match when the surrounding line matches (for example `--mount=type=secret,`, an `import … from` statement) | **Not removed** (removing them would flood generic detection with false positives). Content on the same line can therefore suppress *these two generic rules*; provider-specific rules have no such allowlists. Documented residual risk |

### 5. Normalized findings: `findings.v1`

The contract is `packages/contracts/messages/v1/findings.v1.schema.json` (JSON Schema
2020-12), bundled byte-identically in the worker and checked in Java and Python. It is
documented in [findings contract v1](../api/findings-contract-v1.md).

**Fields:**
- scanner identity, version and image digest;
- the authoritative job context;
- input: kind, `commit_verified`, content digest, counts and skip reasons;
- coverage: `complete` and limitations;
- execution: status, exit code and the digest of the native report;
- findings: id, fingerprint, scanner, rule, category, description, location, severity,
  confidence, evidence, remediation, status and occurrences.

**Rules:**
- **Safe paths only.** File and directory names are repository content and may contain
  credentials (security review D2). A path component is replaced by a `[redacted-N]`
  label when:
  - the Gitleaks scan of `meta/paths.txt` flagged it. Such a detection is also reported
    as a finding with `location.target = FILE_PATH`, and lines and columns null; or
  - a heuristic flags it (known credential prefixes, or long, high-entropy runs of
    letters and digits).

  Labels are assigned per snapshot in the sorted order of the distinct redacted
  components, and a redacted component is redacted wherever it occurs. Raw paths never
  reach findings, fingerprints, logs, audit records or metrics. This is best-effort,
  not a guarantee: a secret that matches no rule and looks low-entropy is not
  recognized.
- **No invented attributes.** Severity, confidence and remediation are `null` because
  Gitleaks provides none. `status` is `OPEN`. Lifecycle states (new, existing, resolved)
  need valid comparisons (M4).
- **Secret findings never carry an excerpt.** The schema itself requires
  `evidence = {redacted: true, excerpt: null}` for `category = SECRET`.
- **Fingerprint:** SHA-256 of
  `["sentinelpipe.finding.v1", scanner, rule, target, safe path, start line, end line, start column, end column]`.
  It is deterministic, contains no secret value and no raw path, and is location-based,
  so it changes when code moves. Redaction labels can shift when other secret-named
  components are added. Cross-commit correlation belongs to M4.
- **Deduplication:** identical fingerprints in one run are merged and counted in
  `occurrences`.
- **Ids:** UUIDv5 of job id and fingerprint.
- **Order and bytes:** findings are sorted deterministically, and the document is
  canonical JSON. The same input gives the same findings, ids, fingerprints and coverage.
  The exception is `execution.raw_report_sha256`, which digests the native report
  actually observed and varies between runs (Gitleaks' output order is concurrent).
  Corrected in Slice 2; the original text claimed identical bytes.
- **Bounds:**
  - at most 1000 findings and 1 MiB per document; 5000 raw report entries; 1 MiB per
    native report;
  - exceeding a bound fails the job with `RESOURCE_LIMIT_EXCEEDED`;
  - findings are never dropped silently.

### 6. Secret redaction (defense in depth)

1. **Gitleaks** redacts at the source (`--redact=100`), so in normal operation the raw
   value never leaves the sandbox. Verified: the sandbox stdout of a leaky scan does not
   contain the synthetic secret.
2. **The worker refuses unredacted reports.** Every entry must have
   `Secret == "REDACTED"` and a `Match` containing the marker; otherwise the run fails as
   `UNREDACTED_REPORT`, and the value appears in no exception, log or metric.
3. **Nothing raw is kept.** `Match`, `Secret`, entropy and the Git metadata fields are
   never copied. The metadata fields must be empty for a directory scan, so author names
   and emails cannot slip in.
4. **Prose is sanitized.** Descriptions have control characters removed, token-like runs
   redacted and their length bounded.
5. **Paths are checked and made safe.** A reported content path must be a file of the
   snapshot, and a path detection must point at a manifest line, so the scanner cannot
   inject arbitrary strings. Only safe paths are persisted.
6. **The native reports are never stored or logged.** Only their SHA-256 is recorded.
   Worker logs carry sanitized codes and counts. Sandbox stderr is bounded, heuristically
   redacted, and never logged or persisted.
7. **No exception chains.** Parser and envelope errors are raised outside `except`
   blocks, so no `ScannerError` carries a `__context__` that could hold report text.

What this does **not** establish: that every secret is recognized (detection is
rule-based), and that a compromised sandbox cannot place repository content into the
fields the worker keeps (rule id within its pattern, sanitized description). Two digests
are kept as integrity anchors, the input `content_sha256` and `raw_report_sha256`. Both
are computed over material that may contain secrets: they cannot be inverted, but they
can confirm a complete guess. They must not be published outside the tenant (for example
in pull-request comments, M5) without review.

### 7. Results, evidence and decisions

- **Integration with the existing pipeline.** `findings.json` is uploaded through
  `worker.put_evidence` and referenced in `job-result.v1`. Lease fencing, tenant-scoped
  content addressing, database-computed digests and re-verification on read (ADR-0008)
  apply unchanged.
- **No schema or migration changes.** `GITLEAKS` was already a valid scanner type in
  V007/V008.
- **Findings are not a decision.** A run that finds secrets is `COMPLETED`, not a
  failure. A clean run is not `PASS`. Until M4, every evaluation records
  `INCOMPLETE / POLICY_EVALUATION_UNAVAILABLE` (end-to-end tested for both cases).
- **Production gating.** The worker refuses `SENTINEL_WORKER_GITLEAKS_ENABLED=true` in
  `production`, and the API refuses `GITLEAKS` in `planned-scanners` under production
  profiles, because the only repository source is local fixtures.

## Consequences

- **Adding a scanner** means adding an adapter: image digest, policy, constant command,
  exit-code table, strict parser, normalization, tests. Semgrep and Trivy reuse the
  snapshot, stdin channel, executor and findings contract. The contract will gain
  categories and scanner names in a compatible way.
- **Memory.** Snapshots are held in worker memory, which is bounded at 16 MiB of content.
  Larger repositories need the staged commit-snapshot path (decision 2).
- **Coverage limits** are inherent to the scanner and are recorded as limitations in
  every document:
  - Git history is not scanned (`GIT_HISTORY_NOT_SCANNED`);
  - archives are not opened (`ARCHIVES_NOT_SCANNED`);
  - only the upstream default rules are used, without custom rules and with value-based
    allowlists (`RULESET_DEFAULT_ONLY`). Path allowlists were removed, so every file of
    the snapshot is scanned;
  - an empty snapshot is flagged (`EMPTY_INPUT`) rather than reported as a clean
    repository;
  - the content is not proven to be the commit (`COMMIT_NOT_VERIFIED`).
- **Isolation strength is unchanged.** Gitleaks is a trusted tool
  (`Workload.TRUSTED_TOOL`) parsing untrusted content under runc. A parser exploit gives
  code execution inside the sandbox, and escaping it needs a kernel or runtime exploit
  (ADR-0009 trust policy). This is acceptable for synthetic fixtures. Hostile
  production content needs the stronger isolation required by ADR-0009 (see the threat
  model).

## Alternatives considered

- **Read-only bind mount of the repository.** Rejected (decision 2).
- **`docker cp` into a created container.** Rejected: it needs a host path and a
  multi-step lifecycle, and offers no advantage over stdin.
- **Storing the native Gitleaks report as evidence.** Rejected: it contains `Match`
  context and fields the worker cannot vouch for. Its digest is enough for traceability.
- **Hashing the secret into the fingerprint.** Rejected: a hash of a low-entropy secret
  can be brute-forced offline.
- **Gitleaks `git` mode on a checkout.** Deferred: it requires repository history, Git
  in the sandbox and verified commit snapshots (M5).
- **New failure reasons (for example `INPUT_UNAVAILABLE`).** Rejected for this slice: the
  reasons live in the database contract (V008), and the existing ones are accurate enough
  (`SCANNER_ERROR`, retried; `RESOURCE_LIMIT_EXCEEDED`, final). Sanitized codes in the
  logs give the detail.

## Acceptance

- **Decision:** Accepted with conditions. The design was implemented, reviewed
  ([Slice 1 review](../security/m3-phase2-slice1-security-review.md)), re-reviewed during
  Slices 2 and 3, and its decisions held under adversarial testing.
- **Date:** 2026-10-11.
- **Decision owner:** the repository owner. Recorded on the owner's instruction; the
  instruction authorizes recording this conditional acceptance, not waiving any
  restriction below.
- **Supporting CI:** GitHub Actions run #13 on `main`, commit `f0f6a83`, all six jobs
  green (Java 21, Python 3.12, Python 3.14, real-container sandbox, end-to-end,
  infrastructure configuration), as reported by the repository owner. The recorder did
  not query GitHub; the only CI log archive in the working tree belongs to the preceding
  commit `7b2c42f`, whose sandbox and end-to-end jobs failed with the Trivy image
  `LOAD_FAILED` error that `f0f6a83` fixes. CI demonstrates the tested behaviors, not
  complete security coverage.
- **Production restrictions (unchanged):**
  - Gitleaks reads only local synthetic fixtures (`LocalFixtureRepositorySource`); the
    worker refuses `SENTINEL_WORKER_GITLEAKS_ENABLED=true` in `production`, and the API
    refuses `GITLEAKS` in `planned-scanners` under production profiles;
  - runc is not an adequate boundary for hostile repository content (ADR-0009); arbitrary
    repository scanning is not authorized.
- **Residual risks accepted as documented:**
  - the line-based regex allowlists of `generic-api-key` and `kubernetes-secret-yaml`
    (content on the same line can suppress those two generic rules);
  - file-name redaction is best-effort;
  - fingerprints are location-based and redaction labels can shift;
  - `content_sha256` and `raw_report_sha256` can confirm a complete guess of the input;
  - Git history and archives are not scanned; the content is not proven to be the commit
    (`COMMIT_NOT_VERIFIED`);
  - integrity, not authenticity: a compromised sandbox can misreport its own job;
  - the vendored ruleset is the pinned upstream default without path allowlists
    (derivation checked by `scripts/dev/derive-gitleaks-rules.py`).
- **Correction recorded at acceptance:** decision 1 stated a 64 MiB tmpfs. The code
  (`GitleaksAdapter.policy`) and the [runbook](../runbooks/gitleaks.md) have used 96 MiB
  since `a79c2c5`; the table now says 96 MiB. No guarantee depended on the stated value
  (the tmpfs counts against the 512 MiB memory limit).
- **Follow-up work:**
  - policy evaluation of `findings.v1` evidence:
    [ADR-0013](0013-security-policy-engine.md) (M4 Phase 1);
  - verified commit snapshots (M5) and stronger isolation before any hostile content;
  - a shared, sandboxed file-name classification pass (needs approval).

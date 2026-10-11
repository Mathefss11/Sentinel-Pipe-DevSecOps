# Scanner adapters

Decision records: [ADR-0010](../adr/0010-scanner-adapters-repository-snapshots-and-findings.md)
(architecture, Gitleaks), [ADR-0011](../adr/0011-semgrep-sast-with-a-bundled-ruleset.md)
(Semgrep), [ADR-0012](../adr/0012-trivy-sca-with-an-embedded-verified-database.md)
(Trivy, embedded vulnerability database).
Execution lifecycle: [execution-lifecycle.md](execution-lifecycle.md).

## Flow of one scanner job

```text
worker.claim_job ─▶ JobLease (authoritative repository, commit, tenant)
   │
   ▼
ScannerExecutor.execute(lease, stop)
   ├─ RepositorySource.snapshot(lease)     validated, bounded, immutable RepositorySnapshot
   ├─ adapter.prepare(snapshot)             minus scanner control files (e.g. .semgrepignore)
   ├─ adapter.stdin(snapshot)               deterministic tar (repo/ + worker ruleset + path manifest;
   │                                        Trivy: dependency files + report template only)
   ├─ adapter.command(snapshot)             constant script, validated integer arguments
   ├─ DockerSandbox.run(argv, stop, stdin)  fresh hardened container of adapter.sandbox_image,
   │                                        killed on cancel/lease loss
   │     └─ not EXITED ─▶ outcome_for(run)  timeout / limits / cancel / runtime failure
   └─ adapter.interpret(run, snapshot, lease)
         ├─ exit-code semantics             findings ≠ failure; errors ≠ clean
         ├─ sandbox-output.v1 → native report (strict, in memory, never stored)
         ├─ redaction checks, safe paths (scanners/paths.py), normalization, deduplication
         └─ findings.json (findings.v1)     or ScannerError(code, reason)
   │
   ▼
ExecutionLoop: worker.put_evidence(findings.json) ─▶ worker.submit_result(job-result.v1)
```

## Modules

| Module | Responsibility |
|---|---|
| `sentinel_worker/repository/snapshot.py` | `RepositorySource` protocol; `LocalFixtureRepositorySource`; safe directory walking; deterministic archives; content digest |
| `sentinel_worker/scanners/adapter.py` | `ScannerAdapter` protocol and `ScannerError` |
| `sentinel_worker/scanners/executor.py` | `ScannerExecutor` (any adapter) and `DispatchingExecutor` (several scanner types in one worker) |
| `sentinel_worker/scanners/findings.py` | `Finding`, fingerprints, deduplication, canonical `findings.v1` documents |
| `sentinel_worker/scanners/gitleaks.py` | The Gitleaks adapter (image, policy, script, exit codes, parsers) |
| `sentinel_worker/scanners/gitleaks-rules.toml` | Derived, pinned Gitleaks ruleset without path allowlists (`scripts/dev/derive-gitleaks-rules.py`) |
| `sentinel_worker/scanners/paths.py` | Safe representation of repository paths (redaction labels) |
| `sentinel_worker/scanners/sandbox_input.py` | Shared script fragment: archive staging, listing checks, extraction, count and digest verification; shared exit codes; strict JSON loading |
| `sentinel_worker/scanners/semgrep.py` | The Semgrep adapter (image, policy, ruleset catalog and validation, script, exit codes, parser, coverage cross-check) |
| `sentinel_worker/scanners/semgrep-rules.json` | Bundled, reviewed Semgrep ruleset, pinned by SHA-256 |
| `sentinel_worker/scanners/trivy.py` | The Trivy adapter (policy, input selection, report template, script, freshness, strict parser, dependency coverage) |
| `sentinel_worker/scanners/trivy_image.py` | The Trivy image with an embedded database: lock, metadata and provenance validation, deterministic construction, content verification, bbolt structure check |
| `sentinel_worker/scanners/trivy-base-config.json` | Vendored configuration blob of the pinned Trivy base image (linux/amd64), pinned by SHA-256 |
| `sentinel_worker/sandbox/policy.py` | Image allowlist and the registry of content-verified local images, stdin limit, runtime arguments (`--interactive` only when allowed) |

## The three adapters compared

| | Gitleaks | Semgrep | Trivy |
|---|---|---|---|
| What it reports | Secrets (`SECRET`) | Code patterns (`CODE_PATTERN`); not proof of exploitability | Dependency versions in advisories' affected ranges (`DEPENDENCY_VULNERABILITY`); not proof of reachability |
| Rules or data | Upstream default, derived without path allowlists | Authored here, 13 rules, validated catalog | Vulnerability database in a verified image layer; freshness enforced |
| Sandbox image | Pinned upstream image | Pinned upstream image | Local image: pinned base plus database layer, verified by content at start |
| Repository control files removed | Root `.gitleaksignore` | Every `.semgrepignore` | Only dependency files are sent at all |
| Extra input | Path manifest (detects secrets in names) | None | Report template |
| Text from scanner output | Description sanitized, then kept | Never kept: catalog only | Identifiers and versions only (template); values validated and redacted |
| Coverage | Snapshot skips | Snapshot skips plus per-language analysis cross-check | Per-manifest result check plus dependency counts (partial formats, unresolved versions, missing lockfiles, unsupported formats) |
| Success exit codes | 0, 41, 42, 43 | 0, 41 | 0 (findings decided by the report) |
| Limits | 512 MiB, 128 PIDs, 96 MiB tmpfs | 1 GiB (256 MiB per file), 64 PIDs, 128 MiB tmpfs (measured) | 512 MiB, 64 PIDs, 128 MiB tmpfs, 1 MiB report (measured) |

## Adding a scanner (checklist)

1. **Review the scanner and pin its image** by index digest, cross-checked on every
   registry that publishes it, and add it to `ALLOWED_IMAGES` and CI's pre-pull list.
   A scanner that needs data too large for stdin follows the Trivy pattern (ADR-0012): a
   deterministic data layer on the pinned base, verified by content before use.
2. **Verify its behavior on the pinned image before designing around it:**
   - configuration discovery, and any repository-controlled configuration or
     suppression files and comments;
   - environment variables it reads;
   - exit codes, including its behavior on a missing or empty target;
   - redaction options;
   - the exact report schema;
   - network needs. The default is none; a vulnerability database must be provisioned
     offline or behind an explicit allowlist;
   - **built-in allowlists or exclusions keyed on file names** (a repository author
     controls names, so these are suppression mechanisms);
   - whether its reports can carry file names, which must go through safe paths;
   - whether its output can carry **source text** (interpolated messages, matched lines);
     if so, take such fields from a trusted catalog or omit them;
   - which files it analyzes, and how it reports skipped or partly parsed files, so that
     coverage can be cross-checked;
   - environment variables declared by its image (pin them in `IMAGE_ENVIRONMENT`).
3. **Write the adapter:**
   - a sandbox policy within the global bounds;
   - a constant command;
   - an input-verification step in the sandbox;
   - an explicit exit-code table;
   - a strict parser with an exact key set, paths restricted to the snapshot, and bounds;
   - normalization without invented severity or confidence;
   - a list of coverage limitations.
4. **Extend `findings.v1` compatibly** (scanner name, category, limitation codes) and
   update the Java and Python contract checks.
5. **Test it:**
   - unit tests with scripted runs (exit codes, malformed output, redaction, limits);
   - real-container tests (detection, suppression attempts, hostile names, links, input
     tampering, isolation probe under its policy, cancellation, no leftovers);
   - integration tests through the protocol;
   - an end-to-end test.
6. **Document it:** a scanner-specific threat model and runbook, and update the ADR.
7. **Gate it:** refuse it in production until its repository source and isolation
   requirements are met.

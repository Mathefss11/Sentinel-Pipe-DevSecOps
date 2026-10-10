# Scanner adapters

Decision record: [ADR-0010](../adr/0010-scanner-adapters-repository-snapshots-and-findings.md).
Execution lifecycle: [execution-lifecycle.md](execution-lifecycle.md).

## Flow of one scanner job

```text
worker.claim_job ─▶ JobLease (authoritative repository, commit, tenant)
   │
   ▼
ScannerExecutor.execute(lease, stop)
   ├─ RepositorySource.snapshot(lease)     validated, bounded, immutable RepositorySnapshot
   ├─ adapter.stdin(snapshot)               deterministic tar (repo/ + worker ruleset + path manifest)
   ├─ adapter.command(snapshot)             constant script, validated integer arguments
   ├─ DockerSandbox.run(argv, stop, stdin)  fresh hardened container, killed on cancel/lease loss
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
| `sentinel_worker/sandbox/policy.py` | Image allowlist, stdin limit, runtime arguments (`--interactive` only when allowed) |

## Adding a scanner (checklist)

1. **Review the scanner and pin its image** by index digest, cross-checked on every
   registry that publishes it, and add it to `ALLOWED_IMAGES` and CI's pre-pull list.
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
   - whether its reports can carry file names, which must go through safe paths.
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

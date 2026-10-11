# Threat model: Trivy dependency scanner integration

Scope:
- dependency manifests crossing into a Trivy sandbox;
- the vulnerability database crossing from a registry, through a trusted preparation step
  and a local image, into that sandbox;
- Trivy's report crossing back into the worker;
- normalized findings stored as evidence.

Builds on the [Gitleaks](gitleaks-scanner.md) and [Semgrep](semgrep-scanner.md) threat
models (shared snapshot channel), the [execution sandbox](execution-sandbox.md) and
ADR-0009's trust policy. Design:
[ADR-0012](../adr/0012-trivy-sca-with-an-embedded-verified-database.md). Status: M3 Phase
2, Slice 3 (local synthetic repositories only), updated after the
[Slice 3 security review](../security/m3-phase2-slice3-security-review.md).

## Assets

| Asset | Why it matters |
|---|---|
| The vulnerability database | Decides what is detected; a wrong, damaged or old database is a false clean |
| The scanner image | Its binary and configuration run on every job; it must be exactly the pinned base plus the database |
| Coverage statements | A silently skipped lockfile or unresolved dependency is a false clean |
| Dependency inventories | Package names and versions can reveal private software and internal project names |
| Worker credentials, host files | Must never reach the sandbox |

## Data flow

```text
registry (ghcr.io) ─manifest by digest, blob by digest─▶ fetch-trivy-db.py (trusted, network)
  ─▶ trivy.db + metadata.json + provenance.json
  ─▶ trivy-image build: deterministic layer + derived config ─▶ docker load ─▶ lock
worker start: lock (config) ─▶ recompute config ─▶ inspect + docker save ─▶ verify every blob,
  the DB layer, the bbolt structure ─▶ register image id
scan: snapshot ─▶ tar (dependency files + config/report.tpl) ─▶ stdin
  ─▶ [sandbox: stage, verify, check DB files against the lock, env -i trivy fs --offline-scan …]
     (UNTRUSTED)
  ─▶ stdout: sandbox-output.v1 { trivy-report.json (identifiers only) } ─▶ worker: strict parse,
     freshness, coverage classification, safe values ─▶ findings.json ─▶ worker.put_evidence
```

## Threats

| # | STRIDE | Threat | Controls | Verified by | Residual risk |
|---|---|---|---|---|---|
| T1 | Tampering, elevation | A different scanner image is used: a modified Trivy binary, an added file, a changed environment or entrypoint, an arbitrary local image named in configuration | Base pinned by index digest; vendored, digest-checked base config; lock parsed strictly; expected config recomputed; `inspect` checks platform, `Env`, `Entrypoint`, `User`, `Volumes`, exact `diff_ids`; `docker save` export: every blob digest, every layer's uncompressed digest, config bytes, DB layer entries and modes; only then a process-local registration; `SandboxPolicy` refuses unregistered `sha256:` images | `test_an_added_executable_in_the_database_layer_is_refused`, `test_modified_base_layers_are_refused`, `test_an_additional_layer_is_refused`, `test_changed_image_configuration_is_refused` (5), `test_a_configuration_blob_that_differs_from_the_derivation_is_refused`, `test_a_lock_whose_configuration_digest_does_not_derive_is_refused`, `test_export_integrity_problems_are_refused`, `test_a_genuine_image_is_verified_and_only_then_allowed`, `test_the_real_image_is_verified_by_content` (including the bare base image), `test_the_sandbox_runs_only_the_verified_image` | Whoever controls the Docker daemon controls the host anyway. No signature verification of the base image (M6) |
| T2 | Spoofing (false clean) | A wrong database: tampered, from another source, of another schema | Upstream artifact fetched by manifest digest and blob digest; extraction of exactly two regular files; `trivy_db_sha256` recorded and re-checked at build; lock digests checked against layer content at every start; schema 2 only; per-scan size and metadata digest check in the sandbox (exit 76) | `test_a_database_different_from_the_lock_is_refused`, `test_a_fetched_database_must_still_match_its_recorded_digest`, `test_invalid_or_incompatible_metadata_is_refused` (11), `test_unrecognized_provenance_is_refused`, `test_a_tampered_lock_is_refused` (8), `test_the_sandbox_refuses_a_database_that_differs_from_the_lock` (real, 2), `test_a_lock_cannot_claim_other_metadata_than_the_verified_file` (S3-2), `test_an_artifact_the_mirror_does_not_serve_is_refused_unless_explicitly_skipped` | **R2.** Integrity is not authenticity. No upstream signature exists. Mirror corroboration and audited, second-person-reviewed refreshes raise the bar, but someone who can write the lock *and* load an image (or who controls both registries) could supply a self-made, structurally valid database with the required buckets |
| T3 | Spoofing (false clean) | A damaged database opens and returns nothing | bbolt structural check (both meta pages, checksums, high-water mark versus size) at build and verification; Trivy fails on damaged data pages | `test_a_damaged_database_structure_is_refused` (7), `test_a_truncated_database_is_refused_even_when_the_lock_matches`, `test_a_truncated_database_is_refused_when_building`, `test_a_truncated_database_is_refused_before_any_scan` (real), `test_a_corrupted_database_fails_the_scan_never_clean` (real) | **Defect S3-1, fixed.** Partial damage to data pages that Trivy still reads without error cannot be detected by structure; digests cover it for upstream databases (T2). **S3-3, fixed:** a structurally valid database without an ecosystem's advisories is refused (`test_a_database_without_advisories_for_a_reviewed_ecosystem_is_refused`, 3), but deleted individual records inside a present bucket are not detectable |
| T4 | Spoofing (false clean) | Old advisory data reported as current | Freshness from `UpdatedAt`: STALE after 48 h (coverage incomplete), refused after 7 days or when more than 1 h in the future, at worker start and per result; `ADVISORY_DATA_POINT_IN_TIME` always | `test_database_freshness_is_explicit` (5), `test_an_expired_or_future_database_fails_the_scan` (3), `test_a_stale_database_is_used_but_disclosed` (real), `test_an_expired_database_fails_closed` (real) | Advisories published after `updated_at` are not covered by design. `UpdatedAt` is the publisher's claim |
| T5 | Spoofing (false clean) | A lockfile is silently skipped (malformed, empty, wrong shape) | Every supported manifest must have a Trivy result, else not analyzed and `complete = false` | `test_a_manifest_without_a_result_is_not_analyzed_never_clean`, `test_invalid_lockfiles_are_not_analyzed_never_clean` (real, 4) | A legitimately empty lockfile is also reported as not analyzed (conservative) |
| T6 | Spoofing (false clean) | Partial resolution looks complete: `pom.xml` without parents or BOMs, unpinned `requirements.txt`, missing lockfiles, other ecosystems, JARs | Partial formats, unresolved versions, declarations without lockfiles, unsupported formats and binary artifacts are counted and make coverage incomplete | `test_partial_formats_and_unresolved_versions_make_coverage_incomplete`, `test_declarations_without_a_lockfile_are_flagged` (6), `test_unsupported_formats_and_binary_artifacts_are_counted_not_ignored`, real equivalents | **S3-4, S3-7, S3-8 (final audit):** incomparable versions are now counted as unresolved; `Pipfile.lock` `develop` entries and ambiguous PyPI names (Trivy does not normalize `.`) are disclosed and make coverage incomplete (`test_dependency_coverage_matrix`, 16 real cases). Trivy's own matching gaps are disclosed, not fixed |
| T7 | Tampering | Repository-controlled suppression or configuration: `trivy.yaml`, `.trivyignore`, `.trivyignore.yaml`, VEX, `TRIVY_*` variables | Only dependency files reach the sandbox; `--config ""`; `--ignorefile /dev/null`; no `--vex`; `env -i`; a smuggled file fails the archive count check | `test_only_dependency_files_and_the_template_reach_the_sandbox`, `test_repository_controlled_trivy_configuration_is_ignored` (real, 5 mechanisms), `smuggled-trivyignore` archive case | Future Trivy versions may add discovery mechanisms (upgrade review) |
| T8 | Information disclosure, SSRF | Trivy contacts the network: database or Java DB download, Maven repositories named by a POM, telemetry, version check | No network in the sandbox; skip-update flags; `--offline-scan`; `--disable-telemetry`; tmpfs `HOME` (no `settings.xml`) | `test_every_isolation_control_holds_under_the_trivy_policy` (`no_network`), `test_xml_external_entities_and_remote_repositories_are_not_followed` (real; metadata-service URL, no wait), `sandbox-check --profile trivy` (13/13) | — |
| T9 | Information disclosure | Lockfile content in evidence: private package names, inventories, token-like versions, paths; advisory prose | Only vulnerable packages are named (they appear in a public advisory); inventory as counts; values validated and token-like runs redacted (`PACKAGE_VALUES_REDACTED`); safe paths; template emits identifiers only; raw report not stored | `test_token_like_package_values_are_redacted_and_disclosed`, `test_package_values_with_control_characters_or_unbounded_length_fail` (4), `test_secret_shaped_manifest_paths_are_redacted`, `test_secret_shaped_paths_and_versions_never_reach_evidence` (real), `test_advisory_prose_and_raw_reports_never_reach_evidence`, integration and E2E prose checks, `test_short_credentials_in_versions_are_redacted` (S3-5) | A vulnerable *private* fork published under a public package name is named in evidence. Path redaction is heuristic (Semgrep S10) |
| T10 | Tampering | A malformed or injected report: forged targets, packages or advisories; format injection through package names | Constant template with `toJson`; exact version; closed keys and arities; targets must be snapshot manifests of the matching type; vulnerabilities must refer to listed packages; validated identifiers; bounds | `test_malformed_or_unexpected_reports_fail_closed` (21), `test_hostile_package_names_cannot_break_the_report_format` (real), `test_report_bounds_are_enforced_not_truncated` | A compromised sandbox can omit or invent findings for its own job (integrity, not authenticity) |
| T11 | Elevation of privilege | Hostile lockfiles exploit a Trivy parser (Go: JSON, YAML, TOML, XML) or the XML parser resolves entities | Sandbox controls unchanged; trusted-tool workload; Go's XML decoder does not resolve external entities | `test_xml_external_entities_and_remote_repositories_are_not_followed`, `sandbox-check --profile trivy` | runc shares the host kernel. **Not acceptable for hostile production repositories** (ADR-0009) |
| T12 | Denial of service | Huge lockfiles or reports exhaust memory, time or output | Measured limits (512 MiB, 64 PIDs, 128 MiB tmpfs, 2 MiB stdout, 1 MiB report); snapshot bounds; timeout; cancellation | `test_oversized_output_and_memory_exhaustion_fail_explicitly`, `test_cancellation_kills_a_running_scan_and_leaves_nothing_behind`, measurements (ADR-0012 §9) | Repositories with more than about 12,000 packages fail with `RESOURCE_LIMIT_EXCEEDED` |
| T13 | Spoofing | Stale, crashed or cancelled attempts, or another tenant's job, get findings accepted | Lease fencing and evidence binding (ADR-0007/0008); one sandbox per job | `test_lost_leases_and_cancelled_scans_never_get_findings_accepted`, `test_two_tenants_get_separate_evidence`, `test_concurrent_scans_of_different_tenants_stay_separate` | — |
| T15 | Information disclosure | The preparation script leaks the registry token through redirects or follows a downgrade | HTTPS-only redirects, at most three, token dropped across hosts (S3-6) | `test_the_registry_token_never_follows_a_redirect_to_another_host`, `test_redirects_other_than_https_are_refused` (3) | The token is anonymous and read-only |
| T16 | Repudiation | A database change cannot be traced to a person and a reason | Manual refresh writes an append-only audit record; locks are never overwritten | `test_a_refresh_is_audited_and_never_touches_the_previous_lock`, real refresh on 2026-10-11 | The audit log is a local file; tamper-evidence of the log itself is future work |
| T14 | Tampering (supply chain) | The fixture builder or its dependencies are replaced | Builder module pinned to an exact pseudo-version; Go checksum database; Go image pinned by digest; builder runs without network; output marked `SYNTHETIC_FIXTURE` in evidence | `test_a_synthetic_database_is_always_disclosed`; CI build step | Test-only; a synthetic database is never acceptable for production scans |

## Detection is not proof

- **What a finding means.** A declared dependency version lies in the affected range of a
  published advisory in the recorded database. It does **not** establish that the
  vulnerable code is used, reachable or exploitable (`REACHABILITY_NOT_ANALYZED`).
- **What a clean scan means.** None of the packages Trivy could identify and compare
  matched an advisory, in data as of `updated_at`, for the analyzed manifests. Check
  `coverage.complete`, `coverage.dependencies` and the limitations before relying on it.
- **Decisions.** Gate decisions, severity policy and exceptions belong to M4. Until then
  every scan is `INCOMPLETE`.

## Required before scanning real repositories

The requirements of the [Gitleaks threat model](gitleaks-scanner.md#required-before-remote-repository-scanning)
apply:
- verified commit snapshots;
- a stronger isolation boundary;
- staged large snapshots;
- escaping in report rendering.

Additionally:
1. An approved, monitored database refresh process: an automatic updater or a scheduled
   pipeline with review, provenance recording and alerting on staleness.
2. Signed or otherwise authenticated database provenance that the worker can verify
   offline (R2), and base image signature verification (M6).
3. A decision on Java archive scanning (the Java DB, 936 MiB) and on arm64 workers.
4. Larger-repository support beyond the 1 MiB report limit (for example several report
   artifacts, or staging through the evidence store).

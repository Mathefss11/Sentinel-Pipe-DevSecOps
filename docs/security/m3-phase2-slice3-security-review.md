# M3 Phase 2, Slice 3: security review (Trivy SCA integration)

- **Scope:**
  - the Trivy adapter (`scanners/trivy.py`);
  - the image with an embedded vulnerability database (`scanners/trivy_image.py`,
    `trivy-base-config.json`);
  - the verified-image registry in `sandbox/policy.py`;
  - the preparation scripts (`scripts/trivy/`);
  - the `findings.v1` extension, worker settings and CLI;
  - the Java scanner gating;
  - CI.
- **Method:**
  - feasibility measurements against the pinned image and the real upstream database
    (Checkpoint A);
  - implementation against the approved design (Option A, Checkpoint B);
  - adversarial testing against the real image with synthetic databases and fixtures
    (Checkpoint C);
  - full verification (Checkpoint D).

  Every behavior below was observed with Trivy 0.75.0 unless marked otherwise.
- **Design:** [ADR-0012](../adr/0012-trivy-sca-with-an-embedded-verified-database.md),
  [threat model](../threat-model/trivy-scanner.md), [runbook](../runbooks/trivy.md).

## Confirmed defects

| # | Severity | Defect | Fix | Regression tests |
|---|---|---|---|---|
| S3-1 | High (false clean) | A **truncated** vulnerability database whose lock matched the truncated file passed image verification. Trivy opened it and **completed with no findings**: a dependency known to be vulnerable was reported clean. (The upstream fetch path was already protected by the recorded `trivy_db_sha256`; synthetic, locally built or damaged-at-rest databases were not.) | bbolt structural check (`check_bolt_structure`): both meta pages must carry magic, version 2, a valid FNV-64a checksum, the same page size, a root and freelist below the high-water mark, and the file must cover every page up to that mark. It runs at build and at every verification (`DATABASE_STRUCTURE_INVALID`) | `test_a_damaged_database_structure_is_refused` (7), `test_a_truncated_database_is_refused_even_when_the_lock_matches`, `test_a_truncated_database_is_refused_when_building`, `test_a_truncated_database_is_refused_before_any_scan` (real) |

Design issues found and corrected before they shipped (not counted as defects):

- **A Dockerfile build (`COPY --chmod=0444`) made the database unreadable** for the
  sandbox user, because it also applied the file mode to the created directories. This
  motivated the deterministic layer the worker builds itself.
- **A 4 MiB report bound could never be reached.** `sandbox-output.v1` limits each
  artifact to 1 MiB. The report was made compact (positional arrays) instead of raising a
  shared contract limit, and is bounded at 1 MiB, measured at about 12,000 packages.
- **Image identity.** The planned allowlist entry assumed one image ID. Measured: the ID
  is the manifest digest under the containerd store and the configuration digest under
  the classic store. The configuration digest became the store-independent anchor.

## Reviewed without defects

- **Base image ancestry.** It is established by content, not labels, through four checks:
  - the vendored configuration blob is pinned;
  - every exported layer must decompress to its `diff_id`;
  - the configuration bytes are recomputed;
  - the database layer's entries, modes and digests are checked.

  Fake-export tests cover each forgery: a trojan binary in the database layer, a modified
  base layer, an extra layer, changed environment, entrypoint, user, volumes or
  architecture, a forged configuration blob, a lock whose digest does not derive, a
  mislabelled blob, a failed export. A real test covers the bare base image named as the
  scanner image.
- **Configuration alone cannot select an arbitrary image.** `SandboxPolicy` accepts a
  `sha256:` image only after `register_verified_image`, which only the verifier calls;
  the registry is process-local.
- **Repository-controlled configuration has no effect.** The real-container test covers
  `trivy.yaml`, `.trivyignore`, `.trivyignore.yaml` and VEX documents. Only dependency
  files reach the sandbox, and a smuggled file fails the archive count check.
- **No network use.** There is no database or Java DB download, and a POM's repositories
  (including a metadata-service URL) are not contacted and cause no wait.
  `--offline-scan`, skip flags, `--disable-telemetry`, `env -i`; `sandbox-check --profile
  trivy` is healthy (13 of 13 controls).
- **XML external entities** in `pom.xml` are not resolved.
- **Report-format injection** through package names is neutralized by the template's
  `toJson` escaping and strict parsing.
- **Database states:**
  - stale data is used and disclosed;
  - expired or future data fails the scan and refuses worker start;
  - schema 1 and 3 are refused at build and verification (and by Trivy itself);
  - data pages corrupted behind valid meta pages make Trivy fail (`SCANNER_ERROR`), never
    clean;
  - files that differ from the lock inside the sandbox exit 76.
- **Silent skips.** Malformed, empty, binary and wrong-shape lockfiles have no Trivy
  result and are counted as not analyzed.
- **Partial resolution is disclosed:** `pom.xml` parents and BOMs, `requirements.txt`
  unpinned lines, missing lockfiles, other ecosystems, Java archives.
- **Privacy:**
  - only vulnerable packages are named;
  - token-like versions are redacted and disclosed;
  - secret-shaped paths are redacted;
  - advisory prose never reaches evidence (unit, real-container and database checks).
- **Isolation, cleanup and tenancy:** cancellation leaves no container or writer thread
  behind; concurrent scans of two tenants stay separate; lost and cancelled leases get
  no result accepted (PostgreSQL integration).
- **Independence:** Gitleaks- and Semgrep-only workers never import the Trivy modules
  (subprocess test); their `findings.v1` documents are unchanged (existing suites pass).

## Accepted residual risks (owner decision required)

- **R1, isolation.** runc shares the host kernel; a Trivy parser exploit (Go: JSON, YAML,
  TOML, XML) runs inside the sandbox. Synthetic fixtures only (ADR-0009).
- **R2, database authenticity.** Integrity is established, publisher authenticity is not.
  - Digests prove the bytes are the ones named.
  - Mirror corroboration shows two independently operated registries serve the same blob.
  - Audited, reviewed refreshes record who prepared what.
  - No upstream signature exists (checked 2026-10-11).
  - A party able to write the lock **and** load images, or one controlling the upstream
    publication or both registries, could still supply a self-made database that passes
    every content check (structure, buckets, freshness).
- **R3, coverage limits.** The following are inherent and disclosed:
  - partial `pom.xml` and `requirements.txt` resolution, including Maven test and
    optional scopes;
  - npm prereleases compared with node-semver rules;
  - Trivy's PyPI name matching (`.` not normalized, `PYPI_NAME_MATCHING_UNVERIFIED`);
  - `Pipfile.lock` `develop` entries;
  - legitimately empty lockfiles reported as not analyzed;
  - no Java archive or other-ecosystem analysis;
  - repositories beyond about 12,000 packages failing with `RESOURCE_LIMIT_EXCEEDED`;
  - records deleted inside a present advisory bucket are not detectable.
- **R4, advisory data is a snapshot.** It is up to 7 days old; the refresh is manual (no
  automatic updater, not approved).
- **R5, unsigned images.** No signature verification of the base image or database (M6).
- **R6, platform.** linux/amd64 only.
- **R7, audit log.** `refresh-audit.jsonl` is a local append-only file, not tamper-evident.
- **Integrity, not authenticity:** a compromised sandbox can misreport its own job.

## Final adversarial audit (2026-10-11)

A second, adversarial pass before the manual commit. It challenged the database trust
boundary, corruption handling, freshness, every dependency format, sensitive output,
sandbox limits and the end-to-end path, all against the real pinned image, synthetic
databases and, where noted, the real upstream database.

### Confirmed defects

| # | Severity | Root cause | Realistic impact | Fix | Regression tests |
|---|---|---|---|---|---|
| S3-2 | High | Every lock field was bound to verified content except `database.metadata`, from which freshness is computed | Editing only the lock (configuration) made an expired database look `FRESH` and bypassed the 7-day fail-closed rule (verified against the real fixture image) | The lock's metadata must equal the parsed `metadata.json` in the verified layer (`METADATA_MISMATCH`) | `test_a_lock_cannot_claim_other_metadata_than_the_verified_file`; E2E `aWorkerWithAForgedTrivyLockRefusesToStartAndRunsNoJob` |
| S3-3 | Medium | Verification proved structure and digests, not that the database has advisories for the reviewed ecosystems | A structurally valid database without npm and PyPI data made Trivy report vulnerable npm and PyPI packages clean, exit 0 (verified with a synthetic Maven-only database built by the pinned builder) | Presence check of the Maven, npm and PyPI GHSA buckets at build and verification (`DATABASE_COVERAGE_MISSING`) | `test_a_database_without_advisories_for_a_reviewed_ecosystem_is_refused` (3), `test_bucket_names_split_across_read_chunks_are_found` |
| S3-4 | Medium | Only empty versions counted as unresolved | git, file and tarball references and garbage versions cannot match any advisory but left coverage complete | SemVer (npm) and PEP 440 (PyPI) grammar checks and unresolved Maven properties count as unresolved | `test_versions_that_cannot_be_compared_are_counted_as_unresolved` (5), `test_ecosystem_versions_are_comparable` (4), coverage matrix `npm-git-dependency` |
| S3-5 | Low | Version redaction only covered token runs of 32+ characters | A 20-character AWS-style key id in a Maven qualifier inside the affected range reached evidence | The path heuristic (credential prefixes, entropy) applied to installed versions | `test_short_credentials_in_versions_are_redacted` |
| S3-6 | Low | urllib's default redirect handler keeps all headers on redirects, including to other hosts and plain HTTP | The (anonymous, read-only) registry token was sent to the blob store, and would be sent over HTTP on a downgrade redirect. Content integrity was unaffected (digests) | Redirects HTTPS-only, at most three, token dropped across hosts | `test_the_registry_token_never_follows_a_redirect_to_another_host`, `test_redirects_other_than_https_are_refused` (3), `test_redirect_chains_are_bounded` |
| S3-7 | Medium | Trivy 0.75.0 ignores `Pipfile.lock` `develop` even with `--include-dev-deps` (verified) | A vulnerable development dependency was missed while coverage was complete | The worker counts `develop` entries with its strict JSON loader: `DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED`, coverage incomplete | `test_pipfile_development_dependencies_are_disclosed_as_not_analyzed`, coverage matrix `pipenv-develop` |
| S3-8 | High (coverage) | Trivy 0.75.0 normalizes case and `_` but not `.` in PyPI names | Real database: a uv lockfile naming `products-cmfplone` (PEP 503 form) matched none of the 6 advisories that `Products.CMFPlone` matched; the same for `plone-app-contenttypes` (0 versus 3). Coverage claimed complete | Disclosure: any PyPI name with `-` or `.` sets `PYPI_NAME_MATCHING_UNVERIFIED` and makes coverage incomplete. A real fix (worker-generated name-variant probes) changes scanner semantics and **needs approval** | `test_pypi_names_trivy_may_not_match_are_disclosed` (4), coverage matrix `pypi-dotted-name` |

**Hardening without a reachable defect.** The worker's report template (`config/report.tpl`)
was not covered by the shared `repo/` input digest. Its SHA-256 is now checked in the
sandbox (exit 72; `test_an_altered_report_template_never_runs`). The Semgrep ruleset has
the same property; it is out of this slice's scope and recorded for review.

**Test reliability (not a security defect).** The existing FIXTURE PID test failed once
under full-suite load.
- Cause: `PIDS_EXHAUSTED` is a label derived from sampling `docker stats`. A fork bomb
  slowed by host load sat at 31 of 32 processes between samples until the 6 s timeout
  and was labelled `TIMED_OUT`.
- Invariant: it held. The run was killed and never succeeded.
- Fix: the test now accepts either label and keeps its containment assertions. A new
  deterministic test reads the kernel's own counter (`pids.events` `max` ≥ 1, `current`
  ≤ `max`): `test_the_kernel_refuses_forks_beyond_the_pid_limit`.

### Assessed without new defects

- **Forged images.** Content verification was already sound: trojan files, modified or
  extra layers, configuration changes and forged configuration blobs are all refused (T1).
  Local image cache poisoning cannot substitute content, because images are run by
  content-addressed ID after verification.
- **Base image.** Verified independently of the lock: vendored configuration pinned by
  digest, and every base layer's uncompressed digest checked from the export.
- **Fetch script.** It accepts only a single-layer OCI manifest of the Trivy DB media
  type, within size bounds. The blob must match its digest. Extraction admits exactly two
  regular files: no links, traversal, extra entries or other schema versions (tests).
- **Freshness.** Timestamps are parsed as UTC with nanosecond truncation. Boundaries
  (48 h, 7 days, 1 h future skew) are tested. The worker clock is trusted, and its skew is
  bounded only by the future-date check.
- **Sensitive output.**
  - Logs, CLI output and exceptions carry sanitized codes only; no exception chains.
  - The raw report is never stored.
  - Fingerprints contain package, version and safe path, which the finding states anyway.
  - `raw_report_sha256` covers the package inventory and could confirm a guessed
    inventory (documented, same as `content_sha256`).
- **Sandbox and resources:**
  - memory and output limits fail explicitly;
  - a timeout is `EXECUTION_TIMEOUT`;
  - a truncated or altered input stream never runs;
  - cancellation, including during start-up verification, kills the container or export
    and leaves nothing behind;
  - concurrent tenants stay separate.
- **Dependency coverage matrix.** All passed against real Trivy: scoped packages, npm
  aliases, optional, transitive and duplicate entries, lockfile v1, Yarn Berry, pnpm v6,
  Poetry, uv and Gradle development groups, a local Maven parent property, a remote BOM,
  version ranges, test scope and unicode paths. Wherever a match is missed, coverage is
  incomplete.

## Verification results

Exact commands and counts are in the final audit report. Remote CI has not run Slice 3.
Linux-only tests: the symlinked-database test and the existing POSIX-only snapshot tests.

## ADR recommendations

- **ADR-0010: Accept with conditions:**
  - remote CI green;
  - runc limited to synthetic fixtures (ADR-0009);
  - the derived Gitleaks ruleset accepted.
- **ADR-0011: Accept with conditions:**
  - remote CI green;
  - `PARSE_COMPLETENESS_UNVERIFIED` and heuristic name redaction accepted;
  - a review of the ruleset-in-archive integrity note above.
- **ADR-0012: Accept with conditions:**
  - remote CI green, including the Trivy sandbox and E2E steps;
  - R2 accepted, with image preparation limited to trusted operators, the documented
    two-person refresh review and mirror corroboration;
  - the manual refresh procedure adopted;
  - R3 accepted as disclosed coverage limits;
  - a decision on the S3-8 variant-probing fix;
  - Trivy stays refused in production until stronger isolation and verified commit
    snapshots exist.

No ADR status was changed by this review.

## Verdict

**Ready for the owner's manual commit and remote CI**, conditional on remote CI:
- S3-1 to S3-6 are fixed;
- S3-7 and S3-8 are disclosed as incomplete coverage (Trivy behavior);
- every confirmed defect has regression tests;
- Trivy stays disabled in production.

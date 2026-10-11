# ADR-0012: Trivy dependency scanning with an embedded, verified vulnerability database

- **Status:** Accepted with conditions (2026-10-11; see [Acceptance](#acceptance)).
  Previously Proposed.
- **Date:** 2026-10-11
- **Milestone:** M3 Phase 2 (Slice 3: Trivy SCA)
- **Builds on:** [ADR-0010](0010-scanner-adapters-repository-snapshots-and-findings.md)
  (scanner adapters, snapshots, `findings.v1`) and
  [ADR-0011](0011-semgrep-sast-with-a-bundled-ruleset.md), both accepted with conditions on
  2026-10-11.
- **Amends:** ADR-0009 (one kind of local, content-verified sandbox image) and ADR-0010
  (`findings.v1` gains dependency findings, compatibly)
- **Threat model:** [Trivy scanner](../threat-model/trivy-scanner.md)
- **Security review:** [Slice 3 review](../security/m3-phase2-slice3-security-review.md)
  (defects S3-1 to S3-8 fixed or disclosed, including the final adversarial audit; this ADR
  reflects the resulting design)
- **Runbook:** [Trivy](../runbooks/trivy.md)

## Context

Trivy is the third scanner and the first that needs **external intelligence**: a
vulnerability database. Compared with Gitleaks and Semgrep it adds these concerns:

- **The database.** Trivy downloads it from a registry by default. It is large:
  121 MiB compressed and 1.37 GiB uncompressed (measured on 2026-10-11). The Java
  database needed only for JAR files is 936 MiB compressed.
- **The sandbox has no network.** The stdin channel (ADR-0010) is bounded at 32 MiB per
  adapter (64 MiB hard cap) and the tmpfs at 1 GiB, which counts against the memory
  limit. Neither can carry the database. Raising those limits was ruled out.
- **Network in the scanner itself.** For `pom.xml`, Trivy fetches parent POMs and
  dependency metadata from Maven repositories, including repositories the POM names.
- **Repository-controlled configuration.** `trivy.yaml`, `.trivyignore`,
  `.trivyignore.yaml`, VEX documents and `TRIVY_*` variables can narrow what is reported.
  Secret scanning is on by default.
- **Partial resolution.** A lockfile parse that succeeds says nothing about how much of the
  dependency graph was seen.

The trust model is unchanged (ADR-0009). Trivy is a reviewed tool parsing hostile lockfiles
under runc. That is acceptable only for synthetic local fixtures until stronger isolation
and verified commit snapshots exist.

## Decision

### 1. Scope

Dependency vulnerabilities only (`--scanners vuln --pkg-types library`).

**Out of scope:**
- container images, host OS packages, Kubernetes;
- IaC misconfiguration and secrets (Gitleaks covers secrets);
- licenses;
- Java archives;
- remote repositories;
- production use;
- M4 policy.

### 2. Image and version

| | |
|---|---|
| Version | Trivy **0.75.0** (2026-10-01). Binary reports `Version: 0.75.0`; image label revision `591e9799…` |
| Base image | `ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa` (OCI index; amd64, arm64, s390x, ppc64le). **linux/amd64 is the verified platform**: manifest `sha256:9db09910…`, config `sha256:6d93f1ec…` |
| Contents | Alpine 3.24 (BusyBox 1.37), `ca-certificates`, `git` (unused by `trivy fs`), `/usr/local/bin/trivy`, report templates. `ENV` is `PATH` only; `ENTRYPOINT ["trivy"]`; no `USER` (the sandbox forces 65534) |
| License | Trivy and trivy-db are Apache-2.0. The database aggregates advisory sources under their own terms; this repository does **not** redistribute it (no database is committed, and images carrying it are built locally) |

The base image is **never run directly** (`TRIVY_BASE_IMAGE` is not in `ALLOWED_IMAGES`).

### 3. Database transport: one read-only image layer (approved Option A)

The database is delivered as one layer on top of the pinned base. The sandbox keeps every
control:
- no network, no mounts, no Docker socket;
- read-only root, no capabilities;
- `--pull never`.

```text
trusted preparation (network, operator/CI)              worker (no network for scans)
---------------------------------------------           ------------------------------------
fetch-trivy-db.py fetch --manifest-digest D   ──┐       parse lock (configuration)
  manifest by digest, blob by digest, verify    │       recompute config from pinned base
  extract trivy.db + metadata.json only         │       inspect image, docker save, verify
  provenance.json                               │         every blob and the DB layer
sentinel-worker trivy-image build ──────────────┼─────▶ register image id (process-local)
  deterministic DB layer + derived config       │       per scan: DB file size + metadata
  OCI layout → docker load → verify → lock    ──┘         digest checked in the sandbox
```

**Construction** (`scanners/trivy_image.py`, `build_image`):

- **Database layer.** A deterministic tar built by the worker code, not by
  `docker build`:
  - directories `opt/sentinelpipe/trivy/db/` (0555; `opt/` 0755);
  - `metadata.json` and `trivy.db` (0444);
  - owner 0:0, mtime 0, USTAR.
  - A Dockerfile `COPY --chmod` was tried and rejected: it also applied the file mode to
    the created directories, which made the database unreadable for the sandbox user.
- **Configuration.** The vendored, pinned base configuration
  (`trivy-base-config.json`, SHA-256-checked on import), with:
  - the layer's digest appended to `rootfs.diff_ids`;
  - one history entry;
  - informational labels: source kind and database digests.

  The configuration digest is a pure function of the pinned base and the database layer.
- **Base layers.** Taken from `docker save` of the base image (pulled by digest). The
  exported configuration must be byte-identical to the pinned one, and every layer's
  uncompressed digest must equal its pinned `diff_id`.
- **Loading.** The OCI layout is streamed into `docker load`. No build step and no download.

**Provenance verification** (`verify_image`, at worker start; 24 s for the real database):

- **What is not trusted.** An image ID or labels alone are not trusted. The OCI image
  format has no verifiable "based on" relationship; the `org.opencontainers.image.base.*`
  annotations are informational. Ancestry is established by content.
- **The lock.** It is configuration and only *names* an image. It is parsed strictly, and
  the expected configuration is recomputed from the pinned base and the lock's layer
  digest; the lock's configuration digest must match.
- **`docker image inspect`.** It must show:
  - linux/amd64;
  - the base `Env` and `Entrypoint`;
  - no `User` and no `Volumes`;
  - `RootFS.Layers` exactly equal to the pinned base `diff_ids` plus the one database layer.
- **`docker save`** is parsed as a stream. Every blob's digest must match its name.
- **The configuration blob** must be byte-identical to the recomputed configuration.
- **Every layer** must decompress to its `diff_id`. This is the content-addressed proof
  that the base layers are the pinned ones, independent of names, labels or the image
  store.
- **The database layer** must contain exactly the expected entries, with the expected
  types, modes and owner. `trivy.db` and `metadata.json` must have the locked SHA-256 and
  size, and `trivy.db` must pass a **structural check** and an **advisory coverage
  presence check** (decision 5);
- **The lock's `metadata` block** (which decides freshness) must equal the parsed,
  verified `metadata.json` (`METADATA_MISMATCH`; defect S3-2: a lock edited to a recent
  date was accepted before).
- **Only then** is the image ID registered as a verified local sandbox image, for that
  process (`register_verified_image`). `SandboxPolicy` refuses any other `sha256:` image.
- **Result.** An arbitrary local image cannot be accepted through configuration. Changing
  the base layers, the environment, entrypoint or user, or adding a file anywhere changes
  a digest that is checked against content.

**Fetch hygiene (defect S3-6).** urllib's default redirect handling forwarded the
registry token to other hosts and accepted plain-HTTP redirects. Redirects are now
HTTPS-only, at most three, and drop the token across hosts.

**Image identity.** The image ID differs by image store: the manifest digest under the
containerd store, the configuration digest under the classic store. The configuration
digest is therefore the store-independent anchor. The lock records both, and so does the
evidence.

**Per scan.** The sandbox script checks, before Trivy starts:
- the database directory holds exactly the two files;
- `trivy.db` has the locked size;
- `metadata.json` has the locked SHA-256 (exit 76, `VULNERABILITY_DB_INVALID`);
- the worker's report template has its pinned SHA-256 (exit 72): unlike `repo/`, worker
  configuration in the archive was not covered by the shared input verification.

Hashing the full database in every sandbox would cost about 5 s of CPU per scan. The image
is immutable and addressed by ID, so the full hash runs once, at worker start.

**What configuration still selects.** The lock selects *which* database content is used.
For `UPSTREAM_OCI`, that content was verified at fetch time against the registry's content
addresses: manifest digest, then blob digest, then `trivy_db_sha256` recorded in
`provenance.json` and re-checked by `build_image`. The worker cannot re-establish the
upstream link offline (residual risk R2).

**Authenticity versus integrity (final audit).** SHA-256 digests establish *integrity*:
the bytes are the ones a digest names. They do not establish *publisher authenticity*. As
verified on 2026-10-11:
- neither the Trivy image nor the trivy-db artifact carries a Sigstore signature or OCI
  referrer on ghcr.io;
- the image index holds only unsigned BuildKit provenance attestations.

What exists instead, and is now used:
- **Cross-registry corroboration.** Aqua Security publishes the same database through
  `mirror.gcr.io/aquasec/trivy-db`, operated on different infrastructure. Its manifest
  differs (a timestamp annotation), but the blob digest was identical. `fetch` requires
  the mirror to serve the same blob (`--skip-corroboration` only explicitly, recorded in
  the audit log).
- **Reviewed, audited operator action.** The refresh procedure (decision 4) records who
  prepared which digests, and why.
- **Content checks that bound what a forged database can do:**
  - schema version;
  - bbolt structure;
  - presence of each reviewed ecosystem's advisory bucket;
  - freshness bound to verified metadata.

A database that passes all of these can still be incomplete or malicious if the operator
or both registries are compromised. Offline publisher authentication requires signed
artifacts from upstream, or a SentinelPipe signing step whose key and process need
approval (not implemented).

### 4. Database lifecycle and provenance

- **Upstream fetch.** `scripts/trivy/fetch-trivy-db.py` (standard library only,
  anonymous, read-only):
  - `resolve` prints the digest the mutable tag `ghcr.io/aquasecurity/trivy-db:2` points at
    now, for review;
  - `fetch --manifest-digest` retrieves exactly that artifact and verifies everything as
    listed in the script.
  - Verified on 2026-10-11: manifest `sha256:9eab04fa…`, blob `sha256:101925ee…`
    (126,973,044 bytes), `trivy.db` `sha256:80395a34…` (1,469,976,576 bytes), `UpdatedAt`
    2026-10-11T13:06:05Z.
- **No automatic updater.** None is part of this slice (not approved). Refreshing the
  database is a manual, audited operator action with
  `scripts/trivy/refresh-trivy-db.py` (runbook §2). It:
  - fetches the reviewed digest with corroboration;
  - builds and verifies a new image;
  - never overwrites an existing database or lock, and never changes a running worker;
  - appends a JSON audit record (operator, reason, digests, `UpdatedAt`, lock SHA-256,
    image id, previous lock SHA-256).

  Workers switch to the new lock only when an operator restarts them; each verifies the
  image again at start. Validated on 2026-10-11 against the real registry: the refreshed
  lock was byte-identical (SHA-256 `1b6f76c8…`) to an earlier, independent build of the
  same database, which shows the construction is reproducible.
- **Java DB.** Not needed and never downloaded. Trivy analyzes JAR/WAR/EAR files only in
  image and rootfs mode, not in filesystem mode (verified). Archives in a repository are
  counted as `binary_artifacts`.
- **Schema.** `metadata.json` must declare version 2, Trivy 0.75.0's trivy-db
  `SchemaVersion`. Versions 1 and 3 are refused at build and at verification (Trivy itself
  also refuses them, verified).
- **CI fixtures.** A **synthetic** database is built by `scripts/trivy/build-fixture-db.sh`:
  - it runs the upstream trivy-db builder (Apache-2.0) at the commit Trivy 0.75.0 pins
    (`v0.0.0-20261001090913-650c4091f951`);
  - the builder is compiled in `golang:1.26.9-alpine3.23@sha256:67503085…`, with modules
    verified against the Go checksum database, and then run without network;
  - its input is synthetic GHSA (OSV) advisories committed under
    `tests/fixtures/trivy-db/` for fictitious `sentinelpipe-fixture-*` packages (Maven,
    npm, PyPI; one advisory with a synthetic CVE alias, one without a fix);
  - its provenance records the builder and a digest of the advisory files;
  - no real database is downloaded in routine CI or committed;
  - the Go tooling never enters the worker package.

### 5. Freshness and false-clean prevention

**Freshness.** The worker clock is compared with `metadata.json`'s `UpdatedAt`, checked at
worker start and again for each result:

| Database state | Result |
|---|---|
| Age ≤ 48 h | `FRESH` |
| 48 h < age ≤ 7 days | `STALE`: scan completes, `VULNERABILITY_DB_STALE`, coverage incomplete |
| Age > 7 days, or more than 1 h in the future | Scan fails (`VULNERABILITY_DB_EXPIRED` / `…_FROM_FUTURE`, `SCANNER_ERROR`); a worker refuses to start with such a database |
| Missing file, invalid metadata, unsupported schema | Refused at build and at verification |
| Digest or size differs from the lock | Refused at verification, or in the sandbox (exit 76) |
| Truncated database (structurally damaged) | Refused at build and at verification (`DATABASE_STRUCTURE_INVALID`) |
| Structurally valid database without advisories for a reviewed ecosystem (Maven, npm or PyPI GHSA bucket missing) | Refused at build and at verification (`DATABASE_COVERAGE_MISSING`; defect S3-3) |
| Lock claims other metadata than the verified `metadata.json` | Refused at verification (`METADATA_MISMATCH`; defect S3-2) |
| Damaged data pages behind valid meta pages | Trivy fails (verified); the scan fails |

**What the database checks prove (final audit).** They prove the file is:
- the one the lock names;
- a structurally sound bbolt file of schema 2;
- dated where its own metadata says;
- holding advisory buckets for Maven, npm and PyPI.

They do **not** prove the advisory content is complete or correct. A database with valid
structure and buckets but deleted records would still report fewer findings. That is
bounded only by the fetch-time digest chain and corroboration (R2).

**Coverage check (defect S3-3).** A structurally valid synthetic database without npm
and PyPI advisories made Trivy report vulnerable npm and PyPI packages as clean (exit 0),
and it passed every earlier check.

**Structural check (defect S3-1).** The pinned Trivy opened a truncated synthetic
database and **completed with no findings**, a false clean. The worker now checks both
bbolt meta pages:
- magic, version 2, FNV-64a checksum and page size;
- root and freelist below the high-water mark;
- a file size covering every page up to the high-water mark.

The check runs when building and when verifying.

No database problem is ever represented as zero vulnerabilities. Every document also
carries `ADVISORY_DATA_POINT_IN_TIME`: advisories published after `updated_at` are not
covered.

### 6. Supported formats, trust boundary and coverage

**No execution.** Trivy parses lockfiles and manifests as data. No Maven, npm or pip, no
lifecycle scripts, no build hooks. Verified offline behavior of 0.75.0 with
`--offline-scan`:

| Format | Ecosystem | Resolution |
|---|---|---|
| `package-lock.json`, `yarn.lock` (+`package.json`), `pnpm-lock.yaml` (v9) | npm | Lockfile, transitive; dev dependencies included and marked |
| `Pipfile.lock`, `poetry.lock` (+`pyproject.toml`), `uv.lock` | PyPI | Lockfile, transitive |
| `*gradle.lockfile` | Maven | Lockfile, transitive |
| `pom.xml` | Maven | **Partial**: direct dependencies with explicit or local-property versions; no parent POMs, BOMs or transitive dependencies from repositories; test scope excluded |
| `requirements.txt` | PyPI | **Partial**: `==` pins only, direct dependencies only; other lines silently ignored |

The archive sent to the sandbox holds only these files and the `package.json` and
`pyproject.toml` that Trivy reads next to lockfiles. Repository Trivy configuration, ignore
files and VEX documents never reach it. The script also passes:
- `--config ""` and `--ignorefile /dev/null`;
- `env -i`;
- `--disable-telemetry`;
- `--skip-db-update --skip-java-db-update --skip-check-update --skip-vex-repo-update`.

**Further gaps found in the final audit** (all verified with the pinned version and now
disclosed, making coverage incomplete):
- **Python name matching (S3-8, real database).** Trivy normalizes case and `_` but not `.`
  in PyPI names. A uv or Poetry lockfile writes PEP 503 names: `products-cmfplone` matched
  none of the 6 advisories that `Products.CMFPlone` matched. Any PyPI package name with `-`
  or `.` is therefore flagged `PYPI_NAME_MATCHING_UNVERIFIED`. A worker-side fix (probing
  name variants) changes scanner semantics and needs approval.
- **`Pipfile.lock` development dependencies (S3-7).** They are ignored even with
  `--include-dev-deps`. The worker counts them with its strict JSON loader
  (`DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED`).
- **Incomparable versions (S3-4).** npm versions outside SemVer (git, file or tarball
  references), PyPI versions outside PEP 440, and Maven versions with unresolved
  properties cannot match any advisory. They are now counted as unresolved.

**Coverage rules.** A Trivy result target is **not** taken as complete resolution:

- **No result → not analyzed.** A supported manifest without a result counts as not
  analyzed (`scanner_skipped`). Trivy reports malformed, empty and dependency-free
  lockfiles the same way: no result, exit 0, no warning (verified). Each is counted.
- **Counts only.** `coverage.dependencies` records:
  - packages, unresolved packages (non-root, no version) and development packages;
  - partial manifests;
  - declarations without a lockfile in their directory or an ancestor;
  - unsupported dependency files (other ecosystems, `requirements-*.txt`, `bun.lockb`, …);
  - binary artifacts.
- **Incomplete coverage.** Any of these makes `coverage.complete` false:
  - partial formats, unresolved versions, missing lockfiles;
  - unsupported formats, binary artifacts;
  - no supported manifest;
  - a stale database.

  A synthetic database is disclosed (`SYNTHETIC_VULNERABILITY_DATABASE`). It does not by
  itself make coverage incomplete.

### 7. Normalization and evidence (`findings.v1`, compatible)

- **Minimal report.** A constant Go template makes Trivy emit only identifiers, versions
  and counts as positional arrays (sprig `toJson` escaping). Advisory titles,
  descriptions, references, CVSS vectors and URLs never leave the sandbox. The report is
  bounded by the shared 1 MiB artifact limit of `sandbox-output.v1`: about 12,000 short
  package names, measured (decision 9).
- **Strict parsing.** The report is parsed with:
  - the exact version `0.75.0`;
  - closed key and arity sets;
  - targets that are snapshot manifests matching their type;
  - vulnerabilities that refer to a package Trivy listed;
  - validated advisory, CWE and data-source identifiers.

  Any deviation fails closed.
- **Finding fields:**
  - category `DEPENDENCY_VULNERABILITY`;
  - `rule_id` = advisory id (CVE when Trivy prefers it, else GHSA);
  - location target `DEPENDENCY_MANIFEST` with the safe manifest path and no lines;
  - `package` {ecosystem, name, installed version, fixed versions, development, redacted};
  - `advisory` {aliases, data source, status};
  - `scanner_severity` verbatim; the normalized `severity` stays null (M4);
  - CWE classification when present;
  - `evidence = {redacted: true, excerpt: null}`, enforced by the schema.
- **Fingerprint.** `[domain, scanner, advisory, DEPENDENCY_MANIFEST, safe path, ecosystem,
  package, version]`, with no lines, which change whenever a lockfile is regenerated.
- **Document-level block.** `vulnerability_database`: schema version, `updated_at`,
  `next_update`, age at scan time, freshness, database digests, source and image identity.
- **Privacy.**
  - Only *vulnerable* packages are named; those exist in a published advisory. The
    inventory is recorded as counts only.
  - Package names and versions come from lockfiles. They must be printable and at most
    256 characters, and token-like runs (32+ characters) are replaced by `[redacted]`,
    flagged by `package.redacted` and `PACKAGE_VALUES_REDACTED`. Installed versions are
    also checked with the path heuristic (credential prefixes such as `AKIA`, high-entropy
    runs) and redacted entirely when flagged (defect S3-5).
  - Manifest paths use the existing safe-path redaction.
  - No raw report is stored, only its digest.
- **Schema changes.** Only optional properties and new enum values. Gitleaks and Semgrep
  documents are unchanged.

### 8. Control plane and production

- `TRIVY` is executable (`EXECUTABLE_SCANNERS`).
- It is refused in `planned-scanners` under production profiles (`LOCAL_FIXTURE_SCANNERS`).
- Workers refuse `SENTINEL_WORKER_TRIVY_ENABLED=true` in `production`.
- Workers that do not enable Trivy never import its modules or touch its image (tested).
- No database migration: `TRIVY` was already a valid scanner type.

### 9. Measured resources (1 CPU, real database)

| Input | Scan time | Peak cgroup memory (incl. tmpfs) | Peak processes |
|---|---|---|---|
| 3 small manifests | < 1 s (about 5 s including container start) | 36 MiB | 17 |
| 12,000-package lockfile | about 1 s | 100–114 MiB | 9 |

**Limits:**
- 512 MiB memory (about 4.5 times the largest measured peak);
- 64 PIDs, 128 MiB tmpfs;
- 32 MiB stdin, 2 MiB stdout, 1 MiB report;
- the shared timeout and CPU settings.

## Consequences

- **Findings mean affected versions, not exploitability.** A finding means a declared
  dependency version is in an advisory's affected range in the recorded database. It does
  not prove that the vulnerable code is reachable (`REACHABILITY_NOT_ANALYZED`). A clean
  result means only that no analyzed package matched, in data as of `updated_at`. Until
  M4, scans stay `INCOMPLETE`.
- **Database refresh is an operational duty.** A worker refuses databases older than 7
  days, so a deployment without a refreshed lock stops scanning rather than reporting
  stale results as current.
- **Upgrading Trivy is a reviewed change** (runbook). It covers:
  - the base pin and vendored configuration;
  - the database schema version and the bbolt version;
  - the template fields, result types and coverage table;
  - the measured limits.
- **Images accumulate locally** (one per database, sharing the base layers). Pruning old
  images is an operator task (runbook).

## Alternatives considered

- **Database on stdin.** Rejected: 121 MiB compressed exceeds the hard stdin cap, 1.37 GiB
  exceeds the tmpfs cap, and it would mean about 2 GiB of memory and a decompression per
  scan. Raising the limits was ruled out.
- **Read-only named volume.** Rejected: it breaks the verified `no_host_mounts` control.
- **Filtered database small enough for stdin.** Rejected for now: rewriting bbolt files
  makes the database our derivation of upstream data.
- **`docker build` with `COPY`.** Rejected: not reproducible, it got directory modes wrong,
  and its output cannot be predicted from the inputs for verification.
- **Trusting the image ID, a tag, or labels.** Rejected: names and labels are
  configuration; only content digests prove ancestry.
- **Hashing the full database in every sandbox.** Rejected: about 5 s of CPU per scan for
  an immutable image already verified by content at start-up.
- **Java DB for JAR analysis.** Deferred: 936 MiB, not used in filesystem mode.
- **Native JSON report.** Rejected: it carries advisory prose and URLs and exceeds the
  1 MiB artifact limit for medium lockfiles.
- **Automatic database updater.** Deferred: requires approval (a privileged, networked
  component).

## Acceptance

- **Decision:** Accepted with conditions.
- **Date:** 2026-10-11.
- **Decision owner:** the repository owner (recorded on the owner's instruction; no
  restriction is waived).
- **Supporting CI:** run #13 on `main`, commit `f0f6a83`, all six jobs green, including
  the Trivy sandbox and end-to-end steps, as reported by the repository owner. `f0f6a83`
  fixed the `LOAD_FAILED` error of the preceding run on `7b2c42f` (classic image store:
  `manifest.json` added to the loaded archive).
- **Production restrictions:** Trivy stays refused in production by worker and API until
  stronger isolation and verified commit snapshots exist. No automatic database updater
  is approved. There is no production authorization of any kind.
- **Residual risks accepted as documented (security review R1 to R7):**
  - R1: runc isolation for synthetic fixtures only;
  - R2: database integrity is established, publisher authenticity is not. Accepted only
    with image preparation limited to trusted operators, the documented two-person
    refresh review and mirror corroboration;
  - R3: the disclosed coverage limits (partial `pom.xml` and `requirements.txt`, npm
    prerelease semantics, `Pipfile.lock` development entries, empty lockfiles reported as
    not analyzed, no Java archive or other-ecosystem analysis, about 12,000 packages per
    report, records deleted inside a present advisory bucket);
  - R4: advisory data is a point-in-time snapshot of up to 7 days; refresh is manual;
  - R5: no signature verification of the base image or database (M6);
  - R6: linux/amd64 only;
  - R7: the refresh audit log is a local append-only file, not tamper-evident.
- **Manual refresh procedure adopted** as documented in the runbook.
- **S3-8 decision:** the worker-side PyPI name-variant workaround is **not approved and
  not implemented**. The limitation stays disclosed (`PYPI_NAME_MATCHING_UNVERIFIED`,
  coverage incomplete). Under M4 policies such evidence cannot produce `PASS` while the
  policy requires complete coverage ([ADR-0013](0013-security-policy-engine.md)).
- **Follow-up work:** signed database provenance or a SentinelPipe signing step (needs
  approval); the S3-8 decision may be revisited with the owner; stronger isolation and
  verified commit snapshots before any production use.

# Runbook: Trivy dependency scanner

Design: [ADR-0012](../adr/0012-trivy-sca-with-an-embedded-verified-database.md). Threat
model: [Trivy scanner](../threat-model/trivy-scanner.md). General operations:
[execution runbook](execution.md); shared input mechanics: [Gitleaks runbook](gitleaks.md).

**Scope in this version:** development and CI only.
- Trivy scans dependency manifests of synthetic repositories from a local fixture
  directory.
- The worker refuses it in `production`, and the API refuses `TRIVY` in
  `planned-scanners` under production profiles.
- Dependency vulnerabilities only: no images, secrets, misconfigurations or licenses.

## 1. Pinned image

| | |
|---|---|
| Version | Trivy **0.75.0** |
| Base image | `ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa` (verified platform: linux/amd64) |
| Vendored base config | `sentinel_worker/scanners/trivy-base-config.json`, SHA-256 `6d93f1ec925b37c5ce785e416b86cba056e10c8c2914a59a8ea7be18115d6764` (`BASE_CONFIG_DIGEST`) |
| Defined in | `TRIVY_BASE_IMAGE` (`sandbox/policy.py`), `BASE_*` (`scanners/trivy_image.py`); CI pre-pulls the same digest |

The base image is never run as is. Scans run a **local image** that adds the vulnerability
database as one read-only layer, and the worker accepts it only after verifying its
content.

## 2. Preparing a database and its image

Everything in this section is a trusted, networked preparation step on an operator machine
or CI. It never runs inside a scanner sandbox, and the worker never downloads anything.

```powershell
docker pull ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa

# 1. See what the mutable tag points at now; review the digest and "created".
python -I scripts\trivy\fetch-trivy-db.py resolve

# 2. Fetch exactly that artifact (manifest and blob verified by digest; only trivy.db
#    and metadata.json extracted; schema version 2 required).
python -I scripts\trivy\fetch-trivy-db.py fetch --manifest-digest sha256:<reviewed> --output C:\trivy\db-2026-10-11

# 3. Build the image (deterministic layer, docker load) and write its lock. The build
#    ends with the same content verification the worker performs.
.\.venv\Scripts\sentinel-worker.exe trivy-image build --db-dir C:\trivy\db-2026-10-11 --lock-out C:\trivy\trivy-2026-10-11.lock

# 4. Verify at any time (also done at every worker start).
.\.venv\Scripts\sentinel-worker.exe trivy-image verify --lock C:\trivy\trivy-2026-10-11.lock
```

**Measured** for the 2026-10-11 database (1.37 GiB):
- fetch 20 s;
- build 2 min 16 s;
- verification 24 s.

The lock is configuration. It names the image and the database digests, and it is never
trusted on its own (ADR-0012 §3).

**Refreshing (manual, audited).** Databases older than 48 hours are reported as `STALE`.
Older than 7 days, the worker refuses to start and fails scans. Refresh at least daily
while Trivy workers run. There is no automatic updater in this version.

1. **Resolve and review.** Run `python -I scripts\trivy\fetch-trivy-db.py resolve`.
   `corroborated` must be `true`: `mirror.gcr.io/aquasec/trivy-db:2` serves the same
   blob as ghcr.io. If the mirror lags, wait and retry.
2. **Prepare.** Run this with the worker's Python:
   ```powershell
   .\.venv\Scripts\python.exe scripts\trivy\refresh-trivy-db.py --manifest-digest sha256:<reviewed> `
     --work-root C:\trivy --operator "<name>" --reason "<ticket>" --previous-lock C:\trivy\trivy-<old>.lock
   ```
   It fetches (by digest, corroborated), builds, verifies, and appends a record to
   `C:\trivy\refresh-audit.jsonl`. It never overwrites an existing database or lock and
   never touches running workers.
3. **Second review.** A second person checks the audit record:
   - the digests match step 1;
   - `updated_at` is recent;
   - `corroboration_skipped` is null, or has an accepted reason.
4. **Switch.** Point `SENTINEL_WORKER_TRIVY_IMAGE_LOCK` at the new lock and restart the
   Trivy workers. Each verifies the image again at start. Keep the previous image and lock
   until every worker runs the new one, then remove the old image.

Never edit a lock by hand. Its metadata must match the database, and the worker refuses
any difference (`METADATA_MISMATCH`).

**Pruning.** Each database produces one image tagged
`sentinelpipe-local/trivy-db:<config digest prefix>`. Remove old ones with
`docker image rm <id>` once no worker uses their lock.

**Test database.** CI uses a synthetic database (fictitious packages) instead:

```powershell
sh scripts/trivy/build-fixture-db.sh C:\trivy\fixture-db
$env:SENTINEL_TEST_TRIVY_DB_DIR = "C:\trivy\fixture-db"
.\.venv\Scripts\python.exe -m pytest -m sandbox -k trivy
```

The script needs Docker and the pinned Go image. Go modules come from the Go proxy and are
checked against the checksum database.

## 3. Running a Trivy worker locally

Use the usual fixture layout (`<root>/<owner>/<name>`). Plan the scanner in the API with
`SENTINEL_EXECUTION_PLANNED_SCANNERS=TRIVY` (`local` profile), then start the worker:

```powershell
$env:SENTINEL_WORKER_TRIVY_ENABLED = "true"
$env:SENTINEL_WORKER_TRIVY_IMAGE_LOCK = "C:\trivy\trivy-2026-10-11.lock"
$env:SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR = "C:\sentinel-fixtures"
.\.venv\Scripts\sentinel-worker.exe sandbox-check --profile trivy
.\.venv\Scripts\sentinel-worker.exe execute --idle-timeout 60
```

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_WORKER_TRIVY_ENABLED` | `false` | Execute `TRIVY` jobs (refused in `production`) |
| `SENTINEL_WORKER_TRIVY_IMAGE_LOCK` | none | Absolute path of the lock written by `trivy-image build` |
| `SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR` | none | Shared with Gitleaks and Semgrep |
| `SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS`, `_CPUS`, `_RUNTIME` | 300, 1, runc | Shared |

**Startup refusals:**
- The worker exits with a configuration error if the image fails verification
  (`trivy image rejected (<code>)`) or if the database is expired or from the future.
- Workers without `SENTINEL_WORKER_TRIVY_ENABLED` never load the Trivy modules.

**Limits.** These are fixed in code and come from measurements (ADR-0012 §9):
- memory 512 MiB, PIDs 64, tmpfs 128 MiB;
- stdin 32 MiB, stdout 2 MiB, report 1 MiB.

## 4. Supported files

| File | Ecosystem | Resolution |
|---|---|---|
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | npm | Lockfile (transitive; dev dependencies included and marked) |
| `Pipfile.lock`, `poetry.lock`, `uv.lock` | PyPI | Lockfile (transitive) |
| `*gradle.lockfile` | Maven | Lockfile (transitive) |
| `pom.xml` | Maven | Partial: no parent POMs, BOMs or transitive dependencies (offline); test scope not analyzed |
| `requirements.txt` | PyPI | Partial: `==` pins only, direct dependencies only |

**Never analyzed, always counted:**
- other ecosystems' manifests (`go.mod`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`,
  `*.csproj`, …);
- `bun.lock`, `bun.lockb`, `pylock.toml`, `npm-shrinkwrap.json`;
- requirement files other than `requirements.txt`;
- Java archives, wheels and eggs.

## 5. Reading results

Each completed job stores one `findings.json` (`findings.v1`,
[contract](../api/findings-contract-v1.md)).

**Findings.** Each one has:
- `category = DEPENDENCY_VULNERABILITY`;
- `rule_id` = advisory id;
- `location.target = DEPENDENCY_MANIFEST` with the safe manifest path;
- `package` (ecosystem, name, installed version, fixed versions, development flag);
- `advisory` (aliases, data source, status);
- `scanner_severity` (Trivy's label, verbatim).

The normalized `severity` stays null until policies exist (M4).

**`vulnerability_database`.** It records:
- `updated_at`, `age_seconds`, `freshness`;
- the database digests;
- `source`: `UPSTREAM_OCI` with digests, or `SYNTHETIC_FIXTURE`;
- the image identity.

**`coverage`:**

| Field | Meaning |
|---|---|
| `files_supported`, `files_analyzed`, `files_not_analyzed` | Supported manifests, and whether Trivy produced a result for each |
| `not_analyzed_reasons.scanner_skipped` | Supported manifests without a result: malformed, empty or dependency-free lockfiles look the same |
| `dependencies` | Counts: packages, unresolved, development, partial manifests, declarations without a lockfile, unsupported dependency files, binary artifacts |
| `limitations` | Always: `ADVISORY_DATA_POINT_IN_TIME`, `REACHABILITY_NOT_ANALYZED`, `COMMIT_NOT_VERIFIED`. As applicable: `VULNERABILITY_DB_STALE`, `PARTIAL_DEPENDENCY_RESOLUTION`, `UNRESOLVED_DEPENDENCY_VERSIONS`, `DEPENDENCY_LOCKFILE_MISSING`, `UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT`, `BINARY_ARTIFACTS_NOT_ANALYZED`, `FILES_NOT_ANALYZED`, `NO_SUPPORTED_FILES`, `SYNTHETIC_VULNERABILITY_DATABASE`, `PACKAGE_VALUES_REDACTED`, `PYPI_NAME_MATCHING_UNVERIFIED`, `DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED` |

A scan with findings is `COMPLETED`, not failed. Neither a clean nor a vulnerable scan is a
decision: until M4 the scan's decision is `INCOMPLETE`.

## 6. Failures

| Log code | Meaning | Job result |
|---|---|---|
| `TRIVY_FAILED` | Trivy exited non-zero (for example a database it cannot read) | `SCANNER_ERROR` |
| `VULNERABILITY_DB_INVALID` | The sandbox found database files that differ from the lock | `SCANNER_ERROR` |
| `VULNERABILITY_DB_EXPIRED`, `VULNERABILITY_DB_FROM_FUTURE` | Database older than 7 days, or dated more than 1 h ahead | `SCANNER_ERROR` |
| `INVALID_REPORT`, `UNEXPECTED_VERSION`, `UNKNOWN_PATH`, `UNEXPECTED_RESULT`, `UNKNOWN_PACKAGE`, `INCONSISTENT_PACKAGE`, `INVALID_ADVISORY`, `INVALID_PACKAGE` | The report failed strict validation | `SCANNER_ERROR` |
| `REPORT_TOO_LARGE`, `FINDINGS_LIMIT_EXCEEDED` | Report over 1 MiB (about 12,000 short package names), or more findings than the contract allows | `RESOURCE_LIMIT_EXCEEDED` |
| `INPUT_*` | Shared archive staging and verification codes ([Gitleaks runbook](gitleaks.md)) | `SCANNER_ERROR` |

Image verification codes (`trivy-image verify`, worker start):

| Code | Meaning |
|---|---|
| `LOCK_INVALID`, `LOCK_BASE_MISMATCH`, `SCHEMA_VERSION_UNSUPPORTED` | The lock is malformed, names another base or another schema |
| `IMAGE_NOT_FOUND`, `IMAGE_INVALID` | No such image, or its configuration (environment, entrypoint, user, platform) is not the base's |
| `CONFIG_MISMATCH`, `LAYERS_MISMATCH` | The configuration or layers differ from the pinned base plus the locked database layer |
| `LAYER_CONTENT_INVALID` | The database layer has other entries, modes or file digests than the lock |
| `DATABASE_STRUCTURE_INVALID` | `trivy.db` is not a structurally sound bbolt file (for example truncated) |
| `DATABASE_COVERAGE_MISSING` | `trivy.db` lacks the GHSA advisory bucket of Maven, npm or PyPI |
| `METADATA_MISMATCH` | The lock's metadata (date) is not the database's verified `metadata.json` |
| `EXPORT_*` | `docker save` failed or produced an inconsistent export |

A failed verification means the image must not be used. Rebuild it from a freshly fetched
database. Do not edit the lock.

## 7. Upgrading Trivy (reviewed change)

1. Pick a release at least a week old, pull it by index digest, and record the
   linux/amd64 manifest and config digests.
2. Replace `trivy-base-config.json` with the exact config blob from `docker save` and
   update `BASE_MANIFEST_DIGEST`, `BASE_CONFIG_DIGEST` and `TRIVY_BASE_IMAGE` (and
   `ci.yml`).
3. Re-verify against the new version:
   - `DB_SCHEMA_VERSION`;
   - the bbolt version and meta layout (`check_bolt_structure`);
   - the template fields (`Relationship`, `Status`, `DataSource`);
   - the result types and the coverage table in §4;
   - the offline and read-only database behavior;
   - the flags;
   - the image `ENV` and `ENTRYPOINT`.
4. Update `FIXTURE_BUILDER` and `build-fixture-db.sh` to the trivy-db commit the new
   Trivy pins.
5. Re-measure the limits and run the full sandbox suite.

## 8. Limitations

- **Findings are version matches**, not proof of reachable or exploitable code.
- **Advisory data is a snapshot**, up to 7 days old. Advisories published since
  `updated_at` are not covered.
- **`pom.xml` and `requirements.txt` coverage is partial** by design (offline). Prefer
  lockfiles.
- **Unparsable versions.** Versions outside the ecosystem grammar (git, file or tarball
  references, garbage, unresolved Maven properties) are counted as unresolved. A valid
  npm prerelease is compared with node-semver rules and does not match release ranges.
- **Python names.** Trivy does not normalize `.` in PyPI names, so a lockfile spelling
  can miss advisories filed under another spelling. Any PyPI package with `-` or `.` sets
  `PYPI_NAME_MATCHING_UNVERIFIED`.
- **`Pipfile.lock` `develop` entries are not analyzed** by Trivy 0.75.0
  (`DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED`).
- **Maven** test-scoped and optional dependencies are not analyzed (`pom.xml` is always
  partial).
- **No result is ambiguous.** A lockfile without a result is reported as not analyzed,
  even when it simply has no dependencies.
- **One platform.** linux/amd64 only.

# ruff: noqa: E501 - the constant sandbox script and template are kept on readable single lines.
"""Trivy v0.75.0 software composition analysis with an embedded, verified vulnerability
database (ADR-0012; runbook docs/runbooks/trivy.md).

**Scope.** Dependency vulnerabilities only (``--scanners vuln --pkg-types library``):
no secret, misconfiguration or license scanning, no images, no Java archives. Trivy never
resolves, builds or installs anything here: it parses lockfiles and manifests as data.

**Image and database.** Scans run the local image verified by
:mod:`.trivy_image` (pinned base plus one read-only database layer). Before each scan
the script checks that the database directory holds exactly ``trivy.db`` (of the locked
size) and ``metadata.json`` (of the locked SHA-256); the full database digest was
verified when the worker accepted the image. Trivy opens the database read-only and runs
with ``--skip-db-update --skip-java-db-update --skip-check-update
--skip-vex-repo-update --offline-scan --disable-telemetry`` and no network at all.

**Freshness** (worker clock against ``metadata.json``'s ``UpdatedAt``): up to 48 hours
FRESH; up to 7 days STALE (``VULNERABILITY_DB_STALE``, coverage incomplete); older, or
more than one hour in the future, fails the scan. A database problem is never a clean
result.

**Input.** The archive holds only the reviewed dependency files of the snapshot
(:data:`MANIFESTS`, plus ``package.json`` and ``pyproject.toml`` that Trivy reads next
to lockfiles). Repository-controlled Trivy configuration (``trivy.yaml``,
``.trivyignore``, ``.trivyignore.yaml``, VEX documents) never reaches the sandbox, and
the script also disables the configuration file and points the ignore file at
``/dev/null``. Trivy runs with ``env -i`` (no ``TRIVY_*`` variables).

**Output.** A constant Go template (:data:`TEMPLATE`) makes Trivy emit only identifiers,
versions and counts; advisory prose, URLs and CVSS vectors never leave the sandbox. The
report is parsed strictly, in memory, and only its digest is kept.

**Coverage** (verified against the pinned version, see the runbook):

* a supported manifest without a Trivy result is *not analyzed* (``scanner_skipped``):
  Trivy reports malformed and dependency-free lockfiles the same way, silently;
* ``pom.xml`` (offline: no parent POMs, BOMs or transitive dependencies from
  repositories; test scope excluded) and ``requirements.txt`` (``==`` pins only, direct
  dependencies only) are partial (``PARTIAL_DEPENDENCY_RESOLUTION``);
* packages without a determinable version cannot match any advisory
  (``UNRESOLVED_DEPENDENCY_VERSIONS``);
* declarations without a lockfile, other ecosystems' manifests and binary artifacts are
  counted and flagged, never silently ignored.

Any of these makes ``coverage.complete`` false. Until M4 the decision stays INCOMPLETE.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel_worker.execution.evidence import MAX_ARTIFACT_BYTES, Artifact
from sentinel_worker.execution.leases import FailureReason, JobLease
from sentinel_worker.repository.snapshot import InputError, InputErrorCode, RepositorySnapshot
from sentinel_worker.sandbox.docker import SandboxRun
from sentinel_worker.sandbox.policy import TRIVY_BASE_IMAGE, SandboxPolicy, Workload
from sentinel_worker.sandbox.protocol import InvalidOutputError, parse
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.findings import (
    CATEGORY_DEPENDENCY_VULNERABILITY,
    DEPENDENCY_MANIFEST,
    AdvisoryRef,
    Classification,
    Coverage,
    Finding,
    FindingsLimitError,
    PackageRef,
    Scanner,
    build_document,
)
from sentinel_worker.scanners.paths import safe_paths, suspicious
from sentinel_worker.scanners.sandbox_input import (
    INVALID_JSON,
    PROLOGUE,
    STAGE_AND_VERIFY,
    failures,
    load_json,
)
from sentinel_worker.scanners.trivy_image import CACHE_DIR, DB_DIR, VerifiedImage

SCANNER_TYPE = "TRIVY"
VERSION = "0.75.0"
IDENTITY = Scanner(name="trivy", version=VERSION, image=TRIVY_BASE_IMAGE)
EVIDENCE_NAME = "findings.json"
REPORT_NAME = "trivy-report.json"
#: The report travels as one sandbox-output.v1 artifact (at most 1 MiB). With the compact
#: format this fits several thousand packages (measured in the runbook); a larger report
#: fails explicitly (REPORT_TOO_LARGE), it is never truncated.
MAX_REPORT_BYTES = MAX_ARTIFACT_BYTES
MAX_RESULTS = 5000
MAX_PACKAGES = 100_000
MAX_VULNERABILITIES = 5000
FRESH_FOR = timedelta(hours=48)
USABLE_FOR = timedelta(days=7)
CLOCK_SKEW = timedelta(hours=1)
DESCRIPTION = (
    "A dependency version is affected by a published vulnerability advisory. Upgrade to a "
    "fixed version where one is listed, then rescan."
)

#: Trivy result type -> (ecosystem, how the manifest file is named).
RESULT_TYPES: dict[str, tuple[str, Callable[[str], bool]]] = {
    "npm": ("npm", lambda name: name == "package-lock.json"),
    "yarn": ("npm", lambda name: name == "yarn.lock"),
    "pnpm": ("npm", lambda name: name == "pnpm-lock.yaml"),
    "pip": ("pypi", lambda name: name == "requirements.txt"),
    "pipenv": ("pypi", lambda name: name == "Pipfile.lock"),
    "poetry": ("pypi", lambda name: name == "poetry.lock"),
    "uv": ("pypi", lambda name: name == "uv.lock"),
    "pom": ("maven", lambda name: name == "pom.xml"),
    "gradle": ("maven", lambda name: name.endswith("gradle.lockfile")),
}
#: Reviewed manifests and lockfiles Trivy analyzes (by file name).
MANIFESTS = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pom.xml",
    }
)
#: Formats that resolve only part of the dependency graph offline.
PARTIAL_MANIFESTS = frozenset({"pom.xml", "requirements.txt"})
#: Files Trivy reads next to lockfiles (dependency relationships, dev groups); they are
#: passed to the sandbox but are not analyzed on their own.
COMPANIONS = frozenset({"package.json", "pyproject.toml"})
#: Declarations that need a lockfile of their ecosystem in the same or an ancestor
#: directory to be analyzed.
DECLARATIONS: dict[str, frozenset[str]] = {
    "package.json": frozenset({"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}),
    "pyproject.toml": frozenset({"poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"}),
    "Pipfile": frozenset({"Pipfile.lock"}),
    "setup.py": frozenset({"poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"}),
    "setup.cfg": frozenset({"poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"}),
    "build.gradle": frozenset({"gradle.lockfile"}),
    "build.gradle.kts": frozenset({"gradle.lockfile"}),
}
#: Dependency manifests of formats or ecosystems that are not analyzed in this version.
UNSUPPORTED_DEPENDENCY_FILES = frozenset(
    {
        "npm-shrinkwrap.json",
        "bun.lock",
        "bun.lockb",
        "pylock.toml",
        "go.mod",
        "go.sum",
        "Cargo.lock",
        "Cargo.toml",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "packages.lock.json",
        "packages.config",
        "pubspec.lock",
        "Podfile.lock",
        "Package.resolved",
        "mix.lock",
        "conan.lock",
        "Manifest.toml",
    }
)
_UNSUPPORTED_SUFFIXES = (".csproj", ".sbt.lock")
_BINARY_SUFFIXES = (".jar", ".war", ".ear", ".par", ".whl", ".egg")
_REQUIREMENTS_VARIANT = re.compile(r".*requirements.*\.(txt|in)\Z")
LIMITATIONS = ("ADVISORY_DATA_POINT_IN_TIME", "COMMIT_NOT_VERIFIED", "REACHABILITY_NOT_ANALYZED")

_ADVISORY_ID = re.compile(r"[A-Z][A-Z0-9]{1,15}(-[A-Za-z0-9._]{1,32}){1,4}\Z")
_CWE = re.compile(r"CWE-[0-9]{1,5}\Z")
_SOURCE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
_PACKAGE_VALUE = re.compile(r"[^\x00-\x1f\x7f-\x9f]{1,256}\Z")
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/=_]{32,}")
#: Version grammars Trivy can compare: SemVer 2.0 (npm) and PEP 440 (PyPI). A version
#: outside its grammar (a git or file reference, garbage) cannot match any advisory, so
#: it is counted as unresolved instead of silently looking clean (security review S3-4).
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\Z"
)
_PEP440 = re.compile(
    r"v?([0-9]+!)?[0-9]+(\.[0-9]+)*([-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"((-[0-9]+)|([-_.]?(post|rev|r)[-_.]?[0-9]*))?([-_.]?dev[-_.]?[0-9]*)?"
    r"(\+[a-z0-9]+([-_.][a-z0-9]+)*)?\Z",
    re.IGNORECASE,
)
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"})
_STATUSES = frozenset(
    {
        "",
        "fixed",
        "affected",
        "under_investigation",
        "will_not_fix",
        "fix_deferred",
        "end_of_life",
        "not_affected",
        "unknown",
    }
)
#: Positional fields of the compact report (see :data:`TEMPLATE`).
PACKAGE_FIELDS = ("id", "name", "version", "dev", "relationship")
VULNERABILITY_FIELDS = (
    "id",
    "vendor_ids",
    "pkg_id",
    "pkg_name",
    "installed",
    "fixed",
    "status",
    "severity",
    "source",
    "cwe",
)

#: The report format: identifiers, versions and counts only (sprig's toJson escapes).
#: Packages and vulnerabilities are positional arrays (PACKAGE_FIELDS,
#: VULNERABILITY_FIELDS) to fit large lockfiles into one 1 MiB artifact.
TEMPLATE = (
    '{"version":{{ toJson appVersion }},"results":['
    "{{- range $i, $r := . }}{{ if $i }},{{ end }}"
    '{"target":{{ toJson $r.Target }},"type":{{ toJson $r.Type }},"class":{{ toJson $r.Class }},"packages":['
    "{{- range $j, $p := $r.Packages }}{{ if $j }},{{ end }}"
    "[{{ toJson $p.ID }},{{ toJson $p.Name }},{{ toJson $p.Version }},{{ toJson $p.Dev }},{{ toJson $p.Relationship.String }}]"
    '{{ end }}],"vulnerabilities":['
    "{{- range $k, $v := $r.Vulnerabilities }}{{ if $k }},{{ end }}"
    "[{{ toJson $v.VulnerabilityID }},{{ toJson $v.VendorIDs }},{{ toJson $v.PkgID }},{{ toJson $v.PkgName }},{{ toJson $v.InstalledVersion }},{{ toJson $v.FixedVersion }},{{ toJson $v.Status.String }},{{ toJson $v.Severity }},{{ if $v.DataSource }}{{ toJson $v.DataSource.ID }}{{ else }}null{{ end }},{{ toJson $v.CweIDs }}]"
    "{{ end }}]}{{ end }}]}"
).encode("ascii")
#: Checked in the sandbox before Trivy runs: the template is worker data, not covered by
#: the repo/ digest (security review: a truncated or altered template must not run).
TEMPLATE_SHA256 = hashlib.sha256(TEMPLATE).hexdigest()

# Positional parameters (all generated by the worker): $1 expected number of files, $2
# maximum report bytes, $3 expected extraction digest, $4 metadata.json SHA-256, $5
# trivy.db size in bytes, $6 report template SHA-256.
_SCRIPT = (
    PROLOGUE
    + "expected_files=$1\nexpected_digest=$3\n"
    + STAGE_AND_VERIFY
    + rf"""
report=/tmp/report.json
db={DB_DIR}
[ -f "$input/config/report.tpl" ] || exit 72
template=$(sha256sum < "$input/config/report.tpl") || exit 72
[ "${{template%% *}}" = "$6" ] || exit 72
[ "$(find "$db" -mindepth 1 | sort | tr '\n' ' ')" = "$db/metadata.json $db/trivy.db " ] || exit 76
[ -z "$(find "$db" -mindepth 1 ! -type f)" ] || exit 76
[ "$(wc -c < "$db/trivy.db")" -eq "$5" ] || exit 76
meta=$(sha256sum < "$db/metadata.json") || exit 76
[ "${{meta%% *}}" = "$4" ] || exit 76
mkdir /tmp/home /tmp/work || exit 71
cd /tmp/work || exit 71
env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/home trivy fs --cache-dir {CACHE_DIR} --cache-backend memory --skip-db-update --skip-java-db-update --skip-check-update --skip-vex-repo-update --offline-scan --disable-telemetry --scanners vuln --pkg-types library --include-dev-deps --list-all-pkgs --config "" --ignorefile /dev/null --format template --template "@$input/config/report.tpl" --output "$report" --quiet "$input/repo" > /dev/null 2> /tmp/trivy.err
[ "$?" -eq 0 ] || exit 70
[ -f "$report" ] || exit 73
[ "$(wc -c < "$report")" -le "$2" ] || exit 74
printf '{{"artifacts":[{{"content_base64":"'
base64 "$report" | tr -d '\n'
printf '","media_type":"application/json","name":"{REPORT_NAME}"}}],"schema_version":1}}'
exit 0
"""
)

_SCRIPT_FAILURES = {
    **failures("TRIVY_FAILED"),
    76: ("VULNERABILITY_DB_INVALID", FailureReason.SCANNER_ERROR),
}


def _invalid(code: str = "INVALID_REPORT") -> ScannerError:
    return ScannerError(code, FailureReason.SCANNER_ERROR)


def _name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def is_manifest(path: str) -> bool:
    name = _name(path)
    return name in MANIFESTS or name.endswith("gradle.lockfile")


def _scanner_input(path: str) -> bool:
    return is_manifest(path) or _name(path) in COMPANIONS


def _ancestors(path: str) -> list[str]:
    directory = posixpath.dirname(path)
    result = [directory]
    while directory:
        directory = posixpath.dirname(directory)
        result.append(directory)
    return result


def _lockfile_missing(path: str, lockfiles: Mapping[str, set[str]]) -> bool:
    """A declaration (package.json, pyproject.toml, ...) with no lockfile of its
    ecosystem in its directory or an ancestor. ``node_modules`` content is ignored."""
    accepted = DECLARATIONS.get(_name(path))
    if accepted is None or "node_modules" in path.split("/"):
        return False
    for directory in _ancestors(path):
        names = lockfiles.get(directory, set())
        if any(
            name in accepted or (name.endswith("gradle.lockfile") and "gradle.lockfile" in accepted)
            for name in names
        ):
            return False
    return True


def _unsupported_dependency_file(path: str) -> bool:
    name = _name(path)
    return (
        name in UNSUPPORTED_DEPENDENCY_FILES
        or name.endswith(_UNSUPPORTED_SUFFIXES)
        or (name != "requirements.txt" and bool(_REQUIREMENTS_VARIANT.match(name)))
    )


def _package_value(value: Any, version: bool = False) -> tuple[str, bool]:
    """A validated value from a lockfile, with token-like runs redacted. Installed
    versions are also checked with the path heuristic (credential prefixes, high-entropy
    runs): a version only has to fall inside an affected range to be reported, so it can
    carry a short credential (security review S3-5). Package names must match a public
    advisory to be reported at all."""
    if not isinstance(value, str) or not _PACKAGE_VALUE.match(value):
        raise _invalid("INVALID_PACKAGE")
    redacted = _TOKEN_RUN.sub("[redacted]", value)
    if version and suspicious(redacted):
        redacted = "[redacted]"
    if len(redacted) > 256:
        raise _invalid("INVALID_PACKAGE")
    return redacted, redacted != value


def ambiguous_pypi_name(name: str) -> bool:
    """Whether Trivy 0.75.0 may fail to match a PyPI name to its advisories. It normalizes
    case and "_" but not "." (PEP 503 treats "-", "_" and "." alike): a lockfile spelling
    ``products-cmfplone`` (uv and Poetry write normalized names) matched none of the 6
    advisories filed under ``Products.CMFPlone`` (security review S3-8). Any name with a
    "-" or "." may be spelled differently in the advisory, so it cannot be verified."""
    return "-" in name or "." in name


def pipfile_develop_entries(content: bytes) -> int:
    """Packages in a Pipfile.lock ``develop`` section. Trivy 0.75.0 ignores them even
    with --include-dev-deps (security review S3-7). Read with the strict, bounded JSON
    loader; an unreadable file counts as not analyzed elsewhere, so 0 here."""
    document = load_json(content)
    if document is INVALID_JSON or not isinstance(document, dict):
        return 0
    develop = document.get("develop")
    return len(develop) if isinstance(develop, dict) else 0


def comparable(ecosystem: str, version: str) -> bool:
    """Whether a declared version can be compared with advisory ranges at all."""
    if not version or "${" in version:
        return False
    if ecosystem == "npm":
        return bool(_SEMVER.match(version))
    if ecosystem == "pypi":
        return bool(_PEP440.match(version))
    return True


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class _Package:
    package_id: str
    name: str
    version: str
    dev: bool
    root: bool


@dataclass(frozen=True, slots=True)
class _Result:
    target: str
    ecosystem: str
    packages: tuple[_Package, ...]
    vulnerabilities: tuple[dict[str, Any], ...]


class TrivyAdapter:
    def __init__(
        self, image: VerifiedImage, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._image = image
        self._clock = clock

    @property
    def scanner_type(self) -> str:
        return SCANNER_TYPE

    @property
    def identity(self) -> Scanner:
        return IDENTITY

    @property
    def sandbox_image(self) -> str:
        return self._image.image_id

    def policy(
        self, timeout_seconds: float = 300.0, cpus: float = 1.0, runtime: str | None = None
    ) -> SandboxPolicy:
        """Measured on 1 CPU with the full upstream database (1.4 GB, memory-mapped
        read-only from the image; docs/runbooks/trivy.md): peak cgroup memory (including
        tmpfs pages) about 36 MiB for small manifests and 100-114 MiB for a 12,000-package
        lockfile (database pages are touched on demand), at most 17 processes, about one
        second of scanning. Limits: 512 MiB memory, 64 processes, 128 MiB tmpfs (staged
        archive up to 32 MiB plus its extraction), 2 MiB stdout for a report of at most
        1 MiB. Trivy is a reviewed tool (TRUSTED_TOOL); the lockfiles it parses
        stay untrusted (ADR-0009 trust policy)."""
        return SandboxPolicy(
            image=self._image.image_id,
            memory_bytes=512 * 1024 * 1024,
            cpus=cpus,
            pids=64,
            tmpfs_bytes=128 * 1024 * 1024,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=2 * 1024 * 1024,
            max_stdin_bytes=32 * 1024 * 1024,
            runtime=runtime,
            workload=Workload.TRUSTED_TOOL,
        )

    def prepare(self, snapshot: RepositorySnapshot) -> RepositorySnapshot:
        """The whole snapshot: :meth:`interpret` classifies every file for coverage. Only
        the dependency files are sent to the sandbox (:meth:`stdin`)."""
        return snapshot

    @staticmethod
    def scanner_input(snapshot: RepositorySnapshot) -> RepositorySnapshot:
        """The files Trivy receives: reviewed manifests and their companion files. Not
        counted as skipped: the rest of the repository is not dependency data."""
        return RepositorySnapshot(
            files=tuple(entry for entry in snapshot.files if _scanner_input(entry.path)),
            skipped=snapshot.skipped,
            kind=snapshot.kind,
        )

    def stdin(self, snapshot: RepositorySnapshot) -> bytes:
        archive = self.scanner_input(snapshot).archive("repo", {"config/report.tpl": TEMPLATE})
        if len(archive) > self.policy().max_stdin_bytes:
            raise InputError(InputErrorCode.INPUT_TOO_LARGE)
        return archive

    def command(self, snapshot: RepositorySnapshot) -> list[str]:
        scanned = self.scanner_input(snapshot)
        lock = self._image.lock
        return [
            "/bin/sh",
            "-c",
            _SCRIPT,
            "sentinel-trivy",
            str(len(scanned.files)),
            str(MAX_REPORT_BYTES),
            scanned.extraction_sha256,
            lock.metadata_sha256,
            str(lock.trivy_db_size),
            TEMPLATE_SHA256,
        ]

    def database_state(self) -> tuple[str, int]:
        """("FRESH" or "STALE", age in seconds) at this moment, or ScannerError."""
        age = self._clock() - self._image.lock.metadata.updated_at
        if age < -CLOCK_SKEW:
            raise ScannerError("VULNERABILITY_DB_FROM_FUTURE", FailureReason.SCANNER_ERROR)
        if age > USABLE_FOR:
            raise ScannerError("VULNERABILITY_DB_EXPIRED", FailureReason.SCANNER_ERROR)
        seconds = max(0, int(age.total_seconds()))
        return ("FRESH" if age <= FRESH_FOR else "STALE"), seconds

    def interpret(
        self, run: SandboxRun, snapshot: RepositorySnapshot, lease: JobLease
    ) -> tuple[Artifact, ...]:
        code = run.exit_code
        if code in _SCRIPT_FAILURES:
            raise ScannerError(*_SCRIPT_FAILURES[code])
        if code != 0:
            if code is not None and 0 < code < 128:
                raise _invalid("UNEXPECTED_EXIT_CODE")
            raise ScannerError("TERMINATED", FailureReason.SANDBOX_ERROR)
        freshness, age_seconds = self.database_state()
        raw = self._output(run.stdout)
        if raw is None:
            raise _invalid("INVALID_OUTPUT")
        report = load_json(raw)
        if report is INVALID_JSON or not isinstance(report, dict):
            raise _invalid()
        if set(report) != {"version", "results"}:
            raise _invalid()
        if report["version"] != VERSION:
            raise _invalid("UNEXPECTED_VERSION")
        manifests = [entry.path for entry in snapshot.files if is_manifest(entry.path)]
        results = self._results(report["results"], frozenset(manifests))
        safe = safe_paths(snapshot.ordered_paths)
        findings: list[Finding] = []
        redacted_values = False
        for result in results:
            for vulnerability in result.vulnerabilities:
                finding = self._finding(vulnerability, result, safe)
                redacted_values = redacted_values or bool(
                    finding.package and finding.package.redacted
                )
                findings.append(finding)
        analyzed = {result.target for result in results}
        not_analyzed = [path for path in manifests if path not in analyzed]
        lockfiles: dict[str, set[str]] = {}
        for path in manifests:
            lockfiles.setdefault(posixpath.dirname(path), set()).add(_name(path))
        paths = [entry.path for entry in snapshot.files]
        dependencies = {
            "packages": sum(len(result.packages) for result in results),
            "packages_unresolved": sum(
                1
                for result in results
                for package in result.packages
                if not package.root and not comparable(result.ecosystem, package.version)
            ),
            "packages_development": sum(
                1 for result in results for package in result.packages if package.dev
            ),
            "manifests_partial": sum(1 for path in analyzed if _name(path) in PARTIAL_MANIFESTS),
            "manifests_lockfile_missing": sum(
                1 for path in paths if _lockfile_missing(path, lockfiles)
            ),
            "unsupported_dependency_files": sum(
                1 for path in paths if _unsupported_dependency_file(path)
            ),
            "binary_artifacts": sum(
                1 for path in paths if _name(path).lower().endswith(_BINARY_SUFFIXES)
            ),
        }
        limitations = set(LIMITATIONS)
        conditional = {
            "FILES_NOT_ANALYZED": bool(not_analyzed),
            "NO_SUPPORTED_FILES": not manifests,
            "PARTIAL_DEPENDENCY_RESOLUTION": dependencies["manifests_partial"] > 0,
            "UNRESOLVED_DEPENDENCY_VERSIONS": dependencies["packages_unresolved"] > 0,
            "DEPENDENCY_LOCKFILE_MISSING": dependencies["manifests_lockfile_missing"] > 0,
            "UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT": dependencies["unsupported_dependency_files"]
            > 0,
            "BINARY_ARTIFACTS_NOT_ANALYZED": dependencies["binary_artifacts"] > 0,
            "VULNERABILITY_DB_STALE": freshness == "STALE",
            "SYNTHETIC_VULNERABILITY_DATABASE": self._image.lock.source.kind == "SYNTHETIC_FIXTURE",
            "PACKAGE_VALUES_REDACTED": redacted_values,
            "PYPI_NAME_MATCHING_UNVERIFIED": any(
                result.ecosystem == "pypi"
                and not package.root
                and ambiguous_pypi_name(package.name)
                for result in results
                for package in result.packages
            ),
            "DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED": any(
                pipfile_develop_entries(entry.content) > 0
                for entry in snapshot.files
                if _name(entry.path) == "Pipfile.lock"
            ),
        }
        limitations |= {name for name, present in conditional.items() if present}
        # Anything that leaves dependencies unexamined, or advisory data stale, means the
        # dependency coverage is not complete (even when every manifest was parsed).
        incomplete = any(
            conditional[name]
            for name in (
                "NO_SUPPORTED_FILES",
                "PARTIAL_DEPENDENCY_RESOLUTION",
                "UNRESOLVED_DEPENDENCY_VERSIONS",
                "DEPENDENCY_LOCKFILE_MISSING",
                "UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT",
                "BINARY_ARTIFACTS_NOT_ANALYZED",
                "VULNERABILITY_DB_STALE",
                "PYPI_NAME_MATCHING_UNVERIFIED",
                "DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED",
            )
        )
        coverage = Coverage(
            files_supported=len(manifests),
            files_analyzed=len(manifests) - len(not_analyzed),
            files_not_analyzed=len(not_analyzed),
            files_unsupported=len(snapshot.files) - len(manifests),
            not_analyzed_reasons={
                "scanner_skipped": len(not_analyzed),
                "parse_error": 0,
                "resource_limit": 0,
                "unverifiable_encoding": 0,
            },
        )
        lock = self._image.lock
        database = {
            "schema_version": lock.metadata.version,
            "updated_at": _format_time(lock.metadata.updated_at),
            "next_update": _format_time(lock.metadata.next_update),
            "age_seconds": age_seconds,
            "freshness": freshness,
            "trivy_db_sha256": lock.trivy_db_sha256,
            "metadata_sha256": lock.metadata_sha256,
            "source": lock.source.to_document(),
            "image": {"config_digest": lock.config_digest, "id": self._image.image_id},
        }
        document: bytes | None = None
        failure: ScannerError | None = None
        try:
            document = build_document(
                IDENTITY,
                lease,
                snapshot,
                findings,
                0,
                hashlib.sha256(raw).hexdigest(),
                limitations,
                paths_redacted=sum(1 for value in safe.values() if value.redacted),
                coverage=coverage,
                incomplete=incomplete,
                dependencies=dependencies,
                vulnerability_database=database,
            )
        except FindingsLimitError:
            failure = ScannerError("FINDINGS_LIMIT_EXCEEDED", FailureReason.RESOURCE_LIMIT_EXCEEDED)
        except ValueError:
            failure = _invalid("INVALID_FINDING")
        if failure is not None or document is None:
            raise failure or _invalid("INVALID_FINDING")
        return (Artifact(EVIDENCE_NAME, "application/json", document),)

    @staticmethod
    def _output(stdout: bytes) -> bytes | None:
        try:
            artifacts = parse(stdout)
        except InvalidOutputError:
            return None
        if len(artifacts) != 1 or artifacts[0].name != REPORT_NAME:
            return None
        return artifacts[0].content

    @staticmethod
    def _results(value: Any, manifests: frozenset[str]) -> list[_Result]:
        if not isinstance(value, list) or len(value) > MAX_RESULTS:
            raise _invalid()
        results: list[_Result] = []
        seen: set[str] = set()
        packages_total = 0
        vulnerabilities_total = 0
        for entry in value:
            if not isinstance(entry, dict) or set(entry) != {
                "target",
                "type",
                "class",
                "packages",
                "vulnerabilities",
            }:
                raise _invalid()
            target, kind = entry["target"], entry["type"]
            if entry["class"] != "lang-pkgs" or kind not in RESULT_TYPES:
                raise _invalid("UNEXPECTED_RESULT")
            if not isinstance(target, str) or target not in manifests or target in seen:
                raise _invalid("UNKNOWN_PATH")
            ecosystem, names = RESULT_TYPES[kind]
            if not names(_name(target)):
                raise _invalid("UNEXPECTED_RESULT")
            seen.add(target)
            packages, vulnerabilities = entry["packages"], entry["vulnerabilities"]
            if not isinstance(packages, list) or not isinstance(vulnerabilities, list):
                raise _invalid()
            packages_total += len(packages)
            vulnerabilities_total += len(vulnerabilities)
            if packages_total > MAX_PACKAGES or vulnerabilities_total > MAX_VULNERABILITIES:
                raise ScannerError("FINDINGS_LIMIT_EXCEEDED", FailureReason.RESOURCE_LIMIT_EXCEEDED)
            parsed: list[_Package] = []
            for row in packages:
                if not isinstance(row, list) or len(row) != len(PACKAGE_FIELDS):
                    raise _invalid()
                package_id, name, version, dev, relationship = row
                fields = (package_id, name, version, relationship)
                if not all(isinstance(item, str) and len(item) <= 1024 for item in fields):
                    raise _invalid()
                if type(dev) is not bool:
                    raise _invalid()
                parsed.append(_Package(package_id, name, version, dev, relationship == "root"))
            named: list[dict[str, Any]] = []
            for row in vulnerabilities:
                if not isinstance(row, list) or len(row) != len(VULNERABILITY_FIELDS):
                    raise _invalid()
                named.append(dict(zip(VULNERABILITY_FIELDS, row, strict=True)))
            results.append(_Result(target, ecosystem, tuple(parsed), tuple(named)))
        return results

    @staticmethod
    def _finding(
        vulnerability: dict[str, Any], result: _Result, safe: Mapping[str, Any]
    ) -> Finding:
        advisory_id = vulnerability["id"]
        if not isinstance(advisory_id, str) or not _ADVISORY_ID.match(advisory_id):
            raise _invalid("INVALID_ADVISORY")
        aliases = vulnerability["vendor_ids"] or []
        if (
            not isinstance(aliases, list)
            or len(aliases) > 8
            or not all(isinstance(a, str) and _ADVISORY_ID.match(a) for a in aliases)
        ):
            raise _invalid("INVALID_ADVISORY")
        severity, status, source = (
            vulnerability["severity"],
            vulnerability["status"],
            vulnerability["source"],
        )
        if severity not in _SEVERITIES or status not in _STATUSES:
            raise _invalid("INVALID_ADVISORY")
        if source is not None and (not isinstance(source, str) or not _SOURCE.match(source)):
            raise _invalid("INVALID_ADVISORY")
        cwe = vulnerability["cwe"] or []
        if not isinstance(cwe, list) or not all(isinstance(c, str) and _CWE.match(c) for c in cwe):
            raise _invalid("INVALID_ADVISORY")
        package = TrivyAdapter._package_of(vulnerability, result.packages)
        name, name_redacted = _package_value(vulnerability["pkg_name"])
        installed, version_redacted = _package_value(vulnerability["installed"], version=True)
        fixed_raw = vulnerability["fixed"]
        if not isinstance(fixed_raw, str):
            raise _invalid("INVALID_ADVISORY")
        fixed_values = [part.strip() for part in fixed_raw.split(",") if part.strip()]
        if len(fixed_values) > 8:
            raise _invalid("INVALID_ADVISORY")
        fixed = tuple(_package_value(value)[0] for value in fixed_values)
        location = safe[result.target]
        return Finding(
            rule_id=advisory_id,
            category=CATEGORY_DEPENDENCY_VULNERABILITY,
            description=DESCRIPTION,
            path=location.value,
            start_line=None,
            end_line=None,
            start_column=None,
            end_column=None,
            target=DEPENDENCY_MANIFEST,
            path_redacted=location.redacted,
            scanner_severity=severity,
            classification=Classification(tuple(dict.fromkeys(cwe))[:8], ()) if cwe else None,
            package=PackageRef(
                ecosystem=result.ecosystem,
                name=name,
                installed_version=installed,
                fixed_versions=fixed,
                development=package.dev,
                redacted=name_redacted or version_redacted,
            ),
            advisory=AdvisoryRef(
                aliases=tuple(dict.fromkeys(a for a in aliases if a != advisory_id)),
                data_source=source,
                status=status or None,
            ),
        )

    @staticmethod
    def _package_of(vulnerability: dict[str, Any], packages: Sequence[_Package]) -> _Package:
        """The reported package a vulnerability refers to (by id, else by name and
        version); a vulnerability for a package Trivy did not list is invalid."""
        package_id, name, installed = (
            vulnerability["pkg_id"],
            vulnerability["pkg_name"],
            vulnerability["installed"],
        )
        if not all(isinstance(item, str) for item in (package_id, name, installed)):
            raise _invalid()
        for package in packages:
            if package_id and package.package_id == package_id:
                if package.name != name or package.version != installed:
                    raise _invalid("INCONSISTENT_PACKAGE")
                return package
        for package in packages:
            if not package_id and package.name == name and package.version == installed:
                return package
        raise _invalid("UNKNOWN_PACKAGE")

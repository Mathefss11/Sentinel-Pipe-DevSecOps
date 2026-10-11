"""Trivy adapter: report parsing, normalization, coverage, freshness and failure handling
(ADR-0012). No container runtime is needed; reports are synthetic."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
from datetime import timedelta
from typing import Any

import pytest

from scanner_support import exited, lease
from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.execution.leases import FailureReason
from sentinel_worker.execution.settings import ExecutionSettings
from sentinel_worker.messaging import contracts
from sentinel_worker.repository.snapshot import RepositorySnapshot, SnapshotFile
from sentinel_worker.sandbox.policy import SandboxPolicy
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.trivy import (
    MAX_VULNERABILITIES,
    TEMPLATE,
    TrivyAdapter,
)
from trivy_support import (
    NOW,
    UPSTREAM,
    envelope,
    make_lock,
    package,
    report,
    result,
    verified,
    vulnerability,
)

FILES = {
    "java/pom.xml": b"<project/>",
    "js/package-lock.json": b"{}",
    "js/package.json": b"{}",
    "py/requirements.txt": b"x==1\n",
    "src/app.py": b"print(1)\n",
}


def snapshot(files: dict[str, bytes] | None = None) -> RepositorySnapshot:
    files = FILES if files is None else files
    return RepositorySnapshot(
        files=tuple(SnapshotFile(path, files[path]) for path in sorted(files)), skipped={}
    )


def adapter(age: timedelta = timedelta(hours=1), **lock: Any) -> TrivyAdapter:
    return TrivyAdapter(verified(make_lock(updated_at=NOW - age, **lock)), clock=lambda: NOW)


def run_with(
    report_bytes: bytes,
    files: dict[str, bytes] | None = None,
    scanner: TrivyAdapter | None = None,
    claimed: Any = None,
) -> dict[str, Any]:
    (artifact,) = (scanner or adapter()).interpret(
        exited(0, envelope(report_bytes)), snapshot(files), claimed or lease("repo", "TRIVY")
    )
    document: dict[str, Any] = json.loads(artifact.content)
    assert list(contracts.validator(contracts.FINDINGS_SCHEMA).iter_errors(document)) == []
    return document


def failure(
    stdout: bytes, code: int | None = 0, scanner: TrivyAdapter | None = None
) -> ScannerError:
    with pytest.raises(ScannerError) as raised:
        (scanner or adapter()).interpret(exited(code, stdout), snapshot(), lease("repo", "TRIVY"))
    assert raised.value.__context__ is None
    return raised.value


LODASH = package("sentinelpipe-fixture-vulnerable", "2.0.0")
DEVTOOL = package("sentinelpipe-fixture-devtool", "1.0.0", dev=True)
PARSER = package(
    "dev.sentinelpipe.fixture:vulnerable-parser",
    "1.4.0",
    package_id="dev.sentinelpipe.fixture:vulnerable-parser:1.4.0::82db81ce",
)
ROOT = package("dev.sentinelpipe.example:app", "1.0.0", relationship="root")
PYPKG = package("sentinelpipe-fixture-vulnerable", "3.0.0", package_id="")


def full_report() -> bytes:
    return report(
        result(
            "java/pom.xml",
            "pom",
            [ROOT, PARSER],
            [
                vulnerability(
                    "GHSA-2f2f-3g3g-4h4h",
                    PARSER,
                    fixed="1.4.2",
                    severity="CRITICAL",
                    cwe=["CWE-502"],
                )
            ],
        ),
        result(
            "js/package-lock.json",
            "npm",
            [DEVTOOL, LODASH],
            [
                vulnerability(
                    "CVE-2099-0001", LODASH, fixed="2.0.1", vendor_ids=["GHSA-5j5j-6m6m-7p7p"]
                ),
                vulnerability("GHSA-8q8q-9r9r-2v2v", DEVTOOL, fixed="1.0.5", severity="MEDIUM"),
            ],
        ),
        result(
            "py/requirements.txt",
            "pip",
            [PYPKG],
            [vulnerability("GHSA-3w3w-4x4x-5c5c", PYPKG, fixed="3.1.0, 2.9.9")],
        ),
    )


# --- Normalization ------------------------------------------------------------------------


def test_vulnerabilities_are_normalized_from_identifiers_only() -> None:
    document = run_with(full_report())

    assert document["scanner"]["name"] == "trivy"
    assert document["execution"]["status"] == "FINDINGS_DETECTED"
    by_rule = {finding["rule_id"]: finding for finding in document["findings"]}
    assert set(by_rule) == {
        "GHSA-2f2f-3g3g-4h4h",
        "CVE-2099-0001",
        "GHSA-8q8q-9r9r-2v2v",
        "GHSA-3w3w-4x4x-5c5c",
    }
    maven = by_rule["GHSA-2f2f-3g3g-4h4h"]
    assert maven["category"] == "DEPENDENCY_VULNERABILITY"
    assert maven["location"] == {
        "target": "DEPENDENCY_MANIFEST",
        "path": "java/pom.xml",
        "path_redacted": False,
        "start_line": None,
        "end_line": None,
        "start_column": None,
        "end_column": None,
    }
    assert maven["package"] == {
        "ecosystem": "maven",
        "name": "dev.sentinelpipe.fixture:vulnerable-parser",
        "installed_version": "1.4.0",
        "fixed_versions": ["1.4.2"],
        "development": False,
        "redacted": False,
    }
    assert maven["scanner_severity"] == "CRITICAL"
    assert maven["classification"] == {"cwe": ["CWE-502"], "owasp": []}
    # The scanner's label is kept verbatim; the normalized severity is a policy matter (M4).
    assert maven["severity"] is None
    assert maven["evidence"] == {"redacted": True, "excerpt": None}
    assert by_rule["CVE-2099-0001"]["advisory"] == {
        "aliases": ["GHSA-5j5j-6m6m-7p7p"],
        "data_source": "ghsa",
        "status": "fixed",
    }
    assert by_rule["GHSA-8q8q-9r9r-2v2v"]["package"]["development"] is True
    assert by_rule["GHSA-3w3w-4x4x-5c5c"]["package"]["fixed_versions"] == ["3.1.0", "2.9.9"]
    assert by_rule["GHSA-3w3w-4x4x-5c5c"]["package"]["ecosystem"] == "pypi"


def test_the_database_used_is_recorded_and_findings_are_not_a_decision() -> None:
    document = run_with(full_report(), scanner=adapter(source=UPSTREAM))

    database = document["vulnerability_database"]
    assert database["freshness"] == "FRESH"
    assert database["age_seconds"] == 3600
    assert database["schema_version"] == 2
    assert database["source"]["kind"] == "UPSTREAM_OCI"
    assert database["image"]["id"] == make_lock().image_id
    assert "decision" not in json.dumps(document).lower()
    assert "SYNTHETIC_VULNERABILITY_DATABASE" not in document["coverage"]["limitations"]
    assert {
        "ADVISORY_DATA_POINT_IN_TIME",
        "REACHABILITY_NOT_ANALYZED",
        "COMMIT_NOT_VERIFIED",
    } <= set(document["coverage"]["limitations"])


def test_a_synthetic_database_is_always_disclosed() -> None:
    document = run_with(report())

    assert "SYNTHETIC_VULNERABILITY_DATABASE" in document["coverage"]["limitations"]
    assert document["vulnerability_database"]["source"]["kind"] == "SYNTHETIC_FIXTURE"


def test_advisory_prose_and_raw_reports_never_reach_evidence() -> None:
    raw = full_report()
    document = run_with(raw)
    text = json.dumps(document)

    assert "lang-pkgs" not in text
    assert (
        document["execution"]["raw_report_sha256"] == __import__("hashlib").sha256(raw).hexdigest()
    )
    # The template asks Trivy for identifiers and versions only: no titles, descriptions,
    # references, CVSS vectors or dates.
    for field in (
        b"Title",
        b"Description",
        b"References",
        b"CVSS",
        b"PublishedDate",
        b"PrimaryURL",
    ):
        assert field not in TEMPLATE


def test_fingerprints_are_deterministic_line_independent_and_version_specific() -> None:
    claimed = lease("repo", "TRIVY")
    first = run_with(full_report(), claimed=claimed)
    second = run_with(full_report(), claimed=claimed)
    assert [f["fingerprint"] for f in first["findings"]] == [
        f["fingerprint"] for f in second["findings"]
    ]
    assert [f["id"] for f in first["findings"]] == [f["id"] for f in second["findings"]]

    other = package("sentinelpipe-fixture-vulnerable", "2.0.0-rc.1")
    changed = run_with(
        report(
            result("js/package-lock.json", "npm", [other], [vulnerability("CVE-2099-0001", other)])
        )
    )
    original = {f["fingerprint"] for f in first["findings"] if f["rule_id"] == "CVE-2099-0001"}
    assert {f["fingerprint"] for f in changed["findings"]}.isdisjoint(original)


def test_the_same_advisory_for_the_same_package_is_merged() -> None:
    nested = package("sentinelpipe-fixture-vulnerable", "2.0.0", package_id="nested@2.0.0")
    document = run_with(
        report(
            result(
                "js/package-lock.json",
                "npm",
                [LODASH, nested],
                [
                    vulnerability("CVE-2099-0001", LODASH),
                    vulnerability("CVE-2099-0001", nested),
                ],
            )
        )
    )

    assert document["finding_count"] == 1
    assert document["findings"][0]["occurrences"] == 2


# --- Coverage -----------------------------------------------------------------------------


def test_a_fully_analyzed_lockfile_only_repository_is_complete() -> None:
    files = {"js/package-lock.json": b"{}", "js/package.json": b"{}", "README.md": b"x"}
    document = run_with(
        report(result("js/package-lock.json", "npm", [LODASH])),
        files,
        scanner=adapter(source=UPSTREAM),
    )

    coverage = document["coverage"]
    assert document["execution"]["status"] == "NO_FINDINGS"
    assert coverage["complete"] is True
    assert (
        coverage["files_supported"],
        coverage["files_analyzed"],
        coverage["files_unsupported"],
    ) == (1, 1, 2)
    assert coverage["dependencies"]["packages"] == 1


def test_a_manifest_without_a_result_is_not_analyzed_never_clean() -> None:
    # Trivy reports malformed and dependency-free lockfiles alike: no result, exit 0.
    document = run_with(report(result("js/package-lock.json", "npm", [LODASH])))

    coverage = document["coverage"]
    assert coverage["complete"] is False
    assert coverage["files_not_analyzed"] == 2
    assert coverage["not_analyzed_reasons"]["scanner_skipped"] == 2
    assert "FILES_NOT_ANALYZED" in coverage["limitations"]


def test_partial_formats_and_unresolved_versions_make_coverage_incomplete() -> None:
    unresolved = package("org.example:managed-by-parent", "")
    files = {"java/pom.xml": b"<project/>"}
    document = run_with(
        report(result("java/pom.xml", "pom", [ROOT, unresolved])),
        files,
        scanner=adapter(source=UPSTREAM),
    )

    coverage = document["coverage"]
    assert coverage["complete"] is False
    assert coverage["dependencies"]["packages_unresolved"] == 1  # the root is not counted
    assert coverage["dependencies"]["manifests_partial"] == 1
    assert {"PARTIAL_DEPENDENCY_RESOLUTION", "UNRESOLVED_DEPENDENCY_VERSIONS"} <= set(
        coverage["limitations"]
    )


@pytest.mark.parametrize(
    ("files", "missing"),
    [
        ({"web/package.json": b"{}"}, 1),
        ({"package-lock.json": b"{}", "packages/a/package.json": b"{}"}, 0),  # workspace
        ({"node_modules/x/package.json": b"{}", "package-lock.json": b"{}"}, 0),
        ({"pyproject.toml": b"", "setup.py": b"", "Pipfile": b""}, 3),
        ({"svc/build.gradle.kts": b"", "svc/gradle.lockfile": b""}, 0),
        ({"svc/build.gradle": b""}, 1),
    ],
)
def test_declarations_without_a_lockfile_are_flagged(files: dict[str, bytes], missing: int) -> None:
    analyzed = [
        result(path, "npm" if path.endswith("package-lock.json") else "gradle", [LODASH])
        for path in files
        if path.endswith(("package-lock.json", "gradle.lockfile"))
    ]
    document = run_with(report(*analyzed), files)

    assert document["coverage"]["dependencies"]["manifests_lockfile_missing"] == missing
    assert ("DEPENDENCY_LOCKFILE_MISSING" in document["coverage"]["limitations"]) is bool(missing)
    if missing:
        assert document["coverage"]["complete"] is False


def test_unsupported_formats_and_binary_artifacts_are_counted_not_ignored() -> None:
    files = {
        "go.mod": b"",
        "Cargo.lock": b"",
        "requirements-dev.txt": b"",
        "app.csproj": b"",
        "bun.lockb": b"",
        "lib/app.jar": b"PK",
        "dist/x.whl": b"PK",
    }
    document = run_with(report(), files)

    dependencies = document["coverage"]["dependencies"]
    assert dependencies["unsupported_dependency_files"] == 5
    assert dependencies["binary_artifacts"] == 2
    assert {
        "UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT",
        "BINARY_ARTIFACTS_NOT_ANALYZED",
        "NO_SUPPORTED_FILES",
    } <= set(document["coverage"]["limitations"])
    assert document["coverage"]["complete"] is False


def test_a_repository_without_dependency_files_is_flagged_not_clean() -> None:
    document = run_with(report(), {"src/app.py": b"print(1)\n"})

    assert document["execution"]["status"] == "NO_FINDINGS"
    assert document["coverage"]["complete"] is False
    assert "NO_SUPPORTED_FILES" in document["coverage"]["limitations"]


# --- Freshness ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "freshness"),
    [
        (timedelta(0), "FRESH"),
        (timedelta(hours=48), "FRESH"),
        (timedelta(hours=48, seconds=1), "STALE"),
        (timedelta(days=7), "STALE"),
        (-timedelta(minutes=30), "FRESH"),
    ],
)
def test_database_freshness_is_explicit(age: timedelta, freshness: str) -> None:
    document = run_with(
        report(result("js/package-lock.json", "npm", [LODASH])),
        {"js/package-lock.json": b"{}"},
        scanner=adapter(age, source=UPSTREAM),
    )

    assert document["vulnerability_database"]["freshness"] == freshness
    stale = freshness == "STALE"
    assert ("VULNERABILITY_DB_STALE" in document["coverage"]["limitations"]) is stale
    assert document["coverage"]["complete"] is not stale


@pytest.mark.parametrize(
    ("age", "code"),
    [
        (timedelta(days=7, seconds=1), "VULNERABILITY_DB_EXPIRED"),
        (timedelta(days=400), "VULNERABILITY_DB_EXPIRED"),
        (-timedelta(hours=2), "VULNERABILITY_DB_FROM_FUTURE"),
    ],
)
def test_an_expired_or_future_database_fails_the_scan(age: timedelta, code: str) -> None:
    error = failure(envelope(report()), scanner=adapter(age))

    assert error.code == code
    assert error.reason is FailureReason.SCANNER_ERROR


# --- Failures -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected", "reason"),
    [
        (70, "TRIVY_FAILED", FailureReason.SCANNER_ERROR),
        (71, "INPUT_EXTRACTION_FAILED", FailureReason.SCANNER_ERROR),
        (72, "INPUT_VERIFICATION_FAILED", FailureReason.SCANNER_ERROR),
        (73, "REPORT_MISSING", FailureReason.SCANNER_ERROR),
        (74, "REPORT_TOO_LARGE", FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (75, "INPUT_REJECTED", FailureReason.SCANNER_ERROR),
        (76, "VULNERABILITY_DB_INVALID", FailureReason.SCANNER_ERROR),
        (1, "UNEXPECTED_EXIT_CODE", FailureReason.SCANNER_ERROR),
        (137, "TERMINATED", FailureReason.SANDBOX_ERROR),
        (None, "TERMINATED", FailureReason.SANDBOX_ERROR),
    ],
)
def test_failures_are_never_clean_scans(
    code: int | None, expected: str, reason: FailureReason
) -> None:
    # Even a well-formed, empty report on stdout cannot turn a failure into a result.
    error = failure(envelope(report()), code=code)

    assert (error.code, error.reason) == (expected, reason)


def _with(entry: dict[str, Any], **changes: Any) -> dict[str, Any]:
    return {**entry, **changes}


@pytest.mark.parametrize(
    ("stdout", "code"),
    [
        (b"", "INVALID_OUTPUT"),
        (envelope(report(), name="other.json"), "INVALID_OUTPUT"),
        (envelope(b"{not json"), "INVALID_REPORT"),
        (envelope(b'{"version":"0.75.0","results":[],"results":[]}'), "INVALID_REPORT"),
        (envelope(b'{"version":"0.75.0","results":[],"extra":1}'), "INVALID_REPORT"),
        (envelope(report(version="0.74.0")), "UNEXPECTED_VERSION"),
        (envelope(report(result("../etc/passwd", "npm", []))), "UNKNOWN_PATH"),
        (envelope(report(result("src/app.py", "npm", []))), "UNKNOWN_PATH"),
        (envelope(report(result("js/package-lock.json", "pip", []))), "UNEXPECTED_RESULT"),
        (envelope(report(result("js/package-lock.json", "gomod", []))), "UNEXPECTED_RESULT"),
        (
            envelope(
                report(_with(result("js/package-lock.json", "npm", []), **{"class": "secret"}))
            ),
            "UNEXPECTED_RESULT",
        ),
        (
            envelope(
                report(
                    result("js/package-lock.json", "npm", []),
                    result("js/package-lock.json", "npm", []),
                )
            ),
            "UNKNOWN_PATH",
        ),
        (
            envelope(report(result("js/package-lock.json", "npm", [_with(LODASH, dev="yes")]))),
            "INVALID_REPORT",
        ),
        (
            envelope(
                report(
                    result(
                        "js/package-lock.json", "npm", [], [vulnerability("CVE-2099-0001", LODASH)]
                    )
                )
            ),
            "UNKNOWN_PACKAGE",
        ),
        (
            envelope(
                report(
                    result(
                        "js/package-lock.json",
                        "npm",
                        [LODASH],
                        [vulnerability("CVE-2099-0001", LODASH, pkg_name="other")],
                    )
                )
            ),
            "INCONSISTENT_PACKAGE",
        ),
        (
            envelope(
                report(
                    result(
                        "js/package-lock.json", "npm", [LODASH], [vulnerability("<script>", LODASH)]
                    )
                )
            ),
            "INVALID_ADVISORY",
        ),
        (
            envelope(
                report(
                    result(
                        "js/package-lock.json",
                        "npm",
                        [LODASH],
                        [vulnerability("CVE-2099-0001", LODASH, severity="SEVERE")],
                    )
                )
            ),
            "INVALID_ADVISORY",
        ),
        (
            envelope(
                report(
                    result(
                        "js/package-lock.json",
                        "npm",
                        [LODASH],
                        [vulnerability("CVE-2099-0001", LODASH, cwe=["CWE-79 or 89"])],
                    )
                )
            ),
            "INVALID_ADVISORY",
        ),
        (
            envelope(
                report(
                    result(
                        "js/package-lock.json",
                        "npm",
                        [LODASH],
                        [_with(vulnerability("CVE-2099-0001", LODASH), title="x")],
                    )
                )
            ),
            "INVALID_REPORT",
        ),
        (
            envelope(report(result("js/package-lock.json", "npm", [[*LODASH.values(), "extra"]]))),
            "INVALID_REPORT",
        ),
        (
            envelope(
                report(result("js/package-lock.json", "npm", [LODASH], [{"id": "CVE-2099-0001"}]))
            ),
            "INVALID_REPORT",
        ),
    ],
)
def test_malformed_or_unexpected_reports_fail_closed(stdout: bytes, code: str) -> None:
    assert failure(stdout).code == code


def test_report_bounds_are_enforced_not_truncated() -> None:
    many = [
        [f"CVE-2099-{index:04d}", None, "", "a", "1", "", "", "LOW", None, None]
        for index in range(MAX_VULNERABILITIES + 1)
    ]
    raw = report(result("js/package-lock.json", "npm", [LODASH], many))
    assert len(raw) < 1024 * 1024
    error = failure(envelope(raw))

    assert (error.code, error.reason) == (
        "FINDINGS_LIMIT_EXCEEDED",
        FailureReason.RESOURCE_LIMIT_EXCEEDED,
    )


# --- Privacy ------------------------------------------------------------------------------


def test_token_like_package_values_are_redacted_and_disclosed() -> None:
    token = "ghp_" + "Q" * 36
    sneaky = package("sentinelpipe-fixture-vulnerable", f"2.0.0-{token}")
    document = run_with(
        report(
            result(
                "js/package-lock.json", "npm", [sneaky], [vulnerability("CVE-2099-0001", sneaky)]
            )
        )
    )

    assert token not in json.dumps(document)
    assert document["findings"][0]["package"]["installed_version"] == "2.0.0-[redacted]"
    assert document["findings"][0]["package"]["redacted"] is True
    assert "PACKAGE_VALUES_REDACTED" in document["coverage"]["limitations"]


@pytest.mark.parametrize("value", ["2.0.0\n", "2.0.0\x1b[31m", "", "x" * 300])
def test_package_values_with_control_characters_or_unbounded_length_fail(value: str) -> None:
    bad = package("sentinelpipe-fixture-vulnerable", value)
    error = failure(
        envelope(
            report(
                result("js/package-lock.json", "npm", [bad], [vulnerability("CVE-2099-0001", bad)])
            )
        )
    )

    assert error.code == "INVALID_PACKAGE"


def test_secret_shaped_manifest_paths_are_redacted() -> None:
    path = "ghp_" + "Z" * 36 + "/package-lock.json"
    document = run_with(
        report(result(path, "npm", [LODASH], [vulnerability("CVE-2099-0001", LODASH)])),
        {path: b"{}"},
    )

    location = document["findings"][0]["location"]
    assert location["path_redacted"] is True
    assert "ghp_" not in json.dumps(document)


# --- Input --------------------------------------------------------------------------------


def test_only_dependency_files_and_the_template_reach_the_sandbox() -> None:
    files = {
        **FILES,
        "trivy.yaml": b"severity: [LOW]\n",
        ".trivyignore": b"CVE-2099-0001\n",
        ".trivyignore.yaml": b"vulnerabilities: []\n",
        "openvex.json": b"{}",
        ".vex/x.json": b"{}",
        "go.mod": b"module x\n",
    }
    scanner = adapter()
    with tarfile.open(fileobj=io.BytesIO(scanner.stdin(snapshot(files)))) as archive:
        names = sorted(member.name for member in archive if member.isfile())

    assert names == [
        "config/report.tpl",
        "repo/java/pom.xml",
        "repo/js/package-lock.json",
        "repo/js/package.json",
        "repo/py/requirements.txt",
    ]
    command = scanner.command(snapshot(files))
    assert command[:2] == ["/bin/sh", "-c"]
    assert command[4] == "4"  # files in the archive's repo/
    assert command[7] == make_lock().metadata_sha256
    assert command[8] == str(make_lock().trivy_db_size)
    assert command[9] == hashlib.sha256(TEMPLATE).hexdigest()


def test_the_sandbox_runs_only_the_verified_image() -> None:
    scanner = adapter()
    assert scanner.policy().image == make_lock().image_id
    assert scanner.sandbox_image == make_lock().image_id
    with pytest.raises(ValueError, match="verified local image"):
        SandboxPolicy(image="sha256:" + "99" * 32)


# --- Settings -----------------------------------------------------------------------------


def _env(tmp_path: Any, **extra: str) -> dict[str, str]:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir(exist_ok=True)
    return {
        "SENTINEL_WORKER_DB_USERNAME": "w",
        "SENTINEL_WORKER_DB_PASSWORD": "x",
        "SENTINEL_WORKER_TRIVY_ENABLED": "true",
        "SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": str(fixtures),
        "SENTINEL_WORKER_DOCKER_CLI": sys.executable,
        **extra,
    }


def test_trivy_requires_a_valid_lock(tmp_path: Any) -> None:
    with pytest.raises(ConfigurationError, match="TRIVY_IMAGE_LOCK"):
        ExecutionSettings.from_env(Environment.DEVELOPMENT, _env(tmp_path))
    bad = tmp_path / "bad.lock"
    bad.write_bytes(b'{"schema":"other"}')
    with pytest.raises(ConfigurationError, match="LOCK_INVALID"):
        ExecutionSettings.from_env(
            Environment.DEVELOPMENT, _env(tmp_path, SENTINEL_WORKER_TRIVY_IMAGE_LOCK=str(bad))
        )
    good = tmp_path / "good.lock"
    good.write_bytes(make_lock().to_bytes())
    settings = ExecutionSettings.from_env(
        Environment.DEVELOPMENT, _env(tmp_path, SENTINEL_WORKER_TRIVY_IMAGE_LOCK=str(good))
    )
    assert settings.trivy_enabled
    assert settings.trivy_image_lock == str(good)


def test_trivy_is_refused_in_production(tmp_path: Any) -> None:
    with pytest.raises(ConfigurationError, match="not permitted in production"):
        ExecutionSettings.from_env(Environment.PRODUCTION, _env(tmp_path))


def test_other_scanners_never_load_the_trivy_modules(tmp_path: Any) -> None:
    code = (
        "import sys\n"
        "from sentinel_worker.config import Environment\n"
        "from sentinel_worker.execution.settings import ExecutionSettings\n"
        f"env = {{'SENTINEL_WORKER_DB_USERNAME': 'w', 'SENTINEL_WORKER_DB_PASSWORD': 'x',"
        f" 'SENTINEL_WORKER_GITLEAKS_ENABLED': 'true',"
        f" 'SENTINEL_WORKER_SEMGREP_ENABLED': 'true',"
        f" 'SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR': {str(tmp_path)!r},"
        f" 'SENTINEL_WORKER_DOCKER_CLI': {sys.executable!r}}}\n"
        "ExecutionSettings.from_env(Environment.DEVELOPMENT, env)\n"
        "loaded = [m for m in sys.modules if 'trivy' in m]\n"
        "assert loaded == [], loaded\n"
    )
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, check=False)  # noqa: S603

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")


# --- Security review S3 (final audit) ----------------------------------------------------------


def test_short_credentials_in_versions_are_redacted() -> None:
    # Regression S3-5: only 32+ character runs were redacted; an AWS-style key id (20
    # characters) in a Maven qualifier inside the affected range reached evidence.
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    sneaky = package("dev.sentinelpipe.fixture:vulnerable-parser", f"1.4.0-{key}")
    document = run_with(
        report(
            result("java/pom.xml", "pom", [sneaky], [vulnerability("GHSA-2f2f-3g3g-4h4h", sneaky)])
        )
    )

    assert key not in json.dumps(document)
    assert document["findings"][0]["package"]["installed_version"] == "[redacted]"
    assert "PACKAGE_VALUES_REDACTED" in document["coverage"]["limitations"]


@pytest.mark.parametrize(
    ("kind", "target", "version"),
    [
        ("npm", "js/package-lock.json", "file:../local-copy"),
        ("npm", "js/package-lock.json", "github:example/repo#main"),
        ("npm", "js/package-lock.json", "not-a-version"),
        ("pip", "py/requirements.txt", "latest"),
        ("pom", "java/pom.xml", "${revision}"),
    ],
)
def test_versions_that_cannot_be_compared_are_counted_as_unresolved(
    kind: str, target: str, version: str
) -> None:
    # Regression S3-4: a version outside its ecosystem's grammar cannot match any advisory;
    # it was counted as resolved, so the scan looked complete and clean.
    odd = package("sentinelpipe-fixture-vulnerable", version)
    document = run_with(report(result(target, kind, [odd])), {target: b"x"})

    coverage = document["coverage"]
    assert coverage["dependencies"]["packages_unresolved"] == 1
    assert "UNRESOLVED_DEPENDENCY_VERSIONS" in coverage["limitations"]
    assert coverage["complete"] is False


@pytest.mark.parametrize(
    ("kind", "target", "version"),
    [
        ("npm", "js/package-lock.json", "2.0.0-rc.1"),
        ("pip", "py/requirements.txt", "1.0.post1"),
        ("pip", "py/requirements.txt", "2.0.0rc1"),
        ("pom", "java/pom.xml", "1.4.0-SNAPSHOT"),
    ],
)
def test_ecosystem_versions_are_comparable(kind: str, target: str, version: str) -> None:
    usual = package("sentinelpipe-fixture-vulnerable", version)
    document = run_with(report(result(target, kind, [usual])), {target: b"x"})

    assert document["coverage"]["dependencies"]["packages_unresolved"] == 0


@pytest.mark.parametrize(
    ("name", "flagged"),
    [
        ("products-cmfplone", True),
        ("Products.CMFPlone", True),
        ("jupyter_server", False),
        ("django", False),
    ],
)
def test_pypi_names_trivy_may_not_match_are_disclosed(name: str, flagged: bool) -> None:
    # Regression S3-8: Trivy 0.75.0 normalizes case and "_" but not ".", so a normalized
    # lockfile name missed every advisory filed under the dotted name (real database).
    entry = package(name, "1.0.0", package_id="")
    document = run_with(
        report(result("py/poetry.lock", "poetry", [entry])),
        {"py/poetry.lock": b"x"},
        scanner=adapter(source=UPSTREAM),
    )

    limitations = document["coverage"]["limitations"]
    assert ("PYPI_NAME_MATCHING_UNVERIFIED" in limitations) is flagged
    assert document["coverage"]["complete"] is not flagged


def test_pipfile_development_dependencies_are_disclosed_as_not_analyzed() -> None:
    # Regression S3-7: Trivy 0.75.0 ignores Pipfile.lock "develop" even with
    # --include-dev-deps; a vulnerable development dependency was missed while coverage
    # was complete.
    lock = json.dumps({"_meta": {}, "default": {"django": {"version": "==4.2.0"}},
                       "develop": {"pytest": {"version": "==8.0.0"}}}).encode()  # fmt: skip
    entry = package("django", "4.2.0", package_id="")
    files = {"Pipfile.lock": lock}
    document = run_with(report(result("Pipfile.lock", "pipenv", [entry])), files,
                        scanner=adapter(source=UPSTREAM))  # fmt: skip
    empty = json.dumps({"_meta": {}, "default": {}, "develop": {}}).encode()
    without = run_with(report(result("Pipfile.lock", "pipenv", [entry])), {"Pipfile.lock": empty},
                       scanner=adapter(source=UPSTREAM))  # fmt: skip

    assert "DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED" in document["coverage"]["limitations"]
    assert document["coverage"]["complete"] is False
    assert "DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED" not in without["coverage"]["limitations"]
    assert without["coverage"]["complete"] is True

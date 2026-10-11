# ruff: noqa: E501 - synthetic lockfile and archive fixtures are kept on readable lines.
"""Trivy in real sandbox containers with a verified, embedded synthetic database (ADR-0012).

The image is built and verified by the production code path from the synthetic database
(``scripts/trivy/build-fixture-db.sh``; fictitious ``sentinelpipe-fixture-*`` packages).
Covers:

* vulnerable and clean fixtures for Maven (pom.xml, Gradle lockfile), npm (package-lock,
  yarn, pnpm) and Python (requirements.txt, Pipfile.lock, poetry.lock, uv.lock);
* development dependencies;
* missing lockfiles, invalid manifests, unsupported formats, Java archives, malformed and
  token-shaped versions;
* repository-controlled Trivy configuration and ignore files;
* database states: stale, expired, corrupted, truncated, and a database that differs
  from the verified lock inside the sandbox;
* image verification against the real image, including the bare base image;
* oversized output, memory exhaustion, hostile archives;
* cancellation, concurrent executions of different tenants, isolation and cleanup.

Requires Docker, the pinned base image and SENTINEL_TEST_TRIVY_DB_DIR (CI sandbox job).
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from scanner_support import lease, make_repository, synthetic_github_token
from sentinel_worker.execution.leases import FailureReason, JobOutcome
from sentinel_worker.execution.runner import ExecutionResult
from sentinel_worker.repository.snapshot import (
    LocalFixtureRepositorySource,
    RepositorySnapshot,
    SnapshotFile,
)
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
from sentinel_worker.sandbox.isolation import observations, probe_command, unexpected_mounts, verify
from sentinel_worker.sandbox.policy import JOB_LABEL, SANDBOX_LABEL, TRIVY_BASE_IMAGE
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.trivy import TEMPLATE, TrivyAdapter
from sentinel_worker.scanners.trivy_image import ImageError, VerifiedImage, verify_image
from trivy_images import TrivyImages
from trivy_support import (
    MAVEN_ADVISORY,
    NPM_ADVISORY,
    NPM_ALIAS,
    NPM_DEV_ADVISORY,
    PYPI_ADVISORY,
    PYPI_UNFIXED_ADVISORY,
    gradle_lock,
    npm_lock,
    pipfile_lock,
    poetry_lock,
    pom,
    pyproject_poetry,
    requirements,
)

pytestmark = pytest.mark.sandbox

TOKEN = synthetic_github_token(73)


@pytest.fixture(scope="module")
def images(trivy_images: TrivyImages) -> TrivyImages:
    return trivy_images


def adapter(image: VerifiedImage) -> TrivyAdapter:
    return TrivyAdapter(image)


def sandbox(images: TrivyImages, variant: str = "fresh", **overrides: Any) -> DockerSandbox:
    policy = dataclasses.replace(
        adapter(images.image(variant)).policy(timeout_seconds=120), **overrides
    )
    return DockerSandbox(images.cli, policy, monitor_interval=0.5)


def execute(
    images: TrivyImages,
    root: Path,
    name: str,
    variant: str = "fresh",
    scanner: TrivyAdapter | None = None,
    **overrides: Any,
) -> ExecutionResult:
    scanner = scanner or adapter(images.image(variant))
    box = DockerSandbox(
        images.cli,
        dataclasses.replace(scanner.policy(timeout_seconds=120), **overrides),
        monitor_interval=0.5,
    )
    executor = ScannerExecutor(box, scanner, LocalFixtureRepositorySource(root))
    return executor.execute(lease(name, "TRIVY"), threading.Event())


def scan(images: TrivyImages, root: Path, name: str, variant: str = "fresh") -> dict[str, Any]:
    result = execute(images, root, name, variant)
    assert result.outcome is JobOutcome.COMPLETED, result
    (artifact,) = result.artifacts
    assert TOKEN.encode() not in artifact.content
    # Advisory prose of the synthetic database never reaches evidence.
    assert b"SYNTHETIC SentinelPipe test advisory" not in artifact.content
    document: dict[str, Any] = json.loads(artifact.content)
    return document


def advisories(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {
        (f["rule_id"], f["package"]["ecosystem"], f["location"]["path"])
        for f in document["findings"]
    }


def containers(cli: DockerCli, label: str) -> list[str]:
    result = cli.call(["ps", "--all", "--filter", f"label={label}", "--format", "{{.Names}}"])
    return [line for line in result.stdout.decode().splitlines() if line]


# --- Ecosystems: vulnerable and clean fixtures ------------------------------------------------

VULNERABLE: dict[str, tuple[dict[str, str], set[tuple[str, str, str]]]] = {
    "maven-pom": ({"pom.xml": pom()}, {(MAVEN_ADVISORY, "maven", "pom.xml")}),
    "maven-gradle": (
        {"build.gradle": "", "gradle.lockfile": gradle_lock()},
        {(MAVEN_ADVISORY, "maven", "gradle.lockfile")},
    ),
    "npm-package-lock": (
        {"package.json": "{}", "package-lock.json": npm_lock()},
        {
            (NPM_ADVISORY, "npm", "package-lock.json"),
            (NPM_DEV_ADVISORY, "npm", "package-lock.json"),
        },
    ),
    "npm-yarn": (
        {
            "package.json": json.dumps(
                {"dependencies": {"sentinelpipe-fixture-vulnerable": "2.0.0"}}
            ),
            "yarn.lock": (
                "# yarn lockfile v1\n\n"
                'sentinelpipe-fixture-vulnerable@2.0.0:\n  version "2.0.0"\n'
                '  resolved "https://registry.yarnpkg.com/x/-/x-2.0.0.tgz"\n'
            ),
        },
        {(NPM_ADVISORY, "npm", "yarn.lock")},
    ),
    "npm-pnpm": (
        {
            "pnpm-lock.yaml": (
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n"
                "      sentinelpipe-fixture-vulnerable:\n        specifier: 2.0.0\n"
                "        version: 2.0.0\n\npackages:\n\n"
                "  sentinelpipe-fixture-vulnerable@2.0.0:\n"
                "    resolution: {integrity: sha512-AAAA}\n\nsnapshots:\n\n"
                "  sentinelpipe-fixture-vulnerable@2.0.0: {}\n"
            )
        },
        {(NPM_ADVISORY, "npm", "pnpm-lock.yaml")},
    ),
    "python-requirements": (
        {"requirements.txt": requirements()},
        {
            (PYPI_ADVISORY, "pypi", "requirements.txt"),
            (PYPI_UNFIXED_ADVISORY, "pypi", "requirements.txt"),
        },
    ),
    "python-pipenv": ({"Pipfile.lock": pipfile_lock()}, {(PYPI_ADVISORY, "pypi", "Pipfile.lock")}),
    "python-poetry": (
        {"pyproject.toml": pyproject_poetry(), "poetry.lock": poetry_lock()},
        {(PYPI_ADVISORY, "pypi", "poetry.lock")},
    ),
    "python-uv": (
        {
            "uv.lock": (
                'version = 1\nrequires-python = ">=3.12"\n\n[[package]]\n'
                'name = "sentinelpipe-fixture-vulnerable"\nversion = "3.0.0"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
            )
        },
        {(PYPI_ADVISORY, "pypi", "uv.lock")},
    ),
}


@pytest.mark.parametrize("ecosystem", sorted(VULNERABLE))
def test_vulnerable_fixtures_report_exactly_their_advisories(
    images: TrivyImages, tmp_path: Path, ecosystem: str
) -> None:
    files, expected = VULNERABLE[ecosystem]
    make_repository(tmp_path, ecosystem, files)

    document = scan(images, tmp_path, ecosystem)

    assert advisories(document) == expected
    assert document["execution"]["status"] == "FINDINGS_DETECTED"
    assert document["coverage"]["files_not_analyzed"] == 0
    assert "SYNTHETIC_VULNERABILITY_DATABASE" in document["coverage"]["limitations"]
    for finding in document["findings"]:
        assert finding["evidence"] == {"redacted": True, "excerpt": None}
        assert finding["severity"] is None
        assert finding["scanner_severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_advisory_aliases_fix_versions_and_development_dependencies(
    images: TrivyImages, tmp_path: Path
) -> None:
    make_repository(
        tmp_path, "npm", {"package-lock.json": npm_lock(), "requirements.txt": requirements()}
    )

    findings = {f["rule_id"]: f for f in scan(images, tmp_path, "npm")["findings"]}

    assert findings[NPM_ADVISORY]["advisory"]["aliases"] == [NPM_ALIAS]
    assert findings[NPM_ADVISORY]["package"]["fixed_versions"] == ["2.0.1"]
    assert findings[NPM_ADVISORY]["package"]["development"] is False
    assert findings[NPM_DEV_ADVISORY]["package"]["development"] is True
    assert findings[PYPI_UNFIXED_ADVISORY]["package"]["fixed_versions"] == []


CLEAN = {
    "pom.xml": pom("1.4.2"),
    "gradle.lockfile": gradle_lock("1.4.2"),
    "build.gradle": "",
    "web/package.json": "{}",
    "web/package-lock.json": npm_lock("2.0.1", "1.0.5"),
    "py/requirements.txt": "sentinelpipe-fixture-vulnerable==3.1.0\n",
    "py/Pipfile.lock": pipfile_lock("3.1.0"),
}


def test_clean_fixtures_have_no_findings_and_report_partial_formats(
    images: TrivyImages, tmp_path: Path
) -> None:
    make_repository(tmp_path, "clean", CLEAN)

    document = scan(images, tmp_path, "clean")
    coverage = document["coverage"]

    assert document["execution"]["status"] == "NO_FINDINGS"
    assert coverage["files_supported"] == coverage["files_analyzed"] == 5
    # pom.xml and requirements.txt resolve only part of the graph offline: never complete.
    assert coverage["dependencies"]["manifests_partial"] == 2
    assert coverage["complete"] is False
    assert "PARTIAL_DEPENDENCY_RESOLUTION" in coverage["limitations"]


def test_a_lockfile_only_repository_can_be_complete(images: TrivyImages, tmp_path: Path) -> None:
    make_repository(
        tmp_path, "locked", {"package.json": "{}", "package-lock.json": npm_lock("2.0.1", "1.0.5")}
    )

    coverage = scan(images, tmp_path, "locked")["coverage"]

    assert coverage["complete"] is True
    assert coverage["dependencies"]["packages_development"] == 1


def test_scans_are_deterministic(images: TrivyImages, tmp_path: Path) -> None:
    make_repository(tmp_path, "twice", {**VULNERABLE["npm-package-lock"][0], "pom.xml": pom()})

    first, second = scan(images, tmp_path, "twice"), scan(images, tmp_path, "twice")

    assert [f["fingerprint"] for f in first["findings"]] == [
        f["fingerprint"] for f in second["findings"]
    ]
    assert first["coverage"] == second["coverage"]
    assert first["execution"]["raw_report_sha256"] == second["execution"]["raw_report_sha256"]


# --- Coverage gaps: never silent -----------------------------------------------------------


def test_declarations_without_lockfiles_are_flagged_not_clean(
    images: TrivyImages, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "nolock",
        {
            "web/package.json": json.dumps(
                {"dependencies": {"sentinelpipe-fixture-vulnerable": "2.0.0"}}
            ),
            "svc/pyproject.toml": pyproject_poetry(),
            "svc/setup.py": "from setuptools import setup\nsetup()\n",
        },
    )

    document = scan(images, tmp_path, "nolock")
    coverage = document["coverage"]

    assert document["finding_count"] == 0
    assert coverage["dependencies"]["manifests_lockfile_missing"] == 3
    assert {"DEPENDENCY_LOCKFILE_MISSING", "NO_SUPPORTED_FILES"} <= set(coverage["limitations"])
    assert coverage["complete"] is False


@pytest.mark.parametrize(
    "content",
    ["{not json", "", "\x00\x01\x02binary", '{"lockfileVersion": 3, "packages": "oops"}'],
    ids=["malformed", "empty", "binary", "wrong-shape"],
)
def test_invalid_lockfiles_are_not_analyzed_never_clean(
    images: TrivyImages, tmp_path: Path, content: str
) -> None:
    make_repository(
        tmp_path, "invalid", {"package-lock.json": content, "pom.xml": "<project><broken"}
    )

    result = execute(images, tmp_path, "invalid")

    if result.outcome is JobOutcome.FAILED:
        # Trivy may also reject the input outright; that is a failure, never a clean scan.
        assert result.failure_reason is FailureReason.SCANNER_ERROR
        return
    coverage = json.loads(result.artifacts[0].content)["coverage"]
    assert coverage["files_not_analyzed"] == 2
    assert coverage["not_analyzed_reasons"]["scanner_skipped"] == 2
    assert coverage["complete"] is False


def test_unresolvable_and_malformed_versions_are_visible(
    images: TrivyImages, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "versions",
        {
            "pom.xml": pom("${undefined.property}"),
            "package-lock.json": npm_lock(vulnerable="not-a-version", devtool="../../etc/passwd"),
        },
    )

    document = scan(images, tmp_path, "versions")
    coverage = document["coverage"]

    # An unresolvable Maven version is counted; npm versions Trivy cannot compare produce
    # no advisory match (documented residual risk), and nothing unsafe reaches evidence.
    assert coverage["dependencies"]["packages_unresolved"] >= 1
    assert "UNRESOLVED_DEPENDENCY_VERSIONS" in coverage["limitations"]
    assert coverage["complete"] is False
    assert "../../etc/passwd" not in json.dumps(document)


def test_unsupported_formats_and_java_archives_never_reach_trivy(
    images: TrivyImages, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "other",
        {
            "go.mod": "module x\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n",
            "Cargo.lock": "version = 3\n",
            "lib/app.jar": b"PK\x03\x04not-a-real-jar",
            "requirements-dev.txt": "sentinelpipe-fixture-vulnerable==3.0.0\n",
        },
    )

    document = scan(images, tmp_path, "other")
    dependencies = document["coverage"]["dependencies"]

    # No Java DB is needed or downloaded: archives are not analyzed in filesystem mode.
    assert document["finding_count"] == 0
    assert dependencies["unsupported_dependency_files"] == 3
    assert dependencies["binary_artifacts"] == 1
    assert {"UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT", "BINARY_ARTIFACTS_NOT_ANALYZED"} <= set(
        document["coverage"]["limitations"]
    )


def test_repository_controlled_trivy_configuration_is_ignored(
    images: TrivyImages, tmp_path: Path
) -> None:
    files = {
        "package-lock.json": npm_lock(),
        "trivy.yaml": (
            "severity: [LOW]\nvulnerability:\n  ignore-unfixed: true\nscan:\n  skip-files: ['**']\n"
        ),
        ".trivyignore": f"{NPM_ADVISORY}\n{NPM_DEV_ADVISORY}\n",
        ".trivyignore.yaml": f"vulnerabilities:\n  - id: {NPM_ADVISORY}\n",
        "openvex.json": json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{"vulnerability": {"name": NPM_ADVISORY}, "status": "not_affected"}],
            }
        ),
        ".vex/statements.json": "{}",
    }
    make_repository(tmp_path, "suppress", files)

    document = scan(images, tmp_path, "suppress")

    assert {NPM_ADVISORY, NPM_DEV_ADVISORY} <= {f["rule_id"] for f in document["findings"]}


def test_secret_shaped_paths_and_versions_never_reach_evidence(
    images: TrivyImages, tmp_path: Path
) -> None:
    # A Maven qualifier keeps the version inside the affected range (1.4.0 < x < 1.4.2);
    # an npm prerelease would not match the advisory at all (node-semver semantics).
    make_repository(tmp_path, "secrets", {f"{TOKEN}/pom.xml": pom(f"1.4.0-{TOKEN}")})

    document = scan(images, tmp_path, "secrets")

    assert document["input"]["paths_redacted"] == 1
    (finding,) = document["findings"]
    assert finding["location"]["path_redacted"] is True
    assert finding["package"]["installed_version"] == "1.4.0-[redacted]"
    assert "PACKAGE_VALUES_REDACTED" in document["coverage"]["limitations"]


def test_hostile_package_names_cannot_break_the_report_format(
    images: TrivyImages, tmp_path: Path
) -> None:
    hostile = 'evil","results":[],"x":"\n\u0007<script>‮'
    lock = json.loads(npm_lock())
    lock["packages"][f"node_modules/{hostile}"] = {"version": "1.0.0", "name": hostile}
    make_repository(tmp_path, "inject", {"package-lock.json": json.dumps(lock)})

    document = scan(images, tmp_path, "inject")

    # The template's toJson escaping keeps the report well-formed; the vulnerable packages
    # are still reported and the hostile name (not vulnerable) never reaches evidence.
    assert {NPM_ADVISORY, NPM_DEV_ADVISORY} <= {f["rule_id"] for f in document["findings"]}
    assert "<script>" not in json.dumps(document)


def test_xml_external_entities_and_remote_repositories_are_not_followed(
    images: TrivyImages, tmp_path: Path
) -> None:
    xxe = (
        '<?xml version="1.0"?>\n<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        "<project><modelVersion>4.0.0</modelVersion><groupId>a</groupId><artifactId>b</artifactId>"
        "<version>1</version><dependencies><dependency><groupId>dev.sentinelpipe.fixture</groupId>"
        "<artifactId>vulnerable-parser</artifactId><version>&xxe;</version></dependency>"
        "</dependencies></project>\n"
    )
    remote = (
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId>"
        "<artifactId>parent</artifactId><version>1</version></parent><artifactId>c</artifactId>"
        "<repositories><repository><id>meta</id><url>http://169.254.169.254/latest/</url>"
        "</repository></repositories><dependencies><dependency><groupId>org.example</groupId>"
        "<artifactId>managed</artifactId></dependency></dependencies></project>\n"
    )
    make_repository(tmp_path, "xml", {"xxe/pom.xml": xxe, "remote/pom.xml": remote})
    started = time.monotonic()

    result = execute(images, tmp_path, "xml")

    # Offline and without network the scan neither reads host files nor waits on remote
    # repositories; whatever cannot be resolved is reported as such.
    assert time.monotonic() - started < 60
    if result.outcome is JobOutcome.COMPLETED:
        text = result.artifacts[0].content.decode()
        assert "root:" not in text
        assert json.loads(text)["coverage"]["complete"] is False
    else:
        assert result.failure_reason is FailureReason.SCANNER_ERROR


# --- Database states ---------------------------------------------------------------------------


def test_a_stale_database_is_used_but_disclosed(images: TrivyImages, tmp_path: Path) -> None:
    make_repository(tmp_path, "stale", {"package-lock.json": npm_lock()})

    document = scan(images, tmp_path, "stale", variant="stale")

    assert document["vulnerability_database"]["freshness"] == "STALE"
    assert "VULNERABILITY_DB_STALE" in document["coverage"]["limitations"]
    assert document["coverage"]["complete"] is False
    assert advisories(document)  # still reported: stale data is not discarded


def test_an_expired_database_fails_closed(images: TrivyImages, tmp_path: Path) -> None:
    make_repository(tmp_path, "expired", {"package-lock.json": npm_lock()})
    scanner = adapter(images.image("expired"))
    with pytest.raises(ScannerError, match="VULNERABILITY_DB_EXPIRED"):
        scanner.database_state()

    result = execute(images, tmp_path, "expired", scanner=scanner)

    assert result.outcome is JobOutcome.FAILED
    assert result.failure_reason is FailureReason.SCANNER_ERROR


def test_a_corrupted_database_fails_the_scan_never_clean(
    images: TrivyImages, tmp_path: Path
) -> None:
    # Valid meta pages, inverted data pages: the structure check and the digests pass (the
    # lock describes exactly this file; integrity is not quality), so Trivy itself must
    # fail, and the failure is never a clean result.
    make_repository(tmp_path, "corrupted", {"package-lock.json": npm_lock()})

    result = execute(images, tmp_path, "corrupted", variant="corrupted")

    assert result.outcome is JobOutcome.FAILED
    assert result.failure_reason is FailureReason.SCANNER_ERROR


def test_a_truncated_database_is_refused_before_any_scan(images: TrivyImages) -> None:
    # Regression (security review S3): the pinned Trivy opened a truncated synthetic
    # database and completed with no findings. The structure check refuses it at build
    # and at verification, so it never reaches a sandbox.
    with pytest.raises(ImageError, match="DATABASE_STRUCTURE_INVALID"):
        images.image("truncated")


@pytest.mark.parametrize(
    "change",
    [{"metadata_sha256": "0" * 64}, {"trivy_db_size": 1}],
    ids=["metadata-digest", "database-size"],
)
def test_the_sandbox_refuses_a_database_that_differs_from_the_lock(
    images: TrivyImages, tmp_path: Path, change: dict[str, Any]
) -> None:
    genuine = images.image("fresh")
    forged = VerifiedImage(genuine.image_id, dataclasses.replace(genuine.lock, **change))
    make_repository(tmp_path, "forged", {"package-lock.json": npm_lock()})
    scanner = adapter(forged)

    snapshot = LocalFixtureRepositorySource(tmp_path).snapshot(lease("forged", "TRIVY"))
    run = sandbox(images).run(
        scanner.command(snapshot), threading.Event(), stdin=scanner.stdin(snapshot)
    )

    assert run.exit_code == 76
    with pytest.raises(ScannerError, match="VULNERABILITY_DB_INVALID"):
        scanner.interpret(run, snapshot, lease("forged", "TRIVY"))


def test_the_real_image_is_verified_by_content(images: TrivyImages) -> None:
    genuine = images.image("fresh")
    assert verify_image(images.cli, genuine.lock).image_id == genuine.image_id

    stale = images.image("stale")
    with pytest.raises(ImageError):
        verify_image(images.cli, dataclasses.replace(genuine.lock, image_id=stale.image_id))
    with pytest.raises(ImageError):
        verify_image(images.cli, dataclasses.replace(genuine.lock, trivy_db_sha256="0" * 64))
    base_id = images.cli.call(["image", "inspect", "--format", "{{.Id}}", TRIVY_BASE_IMAGE])
    with pytest.raises(ImageError, match="LAYERS_MISMATCH"):
        verify_image(
            images.cli, dataclasses.replace(genuine.lock, image_id=base_id.stdout.decode().strip())
        )


def test_the_image_declares_exactly_the_reviewed_configuration(images: TrivyImages) -> None:
    details = json.loads(
        images.cli.call(
            ["image", "inspect", "--format", "{{json .Config}}", images.image().image_id]
        ).stdout
    )
    assert details["Env"] == ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    assert details["Entrypoint"] == ["trivy"]
    assert not details.get("User")


# --- Resource limits and hostile input -------------------------------------------------------


def test_oversized_output_and_memory_exhaustion_fail_explicitly(
    images: TrivyImages, tmp_path: Path
) -> None:
    packages = {"": {"name": "app", "version": "1.0.0"}} | {
        f"node_modules/load-{index}": {"version": "1.0.0"} for index in range(200)
    }
    lock = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    make_repository(tmp_path, "big", {"package-lock.json": json.dumps(lock)})

    small_stdout = execute(images, tmp_path, "big", max_stdout_bytes=1024)
    starved = execute(images, tmp_path, "big", memory_bytes=16 * 1024 * 1024)

    assert small_stdout.failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED
    assert starved.outcome is JobOutcome.FAILED
    assert starved.failure_reason in {
        FailureReason.RESOURCE_LIMIT_EXCEEDED,
        FailureReason.SCANNER_ERROR,
    }


def entry(name: str, kind: bytes = tarfile.REGTYPE, data: bytes = b"", link: str = "") -> Any:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, link
    info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    return info, io.BytesIO(data) if kind == tarfile.REGTYPE else None


def crafted(*extra: Any) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for info, data in [
            entry("config", tarfile.DIRTYPE),
            entry("repo", tarfile.DIRTYPE),
            entry("config/report.tpl", data=TEMPLATE),
            entry("repo/package-lock.json", data=npm_lock().encode()),
            *extra,
        ]:
            archive.addfile(info, data)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("members", "code"),
    [
        ([entry("repo/link", tarfile.SYMTYPE, link="/opt/sentinelpipe/trivy/db/trivy.db")], 75),
        ([entry("../escape.json", data=b"x")], 75),
        ([entry("repo/.trivyignore", data=NPM_ADVISORY.encode())], 72),
        ([entry("repo/package-lock.json", data=b"{}")], 75),
    ],
    ids=["symlink", "traversal", "smuggled-trivyignore", "duplicate-overwrite"],
)
def test_hostile_archives_never_yield_a_scan(
    images: TrivyImages, members: list[Any], code: int
) -> None:
    scanner = adapter(images.image())
    snapshot = RepositorySnapshot(
        files=(SnapshotFile("package-lock.json", npm_lock().encode()),), skipped={}
    )

    run = sandbox(images).run(scanner.command(snapshot), threading.Event(), stdin=crafted(*members))

    assert run.exit_code == code


# --- Isolation, concurrency, cancellation and cleanup ---------------------------------------


def test_every_isolation_control_holds_under_the_trivy_policy(images: TrivyImages) -> None:
    secret_cli = DockerCli(
        images.cli.executable, os.environ | {"SENTINEL_WORKER_DB_PASSWORD": "must-not-leak"}
    )
    box = DockerSandbox(
        secret_cli, adapter(images.image()).policy(timeout_seconds=60), monitor_interval=0.5
    )

    run = box.run(probe_command(), threading.Event(), stdin=crafted())

    report = verify(run, box.policy)
    assert report["healthy"], report
    assert unexpected_mounts(str(observations(run)["mounts"]).split()) == []
    assert b"must-not-leak" not in run.stdout


def test_concurrent_scans_of_different_tenants_stay_separate(
    images: TrivyImages, tmp_path: Path
) -> None:
    make_repository(tmp_path, "tenant-a", {"package-lock.json": npm_lock()})
    make_repository(tmp_path, "tenant-b", {"pom.xml": pom()})
    scanner = adapter(images.image())
    executor = ScannerExecutor(sandbox(images), scanner, LocalFixtureRepositorySource(tmp_path))
    leases = {name: lease(name, "TRIVY") for name in ("tenant-a", "tenant-b")}
    results: dict[str, ExecutionResult] = {}
    threads = [
        threading.Thread(
            target=lambda n=name: results.__setitem__(
                n, executor.execute(leases[n], threading.Event())
            )
        )
        for name in leases
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    for name, expected in (("tenant-a", "npm"), ("tenant-b", "maven")):
        document = json.loads(results[name].artifacts[0].content)
        assert document["context"]["organization_id"] == str(leases[name].organization_id)
        assert {f["package"]["ecosystem"] for f in document["findings"]} == {expected}


def test_cancellation_kills_a_running_scan_and_leaves_nothing_behind(
    images: TrivyImages, tmp_path: Path
) -> None:
    packages = {"": {"name": "app", "version": "1.0.0"}} | {
        f"node_modules/load-{index}": {"version": "1.0.0"} for index in range(12000)
    }
    big = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    make_repository(
        tmp_path, "slow", {f"m{i}/package-lock.json": json.dumps(big) for i in range(4)}
    )
    claimed = lease("slow", "TRIVY")
    stop = threading.Event()
    executor = ScannerExecutor(
        sandbox(images, cpus=0.1), adapter(images.image()), LocalFixtureRepositorySource(tmp_path)
    )
    outcome: list[ExecutionResult] = []
    worker = threading.Thread(target=lambda: outcome.append(executor.execute(claimed, stop)))
    worker.start()
    deadline = time.monotonic() + 60
    while not containers(images.cli, f"{JOB_LABEL}={claimed.job_id}"):
        assert time.monotonic() < deadline, "the sandbox never started"
        time.sleep(0.05)
    stop.set()
    worker.join(timeout=60)

    assert outcome
    assert outcome[0].failure_reason is FailureReason.WORKER_SHUTDOWN
    assert containers(images.cli, f"{JOB_LABEL}={claimed.job_id}") == []
    assert [t for t in threading.enumerate() if t.name == "sentinel-sandbox-writer"] == []


def test_no_trivy_sandbox_is_left_behind(images: TrivyImages) -> None:
    leftovers = containers(images.cli, f"{SANDBOX_LABEL}=1")
    assert [name for name in leftovers if name.startswith("sentinel-sandbox-")] == []
    ancestors = images.cli.call(
        ["ps", "--all", "--quiet", "--filter", f"ancestor={images.image().image_id}"]
    )
    assert ancestors.stdout.strip() == b""


# --- Final audit: dependency coverage matrix (real Trivy 0.75.0) -----------------------------

V = "sentinelpipe-fixture-vulnerable"
SCOPED_ADVISORY = "GHSA-9c9c-2h2h-3j3j"


def lock3(packages: dict[str, Any]) -> str:
    root = {"": {"name": "app", "version": "1.0.0"}}
    return json.dumps(
        {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
         "packages": root | packages}
    )  # fmt: skip


def uv_lock(name: str, version: str = "3.0.0") -> str:
    return (
        'version = 1\nrequires-python = ">=3.12"\n\n[[package]]\n'
        f'name = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )


PIPFILE_META = {"hash": {"sha256": "0" * 64}, "pipfile-spec": 6, "requires": {}, "sources": []}
YARN_BERRY = (
    f'__metadata:\n  version: 6\n  cacheKey: 8\n\n"{V}@npm:2.0.0":\n  version: 2.0.0\n'
    f'  resolution: "{V}@npm:2.0.0"\n  checksum: abc\n  languageName: node\n  linkType: hard\n'
)
PNPM_V6 = (
    f"lockfileVersion: '6.0'\n\ndependencies:\n  {V}:\n    specifier: 2.0.0\n"
    f"    version: 2.0.0\n\npackages:\n\n  /{V}@2.0.0:\n"
    "    resolution: {integrity: sha512-AAAA}\n    dev: false\n"
)
PARENT_POM = (
    "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>parent</artifactId>"
    "<version>1</version><packaging>pom</packaging><properties><fx.version>1.4.0</fx.version>"
    "</properties><modules><module>child</module></modules></project>"
)
CHILD_POM = (
    "<project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId>"
    "<artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId>"
    "<dependencies><dependency><groupId>dev.sentinelpipe.fixture</groupId>"
    "<artifactId>vulnerable-parser</artifactId><version>${fx.version}</version>"
    "</dependency></dependencies></project>"
)
BOM_POM = (
    "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId>"
    "<version>1</version><dependencyManagement><dependencies><dependency><groupId>org.example"
    "</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import"
    "</scope></dependency></dependencies></dependencyManagement><dependencies><dependency>"
    "<groupId>dev.sentinelpipe.fixture</groupId><artifactId>vulnerable-parser</artifactId>"
    "</dependency></dependencies></project>"
)

#: case -> (files, expected advisories, coverage complete, limitations that must be present).
COVERAGE: dict[str, tuple[dict[str, str], set[str], bool, set[str]]] = {
    "npm-scoped": (
        {"package-lock.json": lock3({"node_modules/@sentinelpipe-fixture/scoped": {"version": "1.1.0"}})},
        {SCOPED_ADVISORY}, True, set(),
    ),
    "npm-alias": (
        {"package-lock.json": lock3({"node_modules/my-alias": {"name": V, "version": "2.0.0"}})},
        {NPM_ADVISORY}, True, set(),
    ),
    "npm-optional": (
        {"package-lock.json": lock3({f"node_modules/{V}": {"version": "2.0.0", "optional": True}})},
        {NPM_ADVISORY}, True, set(),
    ),
    "npm-transitive-duplicates": (
        {"package-lock.json": lock3({
            "node_modules/a": {"version": "1.0.0", "dependencies": {V: "2.0.0"}},
            f"node_modules/a/node_modules/{V}": {"version": "2.0.0"},
            f"node_modules/{V}": {"version": "2.0.1"},
        })},
        {NPM_ADVISORY}, True, set(),
    ),
    "npm-lockfile-v1": (
        {"package-lock.json": json.dumps({"name": "app", "version": "1.0.0", "lockfileVersion": 1,
                                          "dependencies": {V: {"version": "2.0.0"}}})},
        {NPM_ADVISORY}, True, set(),
    ),
    "npm-git-dependency": (
        {"package-lock.json": lock3({f"node_modules/{V}": {"version": "git+ssh://git@example.com/x.git#abc"}})},
        set(), False, {"UNRESOLVED_DEPENDENCY_VERSIONS"},
    ),
    "yarn-berry": (
        {"package.json": json.dumps({"dependencies": {V: "2.0.0"}}), "yarn.lock": YARN_BERRY},
        {NPM_ADVISORY}, True, set(),
    ),
    "pnpm-v6": ({"pnpm-lock.yaml": PNPM_V6}, {NPM_ADVISORY}, True, set()),
    "pypi-dotted-name": (
        {"uv.lock": uv_lock("sentinelpipe.fixture.vulnerable")},
        set(), False, {"PYPI_NAME_MATCHING_UNVERIFIED"},
    ),
    "pipenv-develop": (
        {"Pipfile.lock": json.dumps({"_meta": PIPFILE_META,
                                     "default": {"sentinelpipe-fixture-unfixed": {"version": "==9.9.9"}},
                                     "develop": {V: {"version": "==3.0.0"}}})},
        {PYPI_UNFIXED_ADVISORY}, False, {"DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED"},
    ),
    "maven-local-parent-property": (
        {"pom.xml": PARENT_POM, "child/pom.xml": CHILD_POM},
        {MAVEN_ADVISORY}, False, {"PARTIAL_DEPENDENCY_RESOLUTION"},
    ),
    "maven-remote-bom": (
        {"pom.xml": BOM_POM},
        set(), False, {"UNRESOLVED_DEPENDENCY_VERSIONS", "PARTIAL_DEPENDENCY_RESOLUTION"},
    ),
    "maven-version-range": ({"pom.xml": pom("[1.0,1.4.1]")}, set(), False, {"UNRESOLVED_DEPENDENCY_VERSIONS"}),
    "maven-test-scope": (
        {"pom.xml": pom("1.4.0").replace("<version>1.4.0</version>",
                                         "<version>1.4.0</version><scope>test</scope>")},
        set(), False, {"PARTIAL_DEPENDENCY_RESOLUTION"},
    ),
    "gradle-test-classpath": (
        {"build.gradle": "",
         "gradle.lockfile": "dev.sentinelpipe.fixture:vulnerable-parser:1.4.0=testRuntimeClasspath\nempty=\n"},
        {MAVEN_ADVISORY}, True, set(),
    ),
    "unicode-and-spaces-in-path": (
        {"sérvice dir/package-lock.json": lock3({f"node_modules/{V}": {"version": "2.0.0"}})},
        {NPM_ADVISORY}, True, set(),
    ),
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(COVERAGE))
def test_dependency_coverage_matrix(images: TrivyImages, tmp_path: Path, case: str) -> None:
    files, expected, complete, limitations = COVERAGE[case]
    make_repository(tmp_path, case, files)

    document = scan(images, tmp_path, case)

    assert {f["rule_id"] for f in document["findings"]} == expected
    assert document["coverage"]["complete"] is complete
    assert limitations <= set(document["coverage"]["limitations"])
    if not expected:
        # A missed match must never look like a complete, clean scan.
        assert document["coverage"]["complete"] is False


def test_a_timeout_fails_the_scan(images: TrivyImages, tmp_path: Path) -> None:
    packages = {f"node_modules/load-{index}": {"version": "1.0.0"} for index in range(12000)}
    make_repository(
        tmp_path, "slow", {f"m{i}/package-lock.json": lock3(packages) for i in range(4)}
    )

    result = execute(images, tmp_path, "slow", cpus=0.1, timeout_seconds=2)

    assert result.outcome is JobOutcome.FAILED
    assert result.failure_reason is FailureReason.EXECUTION_TIMEOUT


def test_an_altered_report_template_never_runs(images: TrivyImages) -> None:
    scanner = adapter(images.image())
    snapshot = RepositorySnapshot(
        files=(SnapshotFile("package-lock.json", npm_lock().encode()),), skipped={}
    )
    altered = snapshot.archive(
        "repo", {"config/report.tpl": TEMPLATE.replace(b"results", b"result")}
    )

    run = sandbox(images).run(scanner.command(snapshot), threading.Event(), stdin=altered)

    assert run.exit_code == 72


def test_a_truncated_input_stream_never_yields_a_scan(images: TrivyImages) -> None:
    scanner = adapter(images.image())
    snapshot = RepositorySnapshot(
        files=(SnapshotFile("package-lock.json", npm_lock().encode()),), skipped={}
    )
    stdin = scanner.stdin(snapshot)
    # Cut inside real content (the archive ends with zero padding, which tar may not need).
    cut = stdin.index(b'"lockfileVersion"') + 5

    run = sandbox(images).run(scanner.command(snapshot), threading.Event(), stdin=stdin[:cut])

    assert run.exit_code in {71, 72, 75}
    with pytest.raises(ScannerError):
        scanner.interpret(run, snapshot, lease("cut", "TRIVY"))

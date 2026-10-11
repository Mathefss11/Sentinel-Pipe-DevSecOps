"""Semgrep in real sandbox containers (ADR-0011).

The pinned Semgrep image runs the bundled ruleset under the full sandbox policy over
synthetic repositories delivered on stdin. Covers:

* clean and vulnerable fixtures in Java, Python, JavaScript and TypeScript;
* duplicates and determinism;
* source excerpts and secret-shaped file names never reaching evidence;
* Unicode paths;
* repository-controlled ignore files and configuration;
* unsupported languages and parse errors (partial coverage);
* oversized output;
* hostile archives;
* isolation (network, environment, mounts) and the image's declared environment;
* cancellation and cleanup.

Requires Docker and the pinned image (CI sandbox job). Synthetic data only.
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
from semgrep_support import CLEAN, VULNERABLE, rule_ids
from sentinel_worker.execution.leases import FailureReason, JobOutcome
from sentinel_worker.execution.runner import ExecutionResult
from sentinel_worker.repository.snapshot import (
    LocalFixtureRepositorySource,
    RepositorySnapshot,
    SnapshotFile,
    snapshot_directory,
)
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
from sentinel_worker.sandbox.isolation import observations, probe_command, unexpected_mounts, verify
from sentinel_worker.sandbox.policy import (
    IMAGE_ENVIRONMENT,
    JOB_LABEL,
    SANDBOX_LABEL,
    SEMGREP_IMAGE,
)
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.semgrep import RULESET, SemgrepAdapter

pytestmark = pytest.mark.sandbox

ADAPTER = SemgrepAdapter()
MARKER = "SENTINEL_PROPRIETARY_SOURCE_" + "M" * 24
TOKEN = synthetic_github_token(61)


@pytest.fixture(scope="module")
def cli(docker_cli: DockerCli) -> DockerCli:
    if docker_cli.call(["image", "inspect", SEMGREP_IMAGE]).returncode != 0:
        problem = f"Semgrep image not present; pull {SEMGREP_IMAGE}"
        if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    return docker_cli


def sandbox(cli: DockerCli, **overrides: Any) -> DockerSandbox:
    policy = dataclasses.replace(ADAPTER.policy(timeout_seconds=120), **overrides)
    return DockerSandbox(cli, policy, monitor_interval=0.5)


def execute(cli: DockerCli, root: Path, name: str, **overrides: Any) -> ExecutionResult:
    executor = ScannerExecutor(
        sandbox(cli, **overrides), ADAPTER, LocalFixtureRepositorySource(root)
    )
    return executor.execute(lease(name, "SEMGREP"), threading.Event())


def scan(cli: DockerCli, root: Path, name: str) -> dict[str, Any]:
    result = execute(cli, root, name)
    assert result.outcome is JobOutcome.COMPLETED, result
    (artifact,) = result.artifacts
    for sensitive in (MARKER, TOKEN):
        assert sensitive.encode() not in artifact.content
    document: dict[str, Any] = json.loads(artifact.content)
    return document


def located(document: dict[str, Any]) -> set[tuple[int, str]]:
    return {(f["location"]["start_line"], f["rule_id"]) for f in document["findings"]}


def containers(cli: DockerCli, label: str) -> list[str]:
    result = cli.call(["ps", "--all", "--filter", f"label={label}", "--format", "{{.Names}}"])
    return result.stdout.decode().split()


# --- Languages: vulnerable and clean fixtures -----------------------------------------


@pytest.mark.parametrize("language", sorted(VULNERABLE))
def test_vulnerable_fixtures_trigger_exactly_their_rules(
    cli: DockerCli, tmp_path: Path, language: str
) -> None:
    path, code, expected = VULNERABLE[language]
    make_repository(tmp_path, "vulnerable", {path: code})

    document = scan(cli, tmp_path, "vulnerable")

    assert located(document) == rule_ids(expected)
    assert all(f["category"] == "CODE_PATTERN" for f in document["findings"])
    assert document["execution"]["exit_code"] == 41
    assert document["coverage"]["complete"] is True
    assert document["coverage"]["files_analyzed"] == 1


@pytest.mark.parametrize("language", sorted(CLEAN))
def test_clean_fixtures_have_no_findings_and_full_coverage(
    cli: DockerCli, tmp_path: Path, language: str
) -> None:
    path, code = CLEAN[language]
    make_repository(tmp_path, "clean", {path: code})

    document = scan(cli, tmp_path, "clean")

    assert document["finding_count"] == 0
    assert document["execution"] == {
        "status": "NO_FINDINGS",
        "exit_code": 0,
        "raw_report_sha256": document["execution"]["raw_report_sha256"],
    }
    assert document["coverage"]["complete"] is True


def test_a_multi_language_repository_is_deterministic(cli: DockerCli, tmp_path: Path) -> None:
    files = {path: code for path, code, _ in VULNERABLE.values()}
    files |= {path: code for path, code in CLEAN.values()}
    files["copy/handlers.py"] = VULNERABLE["python"][1]  # duplicated content, distinct file
    make_repository(tmp_path, "multi", files)
    claimed = lease("multi", "SEMGREP")
    executor = ScannerExecutor(sandbox(cli), ADAPTER, LocalFixtureRepositorySource(tmp_path))

    first = executor.execute(claimed, threading.Event())
    second = executor.execute(claimed, threading.Event())

    document, again = (json.loads(r.artifacts[0].content) for r in (first, second))
    # Everything is reproducible except the digest of Semgrep's raw report, which varies
    # between runs (timing and ordering data) and identifies the report actually observed.
    for parsed in (document, again):
        parsed["execution"].pop("raw_report_sha256")
    assert document == again
    expected = sum(len(item[2]) for item in VULNERABLE.values()) + len(VULNERABLE["python"][2])
    assert document["finding_count"] == expected
    assert document["coverage"]["files_analyzed"] == 9


# --- Sensitive output ----------------------------------------------------------------


def test_source_excerpts_never_leave_the_worker_and_never_reach_evidence(
    cli: DockerCli, tmp_path: Path
) -> None:
    code = f'API_KEY = "{TOKEN}"\nPROPRIETARY = "{MARKER}"\neval(PROPRIETARY + input())\n'
    repository = make_repository(tmp_path, "sensitive", {"app.py": code})
    snapshot = snapshot_directory(str(repository))

    run = sandbox(cli).run(
        ADAPTER.command(snapshot), threading.Event(), stdin=ADAPTER.stdin(snapshot)
    )
    document = scan(cli, tmp_path, "sensitive")

    assert run.exit_code == 41
    # Semgrep 1.179.0 does not even place source lines in its report (defense in depth:
    # the worker never reads them anyway).
    assert MARKER.encode() not in run.stdout
    assert TOKEN.encode() not in run.stdout
    assert MARKER not in run.stderr_excerpt
    assert located(document) == {(3, "sentinelpipe.python.code-injection-eval")}


def test_secret_shaped_and_unicode_file_names_are_safe(cli: DockerCli, tmp_path: Path) -> None:
    make_repository(
        tmp_path,
        "names",
        {f"keys/{TOKEN}.py": "eval(input())\n", "ünï cødé/ファイル.py": "eval(input())\n"},
    )

    document = scan(cli, tmp_path, "names")

    paths = {f["location"]["path"] for f in document["findings"]}
    assert paths == {"keys/[redacted-1]", "ünï cødé/ファイル.py"}
    assert document["input"]["paths_redacted"] == 1


# --- Repository-controlled configuration, ignore files and comments ------------------


def test_repository_controlled_suppression_is_ignored(cli: DockerCli, tmp_path: Path) -> None:
    vulnerable = "def f(x):\n    eval(x)\n"
    make_repository(
        tmp_path,
        "suppressing",
        {
            ".semgrepignore": "*\n",
            "sub/.semgrepignore": "*.py\n",
            "sub/hidden.py": vulnerable,
            ".semgrep.yml": "rules: []\n",
            ".semgrep/settings.yml": "has_shown_metrics_notification: true\n",
            ".gitignore": "*.py\n",
            "nosem.py": "def f(x):\n    eval(x)  # nosemgrep\n",
            "tests/test_app.py": vulnerable,
            "node_modules/pkg/index.js": "module.exports = (x) => eval(x);\n",
            "vendor/lib.py": vulnerable,
            "dist/app.min.js": "function f(x){eval(x)}\n",
        },
    )

    document = scan(cli, tmp_path, "suppressing")

    assert {f["location"]["path"] for f in document["findings"]} == {
        "sub/hidden.py", "nosem.py", "tests/test_app.py", "node_modules/pkg/index.js",
        "vendor/lib.py", "dist/app.min.js",
    }  # fmt: skip
    assert document["input"]["skipped"]["suppression_file"] == 2
    assert document["coverage"]["complete"] is True


def test_the_image_declares_exactly_the_reviewed_environment(cli: DockerCli) -> None:
    result = cli.call(["image", "inspect", "--format", "{{json .Config.Env}}", SEMGREP_IMAGE])

    names = {entry.split("=", 1)[0] for entry in json.loads(result.stdout)}
    assert names == {"PATH"} | IMAGE_ENVIRONMENT[SEMGREP_IMAGE]
    assert not any(
        name.startswith(("SEMGREP_RULES", "SEMGREP_APP", "SEMGREP_SEND")) for name in names
    )


# --- Coverage: unsupported languages and parse errors --------------------------------


def test_unsupported_languages_and_parse_errors_are_reported_as_partial_coverage(
    cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "partial",
        {
            "ok.py": "print('ok')\n",
            "broken.js": "}}}{{{ function ((( eval(x\n" * 3,
            "main.rb": "system(params[:cmd])\n",
            "main.go": "package main\n",
            "tool.pyw": "eval(input())\n",
            "bin/run": "#!/usr/bin/env python3\neval(input())\n",
        },
    )

    document = scan(cli, tmp_path, "partial")

    coverage = document["coverage"]
    assert (coverage["files_supported"], coverage["files_unsupported"]) == (2, 4)
    assert coverage["files_not_analyzed"] == 1
    assert coverage["complete"] is False
    assert {"FILES_NOT_ANALYZED", "UNSUPPORTED_FILES_PRESENT"} <= set(coverage["limitations"])


def test_a_repository_without_supported_files_is_flagged(cli: DockerCli, tmp_path: Path) -> None:
    make_repository(tmp_path, "ruby", {"app.rb": "eval(params[:x])\n"})

    document = scan(cli, tmp_path, "ruby")

    assert "NO_SUPPORTED_FILES" in document["coverage"]["limitations"]
    assert document["finding_count"] == 0


# --- Failures: output bounds, hostile archives ---------------------------------------


def test_oversized_output_and_reports_fail_explicitly(cli: DockerCli, tmp_path: Path) -> None:
    repository = make_repository(
        tmp_path, "many", {f"m{i}.py": "eval(input())\n" * 20 for i in range(40)}
    )
    snapshot = snapshot_directory(str(repository))
    argv = ADAPTER.command(snapshot)

    small_report = sandbox(cli).run(
        [*argv[:5], "1024", *argv[6:]], threading.Event(), stdin=ADAPTER.stdin(snapshot)
    )
    small_stdout = execute(cli, tmp_path, "many", max_stdout_bytes=4096)

    assert small_report.exit_code == 74
    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(small_report, snapshot, lease())
    assert raised.value.reason is FailureReason.RESOURCE_LIMIT_EXCEEDED
    assert small_stdout.failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED


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
            entry("config/rules.json", data=RULESET),
            entry("repo/a.py", data=b"print(1)\n"),
            *extra,
        ]:
            archive.addfile(info, data)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("members", "code"),
    [
        ([entry("repo/link", tarfile.SYMTYPE, link="/etc")], 75),
        ([entry("../escape.py", data=b"x")], 75),
        ([entry("repo/.semgrepignore", data=b"*\n")], 72),
        ([entry("repo/a.py", data=b"replaced\n")], 75),
    ],
    ids=["symlink", "traversal", "smuggled-semgrepignore", "duplicate-overwrite"],
)
def test_hostile_archives_never_yield_a_scan(cli: DockerCli, members: list[Any], code: int) -> None:
    snapshot = RepositorySnapshot(files=(SnapshotFile("a.py", b"print(1)\n"),), skipped={})

    run = sandbox(cli).run(ADAPTER.command(snapshot), threading.Event(), stdin=crafted(*members))

    assert run.exit_code == code


# --- Isolation, cancellation and cleanup ---------------------------------------------


def test_an_altered_ruleset_never_runs(cli: DockerCli) -> None:
    """The ruleset in the input archive is checked against its pinned digest before Semgrep
    starts. A ruleset with one rule removed would otherwise run and under-report."""
    rules = json.loads(RULESET)
    rules["rules"] = rules["rules"][1:]
    altered = json.dumps(rules).encode()
    snapshot = RepositorySnapshot(files=(SnapshotFile("a.py", b"eval(input())\n"),), skipped={})

    for config in (altered, RULESET[:-1], RULESET + b" "):
        stdin = snapshot.archive("repo", {"config/rules.json": config})
        run = sandbox(cli).run(ADAPTER.command(snapshot), threading.Event(), stdin=stdin)
        assert run.exit_code == 72
        with pytest.raises(ScannerError):
            ADAPTER.interpret(run, snapshot, lease("altered-ruleset", "SEMGREP"))


def test_every_isolation_control_holds_under_the_semgrep_policy(cli: DockerCli) -> None:
    secret_cli = DockerCli(
        cli.executable, os.environ | {"SENTINEL_WORKER_DB_PASSWORD": "must-not-leak"}
    )
    box = DockerSandbox(secret_cli, ADAPTER.policy(timeout_seconds=60), monitor_interval=0.5)

    run = box.run(probe_command(), threading.Event(), stdin=crafted())

    report = verify(run, box.policy)
    assert report["healthy"], report
    assert report["controls"]["no_network"] is True
    assert unexpected_mounts(str(observations(run)["mounts"]).split()) == []
    assert b"must-not-leak" not in run.stdout


def test_cancellation_kills_a_running_scan_and_leaves_nothing_behind(
    cli: DockerCli, tmp_path: Path
) -> None:
    body = "".join(f"def f{i}(a):\n    return a + {i}\n" for i in range(4000))
    make_repository(tmp_path, "slow", {f"pkg/m{i}.py": body for i in range(12)})
    claimed = lease("slow", "SEMGREP")
    stop = threading.Event()
    executor = ScannerExecutor(
        sandbox(cli, cpus=0.2), ADAPTER, LocalFixtureRepositorySource(tmp_path)
    )
    outcome: list[ExecutionResult] = []
    worker = threading.Thread(target=lambda: outcome.append(executor.execute(claimed, stop)))
    worker.start()
    deadline = time.monotonic() + 30
    while not containers(cli, f"{JOB_LABEL}={claimed.job_id}"):
        assert time.monotonic() < deadline, "the sandbox never started"
        time.sleep(0.05)
    stop.set()
    worker.join(timeout=30)

    assert outcome
    assert outcome[0].failure_reason is FailureReason.WORKER_SHUTDOWN
    assert containers(cli, f"{JOB_LABEL}={claimed.job_id}") == []
    assert [t for t in threading.enumerate() if t.name == "sentinel-sandbox-writer"] == []


def test_no_semgrep_sandbox_is_left_behind(cli: DockerCli) -> None:
    leftovers = containers(cli, f"{SANDBOX_LABEL}=1")
    assert [name for name in leftovers if name.startswith("sentinel-sandbox-")] == []
    ancestors = cli.call(["ps", "--all", "--quiet", "--filter", f"ancestor={SEMGREP_IMAGE}"])
    assert ancestors.stdout.strip() == b""

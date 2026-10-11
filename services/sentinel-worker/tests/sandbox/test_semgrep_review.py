# ruff: noqa: E501 - fixture source lines are kept intact
"""Real-container regression tests for the Slice 2 (Semgrep) security review.

Parser recovery and unverifiable encodings never yield "analyzed"; directories named like
control files do not break scans; ruleset fixes and documented false negatives; the
scanner processes run with a cleared environment; more suppression variants; concurrency,
timeouts, memory exhaustion, finding bounds and cancellation during extraction. Requires
Docker and the pinned images (CI sandbox job). Synthetic data only.
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from scanner_support import lease, make_repository
from sentinel_worker.execution.leases import FailureReason, JobOutcome
from sentinel_worker.execution.runner import ExecutionResult
from sentinel_worker.repository.snapshot import LocalFixtureRepositorySource
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxStatus
from sentinel_worker.sandbox.policy import GITLEAKS_IMAGE, JOB_LABEL, SEMGREP_IMAGE
from sentinel_worker.scanners import semgrep
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.gitleaks import GitleaksAdapter
from sentinel_worker.scanners.semgrep import SemgrepAdapter

pytestmark = pytest.mark.sandbox

ADAPTER = SemgrepAdapter()


@pytest.fixture(scope="module")
def cli(docker_cli: DockerCli) -> DockerCli:
    for image in (SEMGREP_IMAGE, GITLEAKS_IMAGE):
        if docker_cli.call(["image", "inspect", image]).returncode != 0:
            problem = f"image not present; pull {image}"
            if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
                pytest.fail(problem)
            pytest.skip(problem)
    return docker_cli


def sandbox(cli: DockerCli, **overrides: Any) -> DockerSandbox:
    policy = dataclasses.replace(ADAPTER.policy(timeout_seconds=120), **overrides)
    return DockerSandbox(cli, policy, monitor_interval=0.5)


def execute(cli: DockerCli, root: Path, name: str = "r", **overrides: Any) -> ExecutionResult:
    executor = ScannerExecutor(
        sandbox(cli, **overrides), ADAPTER, LocalFixtureRepositorySource(root)
    )
    return executor.execute(lease(name, "SEMGREP"), threading.Event())


def scan(cli: DockerCli, root: Path, files: dict[str, Any]) -> dict[str, Any]:
    make_repository(root, "r", files)
    result = execute(cli, root)
    assert result.outcome is JobOutcome.COMPLETED, result
    document: dict[str, Any] = json.loads(result.artifacts[0].content)
    return document


def containers(cli: DockerCli, job_id: object) -> list[str]:
    listing = cli.call(
        ["ps", "--all", "--filter", f"label={JOB_LABEL}={job_id}", "--format", "{{.Names}}"]
    )
    return listing.stdout.decode().split()


# --- Parser recovery and encodings -----------------------------------------------------


def test_silent_parser_recovery_and_utf16_are_reported_as_not_analyzed(
    cli: DockerCli, tmp_path: Path
) -> None:
    document = scan(
        cli,
        tmp_path,
        {
            "ok.py": "def f(cmd):\n    eval(cmd)\n",
            "recovered1.py": "def bad(:\n    eval(cmd)\n",  # Semgrep: no error reported
            "recovered2.py": "def f(cmd):\n    print 'py2'\n    eval(cmd)\n",
            "utf16.js": "function f(x) { eval(x); }\n".encode("utf-16"),  # Semgrep: silent
            "utf16le.ts": "eval(cmd);\n".encode("utf-16-le"),
            "clean.ts": "export const a = 1;\n",
        },
    )

    coverage = document["coverage"]
    assert coverage["complete"] is False
    assert coverage["files_analyzed"] == 2
    assert coverage["not_analyzed_reasons"] == {
        "scanner_skipped": 0,
        "parse_error": 2,
        "resource_limit": 0,
        "unverifiable_encoding": 2,
    }
    # What Semgrep recovered is still reported.
    assert {f["location"]["path"] for f in document["findings"]} == {
        "ok.py", "recovered1.py", "recovered2.py"
    }  # fmt: skip


def test_per_file_memory_limits_are_reported_not_silent(cli: DockerCli, tmp_path: Path) -> None:
    document = scan(
        cli, tmp_path, {"long.js": "var a=1;" * 120000 + "eval(x);\n", "ok.py": "x = 1\n"}
    )

    assert document["coverage"]["not_analyzed_reasons"]["resource_limit"] == 1
    assert document["coverage"]["complete"] is False


# --- Directories named like control files (both scanners) -----------------------------


def test_semgrepignore_directories_do_not_break_the_scan(cli: DockerCli, tmp_path: Path) -> None:
    document = scan(
        cli,
        tmp_path,
        {
            ".semgrepignore/x.py": "eval(cmd)\n",
            "a/.semgrepignore/y.py": "eval(cmd)\n",
            "ok.py": "eval(cmd)\n",
        },
    )

    assert document["input"]["skipped"]["unsupported_name"] == 2
    assert document["coverage"]["complete"] is False
    assert [f["location"]["path"] for f in document["findings"]] == ["ok.py"]


def test_a_root_gitleaksignore_directory_does_not_break_the_gitleaks_scan(
    cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(tmp_path, "r", {".gitleaksignore/notes.txt": "x\n", "ok.txt": "x\n"})
    adapter = GitleaksAdapter()
    executor = ScannerExecutor(
        DockerSandbox(cli, adapter.policy(timeout_seconds=60)),
        adapter,
        LocalFixtureRepositorySource(tmp_path),
    )

    result = executor.execute(lease("r"), threading.Event())

    assert result.outcome is JobOutcome.COMPLETED
    document = json.loads(result.artifacts[0].content)
    assert document["input"]["skipped"]["unsupported_name"] == 1
    assert document["coverage"]["complete"] is False


# --- Ruleset fixes and documented false negatives ------------------------------------

FIXED = {
    "J6.java": (
        None,
        'class A { void f(java.sql.Statement s) throws Exception { s.executeQuery("SELECT " + "1"); } }\n',
    ),
    "J12.java": (
        "java.insecure-deserialization",
        "class A { Object f(java.io.InputStream i) throws Exception { return new java.io.ObjectInputStream(i).readObject(); } }\n",
    ),
    "J13.java": (
        "java.weak-hash-algorithm",
        'class A { void f() throws Exception { java.security.MessageDigest.getInstance("sha1"); } }\n',
    ),
    "P14.py": (None, "import yaml\ndef f(b):\n    yaml.load(b, yaml.SafeLoader)\n"),
    "S6.js": (
        "javascript.command-injection-child-process",
        "const { execSync } = require('child_process');\nfunction f(x) { execSync(x); }\n",
    ),
    "S7.js": (
        "javascript.command-injection-child-process",
        "const cp = require('node:child_process');\nfunction f(x) { cp.exec(x); }\n",
    ),
}
#: Known false negatives, documented in ADR-0011 and proposed as separate ruleset work.
DOCUMENTED_FALSE_NEGATIVES = {
    "J4.java": 'class A { void f(java.sql.Statement s, String id) throws Exception { s.executeQuery(String.format("SELECT %s", id)); } }\n',
    "J7.java": "class A { void f(String c) throws Exception { Runtime r = Runtime.getRuntime(); r.exec(c); } }\n",
    "P4.py": "import subprocess\ndef f(c):\n    subprocess.call(c, shell=1)\n",
    "P7.py": "import builtins\ndef f(c):\n    builtins.eval(c)\n",
    "P18.py": "def f(cur, n):\n    q = f'SELECT * FROM t WHERE n = {n}'\n    cur.execute(q)\n",
    "P21.py": "import hashlib\ndef f(b):\n    hashlib.new('md5', b)\n",
    "S1.js": "function f(x) { window.eval(x); }\n",
    "S15.js": "function f(el, x) { el.insertAdjacentHTML('beforeend', x); }\n",
}


def test_audited_rule_defects_stay_fixed(cli: DockerCli, tmp_path: Path) -> None:
    document = scan(cli, tmp_path, {name: code for name, (_, code) in FIXED.items()})

    found = {(f["location"]["path"], f["rule_id"]) for f in document["findings"]}
    expected = {(name, "sentinelpipe." + rule) for name, (rule, _) in FIXED.items() if rule}
    assert found == expected


def test_documented_false_negatives_are_still_accurate(cli: DockerCli, tmp_path: Path) -> None:
    """Characterization: if a rule starts covering one of these, update ADR-0011."""
    document = scan(cli, tmp_path, DOCUMENTED_FALSE_NEGATIVES)

    assert document["findings"] == []
    assert document["coverage"]["complete"] is True


# --- Environment of the scanner processes ---------------------------------------------


@pytest.mark.parametrize("program", ["semgrep scan", "python3 -I -S /tmp/pycheck.py"])
def test_scanner_processes_run_with_a_cleared_environment(cli: DockerCli, program: str) -> None:
    line = next(
        line
        for line in semgrep._SCRIPT.splitlines()
        if line.startswith("env -i") and program in line
    )
    prefix = line.split(" " + program.split()[0] + " ", 1)[0]
    hostile = DockerCli(
        cli.executable,
        os.environ | {"SENTINEL_WORKER_DB_PASSWORD": "must-not-leak", "DD_SERVICE": "host-value"},
    )
    box = DockerSandbox(hostile, ADAPTER.policy(timeout_seconds=60), monitor_interval=0.5)

    run = box.run(["/bin/sh", "-c", prefix + " env"], threading.Event())

    assert run.status is SandboxStatus.EXITED
    names = {entry.split("=", 1)[0] for entry in run.stdout.decode().split("\n") if entry}
    expected = {
        "PATH",
        "HOME",
        "PYTHONIOENCODING",
        "SEMGREP_SEND_METRICS",
        "SEMGREP_ENABLE_VERSION_CHECK",
    }
    assert names == (expected if program.startswith("semgrep") else {"PATH"})
    assert b"must-not-leak" not in run.stdout
    assert b"host-value" not in run.stdout


# --- More suppression variants -------------------------------------------------------


def test_comment_and_configuration_variants_never_suppress(cli: DockerCli, tmp_path: Path) -> None:
    document = scan(
        cli,
        tmp_path,
        {
            "a.py": "def f(x):\n    eval(x)  # nosemgrep: sentinelpipe.python.code-injection-eval\n",
            "b.py": "def f(x):\n    eval(x)  # nosem\n",
            "c.js": "function f(x) { eval(x); /* nosemgrep */ }\n",
            "d.ts": "// nosemgrep\nexport const f = (x: string) => eval(x);\n",
            "E.java": "class E { void f(String c) throws Exception { Runtime.getRuntime().exec(c); // nosemgrep\n } }\n",
            ".semgrepconfig.yml": "tags: [ignored]\n",
            "semgrep.yml": "rules: []\n",
            ".semgrep/rules.yml": "rules: []\n",
        },
    )

    assert {f["location"]["path"] for f in document["findings"]} == {
        "a.py",
        "b.py",
        "c.js",
        "d.ts",
        "E.java",
    }


# --- Resource exhaustion, concurrency, cancellation ------------------------------------


def test_concurrent_scans_are_isolated(cli: DockerCli, tmp_path: Path) -> None:
    make_repository(tmp_path, "one", {"a.py": "eval(x)\n"})
    make_repository(tmp_path, "two", {"b.js": "function f(x) { eval(x); }\n", "c.py": "print(1)\n"})
    results: dict[str, ExecutionResult] = {}

    def run(name: str) -> None:
        executor = ScannerExecutor(sandbox(cli), ADAPTER, LocalFixtureRepositorySource(tmp_path))
        results[name] = executor.execute(lease(name, "SEMGREP"), threading.Event())

    threads = [threading.Thread(target=run, args=(name,)) for name in ("one", "two")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=180)

    one, two = (json.loads(results[name].artifacts[0].content) for name in ("one", "two"))
    assert [f["location"]["path"] for f in one["findings"]] == ["a.py"]
    assert [f["location"]["path"] for f in two["findings"]] == ["b.js"]
    assert (one["input"]["files_scanned"], two["input"]["files_scanned"]) == (1, 2)


def test_a_timeout_during_parsing_is_an_execution_timeout(cli: DockerCli, tmp_path: Path) -> None:
    body = "".join(f"def f{i}(a):\n    return eval(a) + {i}\n" for i in range(3000))
    make_repository(tmp_path, "r", {f"m{i}.py": body for i in range(10)})

    result = execute(cli, tmp_path, timeout_seconds=3, cpus=0.2)

    assert result.failure_reason is FailureReason.EXECUTION_TIMEOUT


def test_memory_exhaustion_is_a_resource_failure(cli: DockerCli, tmp_path: Path) -> None:
    make_repository(tmp_path, "r", {"a.py": "eval(x)\n"})

    result = execute(cli, tmp_path, memory_bytes=48 * 1024 * 1024)

    assert result.failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED


def test_more_distinct_findings_than_supported_fail_explicitly(
    cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(tmp_path, "r", {f"m{i}.py": "eval(x)\n" for i in range(1001)})

    result = execute(cli, tmp_path)

    assert result.failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED
    assert result.artifacts == ()


def test_cancellation_during_extraction_leaves_nothing_behind(
    cli: DockerCli, tmp_path: Path
) -> None:
    blob = ("x = 1\n" * 150000).encode()  # about 0.9 MiB per file
    make_repository(tmp_path, "r", {f"big/f{i}.py": blob for i in range(16)})
    claimed = lease("r", "SEMGREP")
    stop = threading.Event()
    executor = ScannerExecutor(
        sandbox(cli, cpus=0.2), ADAPTER, LocalFixtureRepositorySource(tmp_path)
    )
    outcome: list[ExecutionResult] = []
    worker = threading.Thread(target=lambda: outcome.append(executor.execute(claimed, stop)))
    worker.start()
    deadline = time.monotonic() + 30
    while not containers(cli, claimed.job_id):
        assert time.monotonic() < deadline, "the sandbox never started"
        time.sleep(0.02)
    stop.set()
    worker.join(timeout=60)

    assert outcome
    assert outcome[0].failure_reason is FailureReason.WORKER_SHUTDOWN
    assert containers(cli, claimed.job_id) == []
    assert [t for t in threading.enumerate() if t.name == "sentinel-sandbox-writer"] == []

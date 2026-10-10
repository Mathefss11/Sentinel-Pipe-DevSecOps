"""Gitleaks in real sandbox containers (ADR-0010).

The pinned Gitleaks image runs under the full sandbox policy, scanning synthetic
repositories delivered on stdin. Covers clean and leaky repositories, deduplication and
determinism, redaction, repository-controlled suppression, unusual file names, symlink
escapes, input tampering (no false clean), size limits, isolation (network, environment,
mounts), cancellation and cleanup. Requires Docker and the pinned image (CI sandbox job).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from scanner_support import lease, make_repository, synthetic_aws_key, synthetic_github_token
from sentinel_worker.execution.leases import FailureReason, JobOutcome
from sentinel_worker.execution.runner import ExecutionResult
from sentinel_worker.repository.snapshot import LocalFixtureRepositorySource, snapshot_directory
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxStatus
from sentinel_worker.sandbox.isolation import probe_command, verify
from sentinel_worker.sandbox.policy import GITLEAKS_IMAGE, JOB_LABEL, SANDBOX_LABEL
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.gitleaks import GitleaksAdapter

pytestmark = pytest.mark.sandbox

ADAPTER = GitleaksAdapter()
TOKEN = synthetic_github_token(11)
OTHER_TOKEN = synthetic_github_token(12)
AWS_KEY = synthetic_aws_key(13)


@pytest.fixture(scope="module")
def gitleaks_cli(docker_cli: DockerCli) -> DockerCli:
    """The Docker CLI with the pinned Gitleaks image present (never pulled here)."""
    probe = docker_cli.call(["image", "inspect", GITLEAKS_IMAGE])
    if probe.returncode != 0:
        problem = f"Gitleaks image not present; pull {GITLEAKS_IMAGE}"
        if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    return docker_cli


def sandbox(cli: DockerCli, **overrides: Any) -> DockerSandbox:
    policy = ADAPTER.policy(timeout_seconds=60)
    if overrides:
        import dataclasses

        policy = dataclasses.replace(policy, **overrides)
    return DockerSandbox(cli, policy, monitor_interval=0.5)


def scan(
    cli: DockerCli, root: Path, name: str, stop: threading.Event | None = None, **overrides: Any
) -> ExecutionResult:
    executor = ScannerExecutor(
        sandbox(cli, **overrides), ADAPTER, LocalFixtureRepositorySource(root)
    )
    return executor.execute(lease(name), stop or threading.Event())


def document(result: ExecutionResult) -> dict[str, Any]:
    assert result.outcome is JobOutcome.COMPLETED, result
    (artifact,) = result.artifacts
    for secret in (TOKEN, OTHER_TOKEN, AWS_KEY):
        assert secret.encode() not in artifact.content
    parsed: dict[str, Any] = json.loads(artifact.content)
    return parsed


def located(findings: dict[str, Any]) -> list[tuple[str, int, str]]:
    return [
        (f["location"]["path"], f["location"]["start_line"], f["rule_id"])
        for f in findings["findings"]
    ]


def containers(cli: DockerCli, label: str) -> list[str]:
    result = cli.call(["ps", "--all", "--filter", f"label={label}", "--format", "{{.Names}}"])
    return result.stdout.decode().split()


# --- Detection -----------------------------------------------------------------------


def test_a_clean_repository_has_no_findings(gitleaks_cli: DockerCli, tmp_path: Path) -> None:
    make_repository(tmp_path, "clean", {"app.py": "print('hello')\n", "README.md": "# Demo\n"})

    findings = document(scan(gitleaks_cli, tmp_path, "clean"))

    assert findings["finding_count"] == 0
    assert findings["execution"] == {
        "status": "NO_FINDINGS",
        "exit_code": 0,
        "raw_report_sha256": findings["execution"]["raw_report_sha256"],
    }
    assert findings["input"]["files_scanned"] == 2


def test_synthetic_secrets_are_found_redacted_and_deduplicated(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "leaky",
        {
            "src/settings.py": f'DEBUG = False\nGITHUB_TOKEN = "{TOKEN}"\n',
            "deploy/aws.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
            "copies.txt": f"{OTHER_TOKEN}\n{OTHER_TOKEN}\n",
            "clean.txt": "nothing here\n",
        },
    )

    first = document(scan(gitleaks_cli, tmp_path, "leaky"))
    second = document(scan(gitleaks_cli, tmp_path, "leaky"))

    assert located(first) == [
        ("copies.txt", 1, "github-pat"),
        ("copies.txt", 2, "github-pat"),
        ("deploy/aws.env", 1, "aws-access-token"),
        ("src/settings.py", 2, "github-pat"),
    ]
    assert first["execution"]["exit_code"] == 41
    assert all(f["evidence"] == {"redacted": True, "excerpt": None} for f in first["findings"])
    assert [f["fingerprint"] for f in first["findings"]] == [
        f["fingerprint"] for f in second["findings"]
    ]
    assert first["input"]["content_sha256"] == second["input"]["content_sha256"]


def test_the_raw_secret_never_leaves_the_sandbox(gitleaks_cli: DockerCli, tmp_path: Path) -> None:
    repository = make_repository(tmp_path, "raw", {"key.txt": f"token={TOKEN}\n"})
    snapshot = snapshot_directory(str(repository))

    run = sandbox(gitleaks_cli).run(
        ADAPTER.command(snapshot), threading.Event(), stdin=ADAPTER.stdin(snapshot)
    )

    assert run.status is SandboxStatus.EXITED
    assert run.exit_code == 41
    assert TOKEN.encode() not in run.stdout
    assert TOKEN not in run.stderr_excerpt


def test_repository_controlled_suppression_is_ignored(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "suppressing",
        {
            "app.py": f'TOKEN = "{TOKEN}"\n',
            "inline.py": f'TOKEN = "{OTHER_TOKEN}"  # gitleaks:allow\n',
            ".gitleaks.toml": "title = 'allow everything'\n[allowlist]\npaths = ['''.*''']\n",
            ".gitleaksignore": "app.py:github-pat:1\n/tmp/input/repo/app.py:github-pat:1\n",
        },
    )

    findings = document(scan(gitleaks_cli, tmp_path, "suppressing"))

    assert [path for path, _, _ in located(findings)] == ["app.py", "inline.py"]
    assert findings["input"]["skipped"]["suppression_file"] == 1


def test_unusual_and_hostile_file_names_are_scanned_as_data(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    names = [
        "ünï cødé/ファイル.txt",
        "$(touch pwned);`id`.sh",
        "-rf --no-preserve-root.txt",
        "rtl-‮gnp.txt",  # displays as "rtl-txt.png"
    ]
    if sys.platform != "win32":  # characters Windows does not allow in names
        names += ["quote'\"name.txt", "pipe|star*question?.txt"]
    make_repository(tmp_path, "names", {name: f"key = {TOKEN}\n" for name in names})

    findings = document(scan(gitleaks_cli, tmp_path, "names"))

    assert sorted(path for path, _, _ in located(findings)) == sorted(names)


def test_file_names_cannot_hide_secrets_from_the_ruleset(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    """Regression (security review D1): upstream's default ruleset skips files by name
    (global and rule-level path allowlists), which a repository author controls. The
    worker's ruleset has no path allowlists, so every one of these is reported."""
    content = f'TOKEN = "{TOKEN}"\n'
    hiding_places = [
        "creds.png",
        "tool.exe",
        "report.pdf",
        "go.sum",
        "package-lock.json",
        "node_modules/pkg/config.js",
        "vendor/github.com/x/y.go",
        "gitleaks.toml/hidden.py",
        "my.gitleaks.toml.py",
        "@octokit/auth-token/README.md",
        ".venv/lib/python3.12/site.py",
        "verification-metadata.xml",
    ]
    make_repository(tmp_path, "hiding", dict.fromkeys(hiding_places, content))

    findings = document(scan(gitleaks_cli, tmp_path, "hiding"))

    found = {path for path, _, rule in located(findings) if rule == "github-pat"}
    assert found == set(hiding_places)


def test_symlink_escapes_never_reach_the_scanner(gitleaks_cli: DockerCli, tmp_path: Path) -> None:
    host_secret = tmp_path / "host-credentials.txt"
    host_secret.write_text(f"token={TOKEN}\n")
    repository = make_repository(tmp_path / "fixtures", "linked", {"ok.txt": "ok\n"})
    try:
        os.symlink(host_secret, repository / "escape.txt")
        os.symlink(tmp_path, repository / "escape-dir", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symbolic links is not permitted on this host")

    findings = document(scan(gitleaks_cli, tmp_path / "fixtures", "linked"))

    assert findings["finding_count"] == 0
    assert findings["input"]["skipped"]["symlink"] == 2
    assert findings["coverage"]["complete"] is False
    assert "FILES_SKIPPED" in findings["coverage"]["limitations"]


# --- No false clean: input verification and failures --------------------------------


def test_input_that_does_not_match_the_snapshot_is_never_a_clean_scan(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    repository = make_repository(tmp_path, "tampered", {"a.txt": f"{TOKEN}\n"})
    snapshot = snapshot_directory(str(repository))
    argv = ADAPTER.command(snapshot)
    box = sandbox(gitleaks_cli)

    wrong_count = box.run(
        [*argv[:4], "2", *argv[5:]], threading.Event(), stdin=ADAPTER.stdin(snapshot)
    )
    empty_input = box.run(argv, threading.Event(), stdin=b"")
    garbage = box.run(argv, threading.Event(), stdin=b"not a tar archive" * 100)

    assert wrong_count.exit_code == 72
    assert empty_input.exit_code in (71, 72, 75)
    assert garbage.exit_code in (71, 72, 75)
    for run in (wrong_count, empty_input, garbage):
        with pytest.raises(ScannerError) as raised:
            ADAPTER.interpret(run, snapshot, lease())
        assert raised.value.reason is FailureReason.SCANNER_ERROR


def test_an_oversized_report_fails_explicitly(gitleaks_cli: DockerCli, tmp_path: Path) -> None:
    repository = make_repository(tmp_path, "big", {"a.txt": f"{TOKEN}\n"})
    snapshot = snapshot_directory(str(repository))
    argv = ADAPTER.command(snapshot)

    run = sandbox(gitleaks_cli).run(
        [*argv[:5], "64", *argv[6:]], threading.Event(), stdin=ADAPTER.stdin(snapshot)
    )

    assert run.exit_code == 74
    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(run, snapshot, lease())
    assert raised.value.reason is FailureReason.RESOURCE_LIMIT_EXCEEDED


def test_output_beyond_the_stdout_limit_is_a_resource_failure(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(
        tmp_path, "flood", {f"f{i}.txt": f"{synthetic_github_token(100 + i)}\n" for i in range(30)}
    )

    result = scan(gitleaks_cli, tmp_path, "flood", max_stdout_bytes=4096)

    assert result.failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED


# --- Isolation, cancellation and cleanup ---------------------------------------------


def test_every_isolation_control_holds_under_the_gitleaks_policy(gitleaks_cli: DockerCli) -> None:
    secret_cli = DockerCli(
        gitleaks_cli.executable, os.environ | {"SENTINEL_WORKER_DB_PASSWORD": "must-not-leak"}
    )
    box = DockerSandbox(secret_cli, ADAPTER.policy(timeout_seconds=60), monitor_interval=0.5)

    run = box.run(probe_command(), threading.Event())

    report = verify(run, box.policy)
    assert report["healthy"], report
    assert b"must-not-leak" not in run.stdout


def test_scanner_input_on_stdin_adds_no_mount(gitleaks_cli: DockerCli, tmp_path: Path) -> None:
    """The probe, with an input archive attached, still sees only runtime mounts."""
    from sentinel_worker.sandbox.isolation import observations, unexpected_mounts

    repository = make_repository(tmp_path, "probe", {"a.txt": "a"})
    snapshot = snapshot_directory(str(repository))

    run = sandbox(gitleaks_cli).run(
        probe_command(), threading.Event(), stdin=ADAPTER.stdin(snapshot)
    )

    assert unexpected_mounts(str(observations(run)["mounts"]).split()) == []


def test_cancellation_kills_a_running_scan_and_leaves_nothing_behind(
    gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    # A large repository keeps Gitleaks busy long enough to cancel it mid-run.
    blob = ("".join(f"line {i} {'x' * 60}\n" for i in range(12000))).encode()
    make_repository(tmp_path, "slow", {f"big/{i}.txt": blob for i in range(14)})
    claimed = lease("slow")
    stop = threading.Event()
    executor = ScannerExecutor(
        sandbox(gitleaks_cli, cpus=0.2), ADAPTER, LocalFixtureRepositorySource(tmp_path)
    )
    outcome: list[ExecutionResult] = []
    worker = threading.Thread(target=lambda: outcome.append(executor.execute(claimed, stop)))
    worker.start()
    deadline = time.monotonic() + 30
    while not containers(gitleaks_cli, f"{JOB_LABEL}={claimed.job_id}"):
        assert time.monotonic() < deadline, "the sandbox never started"
        time.sleep(0.05)
    stop.set()
    worker.join(timeout=30)

    assert outcome
    assert outcome[0].failure_reason is FailureReason.WORKER_SHUTDOWN
    assert containers(gitleaks_cli, f"{JOB_LABEL}={claimed.job_id}") == []


def test_no_gitleaks_sandbox_is_left_behind(gitleaks_cli: DockerCli) -> None:
    leftovers = containers(gitleaks_cli, f"{SANDBOX_LABEL}=1")
    assert [name for name in leftovers if name.startswith("sentinel-sandbox-")] == []
    ancestors = subprocess.run(  # noqa: S603 - fixed arguments
        [
            gitleaks_cli.executable,
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"ancestor={GITLEAKS_IMAGE}",
        ],
        capture_output=True,
        check=False,
    )
    assert ancestors.stdout.strip() == b""

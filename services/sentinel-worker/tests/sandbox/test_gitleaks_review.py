# ruff: noqa: S108 - /tmp paths are inside the sandbox
"""Real-container regression tests for the Slice 1 security review (ADR-0010).

Hostile archives never extract outside the input directory and never yield a scan;
extracted content must match the snapshot exactly; nested suppression files are inert;
secrets in file names are detected and redacted; empty input is flagged; the stdin
writer never blocks on a sandbox that does not read. Requires Docker and the pinned
Gitleaks image (CI sandbox job). Synthetic credentials only.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from scanner_support import lease, make_repository, synthetic_aws_key, synthetic_github_token
from sentinel_worker.execution.leases import JobOutcome
from sentinel_worker.repository.snapshot import (
    LocalFixtureRepositorySource,
    RepositorySnapshot,
    SnapshotFile,
)
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxStatus
from sentinel_worker.sandbox.policy import GITLEAKS_IMAGE
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.gitleaks import CONFIG, GitleaksAdapter

pytestmark = pytest.mark.sandbox

ADAPTER = GitleaksAdapter()
TOKEN = synthetic_github_token(41)
OTHER = synthetic_github_token(42)
AWS = synthetic_aws_key(43)
SNAPSHOT = RepositorySnapshot(files=(SnapshotFile("a.txt", b"hello\n"),), skipped={})


@pytest.fixture(scope="module")
def cli(docker_cli: DockerCli) -> DockerCli:
    if docker_cli.call(["image", "inspect", GITLEAKS_IMAGE]).returncode != 0:
        problem = f"Gitleaks image not present; pull {GITLEAKS_IMAGE}"
        if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    return docker_cli


def sandbox(cli: DockerCli, **overrides: Any) -> DockerSandbox:
    policy = dataclasses.replace(ADAPTER.policy(timeout_seconds=60), **overrides)
    return DockerSandbox(cli, policy, monitor_interval=0.5)


def scan(cli: DockerCli, root: Path, name: str) -> dict[str, Any]:
    result = ScannerExecutor(sandbox(cli), ADAPTER, LocalFixtureRepositorySource(root)).execute(
        lease(name), threading.Event()
    )
    assert result.outcome is JobOutcome.COMPLETED, result
    (artifact,) = result.artifacts
    for secret in (TOKEN, OTHER, AWS):
        assert secret.encode() not in artifact.content
    document: dict[str, Any] = json.loads(artifact.content)
    return document


def entry(name: str, kind: bytes = tarfile.REGTYPE, data: bytes = b"", link: str = "") -> Any:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, link
    info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    return info, io.BytesIO(data) if kind == tarfile.REGTYPE else None


def crafted(*extra: Any, legit: bool = True) -> bytes:
    """The legitimate archive for SNAPSHOT, followed by hostile members."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        members = [
            entry("config", tarfile.DIRTYPE),
            entry("meta", tarfile.DIRTYPE),
            entry("repo", tarfile.DIRTYPE),
            entry("config/gitleaks.toml", data=CONFIG),
            entry("meta/paths.txt", data=b"a.txt\n"),
            entry("repo/a.txt", data=b"hello\n"),
        ]
        for info, data in (members if legit else []) + list(extra):
            archive.addfile(info, data)
    return buffer.getvalue()


# --- Hostile archives ----------------------------------------------------------------


@pytest.mark.parametrize(
    "members",
    [
        [entry("../escape.txt", data=b"x")],
        [entry("/tmp/absolute.txt", data=b"x")],
        [entry("repo/../../inner.txt", data=b"x")],
        [entry("other/x.txt", data=b"x")],
        [entry("repo/link", tarfile.SYMTYPE, link="/tmp")],
        [entry("repo/link", tarfile.SYMTYPE, link="/tmp"), entry("repo/link/evil", data=b"x")],
        [entry("repo/hard", tarfile.LNKTYPE, link="config/gitleaks.toml")],
        [entry("repo/fifo", tarfile.FIFOTYPE)],
        [entry("repo/device", tarfile.CHRTYPE)],
        [entry("repo/a.txt", data=b"replaced\n")],
    ],
    ids=[
        "leading-traversal",
        "absolute",
        "inner-traversal",
        "unknown-top-level",
        "symlink",
        "write-through-symlink",
        "hardlink",
        "fifo",
        "device",
        "duplicate-overwrite",
    ],
)
def test_hostile_archive_members_are_refused_before_extraction(
    cli: DockerCli, members: list[Any]
) -> None:
    run = sandbox(cli).run(ADAPTER.command(SNAPSHOT), threading.Event(), stdin=crafted(*members))

    assert run.status is SandboxStatus.EXITED
    assert run.exit_code == 75  # refused by the listing check, before any extraction


def test_truncated_or_tampered_input_never_yields_a_scan(cli: DockerCli) -> None:
    complete = crafted()
    argv = ADAPTER.command(SNAPSHOT)
    tampered = crafted().replace(b"hello\n", b"HELLO\n")

    results = {
        "truncated": sandbox(cli).run(
            argv, threading.Event(), stdin=complete[: len(complete) // 2]
        ),
        "cut-at-member": sandbox(cli).run(argv, threading.Event(), stdin=complete[:2048]),
        "tampered-content": sandbox(cli).run(argv, threading.Event(), stdin=tampered),
        "wrong-digest": sandbox(cli).run([*argv[:-1], "0" * 64], threading.Event(), stdin=complete),
    }

    for name, run in results.items():
        assert run.exit_code in (71, 72, 75), name
    assert results["tampered-content"].exit_code == 72
    assert results["wrong-digest"].exit_code == 72


def test_long_deep_and_unusual_names_extract_exactly(cli: DockerCli, tmp_path: Path) -> None:
    # Beyond the 100-byte ustar name field (GNU long names), within Windows' path limit.
    long_name = "d" * 20 + "/" + "f" * 110 + ".txt"
    deep = "/".join(f"l{i}" for i in range(30)) + "/deep.txt"
    names = {long_name: f"{TOKEN}\n", deep: f"{TOKEN}\n", " spaced name .txt": f"{TOKEN}\n"}
    if sys.platform != "win32":
        names["arrow -> name.txt"] = f"{TOKEN}\n"  # resembles a link in `tar -tv` output
    make_repository(tmp_path, "names", names)

    document = scan(cli, tmp_path, "names")

    contents = {f["location"]["path"] for f in document["findings"] if f["rule_id"] == "github-pat"}
    assert contents == set(names)


# --- Suppression ---------------------------------------------------------------------


def test_nested_suppression_files_are_inert(cli: DockerCli, tmp_path: Path) -> None:
    make_repository(
        tmp_path,
        "nested",
        {
            "sub/app.py": f'TOKEN = "{TOKEN}"\n',
            "sub/.gitleaks.toml": "[allowlist]\npaths = ['''.*''']\n",
            "sub/.gitleaksignore": (
                "sub/app.py:github-pat:1\n/tmp/input/repo/sub/app.py:github-pat:1\n"
            ),
            "sub/deeper/.gitleaks.toml": "[extend]\nuseDefault = false\n",
        },
    )

    document = scan(cli, tmp_path, "nested")

    assert ("sub/app.py", "github-pat") in {
        (f["location"]["path"], f["rule_id"]) for f in document["findings"]
    }
    assert document["input"]["skipped"]["suppression_file"] == 0


def test_the_image_sets_no_gitleaks_environment(cli: DockerCli) -> None:
    """Docker passes an image's own ENV to every container: an image that set
    GITLEAKS_CONFIG would change the configuration source (supply-chain guard)."""
    result = cli.call(["image", "inspect", "--format", "{{json .Config.Env}}", GITLEAKS_IMAGE])

    environment = json.loads(result.stdout)
    assert [name.split("=", 1)[0] for name in environment] == ["PATH"]


# --- Secrets in file names -----------------------------------------------------------


def test_secrets_in_file_and_directory_names_are_detected_and_redacted(
    cli: DockerCli, tmp_path: Path
) -> None:
    make_repository(
        tmp_path,
        "named",
        {
            f"keys/{TOKEN}.txt": "harmless\n",
            f"ünï/{AWS}/notes.md": "harmless\n",
            f"exports/{OTHER}.env": f'API = "{OTHER}"\n',
            "src/app.py": "print('ok')\n",
        },
    )

    document = scan(cli, tmp_path, "named")

    by_target: dict[str, set[str]] = {}
    for finding in document["findings"]:
        by_target.setdefault(finding["location"]["target"], set()).add(finding["location"]["path"])
        if finding["location"]["target"] == "FILE_PATH":
            assert finding["location"]["path_redacted"] is True
            assert finding["location"]["start_line"] is None
    assert len(by_target["FILE_PATH"]) == 3
    assert all("[redacted-" in path for path in by_target["FILE_PATH"])
    # The content finding in the secret-named file uses the same safe path.
    assert by_target["FILE_CONTENT"] <= by_target["FILE_PATH"]
    assert document["input"]["paths_redacted"] == 3
    assert document["execution"]["exit_code"] == 43


def test_an_empty_repository_is_flagged_not_clean(cli: DockerCli, tmp_path: Path) -> None:
    (tmp_path / "acme" / "empty").mkdir(parents=True)

    document = scan(cli, tmp_path, "empty")

    assert document["finding_count"] == 0
    assert document["execution"]["exit_code"] == 0
    assert "EMPTY_INPUT" in document["coverage"]["limitations"]


# --- Stdin writer --------------------------------------------------------------------


def writer_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "sentinel-sandbox-writer"]


def test_a_sandbox_that_exits_without_reading_stdin_never_blocks_the_writer(
    cli: DockerCli,
) -> None:
    started = time.monotonic()

    run = sandbox(cli).run(["/bin/sh", "-c", "exit 3"], threading.Event(), stdin=b"\0" * (30 << 20))

    assert (run.status, run.exit_code) == (SandboxStatus.EXITED, 3)
    assert time.monotonic() - started < 30
    assert run.removed
    assert writer_threads() == []


def test_stopping_during_the_transfer_kills_the_sandbox_and_releases_the_writer(
    cli: DockerCli,
) -> None:
    # The sandbox never reads stdin, so the 30 MiB transfer blocks until it is stopped.
    # Cancellation, lease loss and worker shutdown all set this same stop event (LeaseKeeper,
    # ExecutionLoop.request_shutdown).
    stop = threading.Event()
    threading.Timer(1.5, stop.set).start()
    started = time.monotonic()

    run = sandbox(cli).run(["/bin/sh", "-c", "sleep 60"], stop, stdin=b"\0" * (30 << 20))

    assert run.status is SandboxStatus.CANCELLED
    assert time.monotonic() - started < 25
    assert run.removed
    assert writer_threads() == []

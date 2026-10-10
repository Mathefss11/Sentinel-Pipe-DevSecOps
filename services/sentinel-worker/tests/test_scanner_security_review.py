# ruff: noqa: S108 - /tmp paths are inside the sandbox, as Gitleaks reports them
"""Regression tests for the M3 Phase 2 Slice 1 security review (ADR-0010).

D2  secrets in file names never reach findings, fingerprints or logs in raw form;
D3  snapshot and archive invariants; extraction digest; empty input is not "clean";
D4  scanner errors carry no exception chain or content;
plus the stdin writer's cleanup when the runtime CLI fails, and the trust policy.
Synthetic credentials only, generated at run time.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from scanner_support import (
    envelope,
    exited,
    lease,
    make_repository,
    paths_entry,
    report_entry,
    synthetic_aws_key,
    synthetic_github_token,
)
from sentinel_worker.execution.leases import FailureReason, JobOutcome
from sentinel_worker.messaging import contracts
from sentinel_worker.repository.snapshot import (
    LocalFixtureRepositorySource,
    RepositorySnapshot,
    SnapshotFile,
    snapshot_directory,
)
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxStatus
from sentinel_worker.sandbox.policy import SandboxPolicy, Workload
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.findings import FINGERPRINT_DOMAIN, canonical_json_value
from sentinel_worker.scanners.gitleaks import GitleaksAdapter
from sentinel_worker.scanners.paths import components_in_byte_window, safe_paths, suspicious

ADAPTER = GitleaksAdapter()
TOKEN = synthetic_github_token(31)
OTHER = synthetic_github_token(32)
AWS = synthetic_aws_key(33)


def snapshot(*paths: str) -> RepositorySnapshot:
    return RepositorySnapshot(
        files=tuple(SnapshotFile(path, b"x") for path in sorted(paths)), skipped={}
    )


def run_report(content: list[dict[str, Any]], paths: list[dict[str, Any]], code: int) -> Any:
    return exited(code, envelope(json.dumps(content).encode(), json.dumps(paths).encode()))


def document_of(snap: RepositorySnapshot, run: Any) -> tuple[dict[str, Any], bytes]:
    (artifact,) = ADAPTER.interpret(run, snap, lease())
    document: dict[str, Any] = json.loads(artifact.content)
    assert list(contracts.validator(contracts.FINDINGS_SCHEMA).iter_errors(document)) == []
    return document, artifact.content


# --- D2: secrets in file names -------------------------------------------------------


def test_the_heuristic_flags_credential_shaped_names_only() -> None:
    for name in (f"{TOKEN}.txt", f"{AWS}", f"backup-{OTHER}", "xoxb-1234567890-abcdefghij"):
        assert suspicious(name), name
    for name in (
        "test_repository_snapshot_with_a_long_name.py",
        "README.md",
        "docker-compose.override.yml",
        "2026-10-10-release-notes.md",
        "ünï cødé.txt",
    ):
        assert not suspicious(name), name


def test_safe_paths_redact_components_consistently_and_deterministically() -> None:
    paths = [f"keys/{TOKEN}.txt", f"{AWS}/a.txt", f"{AWS}/b.txt", "src/app.py"]

    first, second = safe_paths(paths), safe_paths(list(reversed(paths)))

    assert first == second
    assert first["src/app.py"].value == "src/app.py"
    assert not first["src/app.py"].redacted
    assert first[f"{AWS}/a.txt"].value.split("/")[0] == first[f"{AWS}/b.txt"].value.split("/")[0]
    assert first[f"keys/{TOKEN}.txt"].value.startswith("keys/[redacted-")
    rendered = json.dumps({path: value.value for path, value in first.items()})
    for secret in (TOKEN, AWS):
        assert all(secret not in value.value for value in first.values())
        assert rendered.count(secret) == sum(1 for p in paths if secret in p)  # keys only


def test_a_detected_component_is_redacted_wherever_it_occurs() -> None:
    harmless_looking = "release-candidate"  # not suspicious by itself
    paths = [f"{harmless_looking}/a.txt", f"{harmless_looking}/b.txt"]

    result = safe_paths(paths, {0: {0}})

    assert result[paths[0]].value == "[redacted-1]/a.txt"
    assert result[paths[1]].value == "[redacted-1]/b.txt"
    assert result[paths[1]].redacted


def test_byte_windows_map_gitleaks_columns_onto_components() -> None:
    path = f"ünï/{TOKEN}.txt"
    start = len("ünï/".encode())  # 0-based byte offset of the token

    assert components_in_byte_window(path, start - 1, start + 40) == {1}
    assert components_in_byte_window("a/b/c", 0, 0) == {0}
    assert components_in_byte_window("a/b/c", 1, 1) == set()  # the separator only


def test_a_secret_in_a_file_name_becomes_a_redacted_path_finding() -> None:
    snap = snapshot(f"config/{TOKEN}.json", "src/app.py")
    # Gitleaks' columns on line 1 of paths.txt: "config/" is 7 bytes, so start = 8.
    paths = [paths_entry(1, 8, 47)]
    content = [report_entry(f"config/{TOKEN}.json", RuleID="generic-api-key")]

    document, raw = document_of(snap, run_report(content, paths, 43))

    assert TOKEN.encode() not in raw
    by_target = {f["location"]["target"]: f for f in document["findings"]}
    path_finding, content_finding = by_target["FILE_PATH"], by_target["FILE_CONTENT"]
    assert path_finding["location"] == {
        "target": "FILE_PATH",
        "path": "config/[redacted-1]",
        "path_redacted": True,
        "start_line": None,
        "end_line": None,
        "start_column": None,
        "end_column": None,
    }
    assert content_finding["location"]["path"] == "config/[redacted-1]"
    assert content_finding["location"]["path_redacted"] is True
    assert document["input"]["paths_redacted"] == 1
    assert document["execution"]["exit_code"] == 43


def test_fingerprints_use_only_the_safe_path() -> None:
    snap = snapshot(f"config/{TOKEN}.json")
    document, _ = document_of(snap, run_report([], [paths_entry(1, 8, 47)], 42))

    (finding,) = document["findings"]
    expected = hashlib.sha256(
        canonical_json_value(
            [
                FINGERPRINT_DOMAIN,
                "gitleaks",
                "github-pat",
                "FILE_PATH",
                "config/[redacted-1]",
                None,
                None,
                None,
                None,
            ]
        )
    ).hexdigest()
    assert finding["fingerprint"] == expected
    # The same secret-named file in another snapshot yields the same fingerprint, and a
    # different secret in the same place does too: the name never shapes the identity.
    other, _ = document_of(
        snapshot(f"config/{OTHER}.json"), run_report([], [paths_entry(1, 8, 47)], 42)
    )
    assert other["findings"][0]["fingerprint"] == expected


def test_names_flagged_only_by_the_heuristic_are_redacted_without_a_finding() -> None:
    unknown_format = "k9Xq2Lm7Pz4Rt8Vw1Ny6Bc3"  # high-entropy, no scanner rule
    snap = snapshot(f"secrets/{unknown_format}.key", "src/app.py")
    content = [report_entry("src/app.py")]

    document, raw = document_of(snap, run_report(content, [], 41))

    assert unknown_format.encode() not in raw
    assert document["input"]["paths_redacted"] == 1
    assert [f["location"]["target"] for f in document["findings"]] == ["FILE_CONTENT"]


@pytest.mark.parametrize(
    "entry",
    [
        paths_entry(0, 1, 5),
        paths_entry(3, 1, 5),
        paths_entry(1, 1, 5, File="/tmp/input/repo/paths.txt"),
        paths_entry(1, 1, 5, EndLine=2),
    ],
    ids=["line-zero", "line-out-of-range", "wrong-file", "multi-line"],
)
def test_path_detections_must_point_at_a_manifest_line(entry: dict[str, Any]) -> None:
    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(run_report([], [entry], 42), snapshot("a.txt", "b.txt"), lease())

    assert raised.value.code in ("UNKNOWN_PATH", "INVALID_REPORT")


@pytest.mark.parametrize(
    ("code", "content", "paths"),
    [(41, False, True), (42, True, False), (43, True, False), (0, False, True)],
)
def test_exit_codes_must_agree_with_both_reports(code: int, content: bool, paths: bool) -> None:
    snap = snapshot("a.txt")
    run = run_report(
        [report_entry("a.txt")] if content else [], [paths_entry(1, 1, 5)] if paths else [], code
    )

    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(run, snap, lease())

    assert raised.value.code == "INCONSISTENT_EXIT_CODE"


def test_logs_never_contain_file_names(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from test_gitleaks_adapter import ScriptedSandbox

    make_repository(tmp_path, "repo", {f"keys/{TOKEN}.txt": "x", "missing-name.txt": "y"})
    # A report naming a file outside the snapshot fails; neither path is ever logged.
    bad = run_report([report_entry(f"keys/{TOKEN}.txt/../../{OTHER}")], [], 41)
    sandbox = ScriptedSandbox(bad)
    executor = ScannerExecutor(sandbox, ADAPTER, LocalFixtureRepositorySource(tmp_path))  # type: ignore[arg-type]

    with caplog.at_level(logging.DEBUG):
        result = executor.execute(lease("repo"), threading.Event())

    assert result.failure_reason is FailureReason.SCANNER_ERROR
    for secret in (TOKEN, OTHER, "missing-name"):
        assert secret not in caplog.text


# --- D3: snapshot and archive invariants ---------------------------------------------


@pytest.mark.parametrize(
    "paths",
    [
        ("b.txt", "a.txt"),
        ("a.txt", "a.txt"),
        ("../escape.txt",),
        ("/etc/passwd",),
        ("a/../../b",),
        ("a//b",),
        ("a/",),
        ("a\\b",),
        ("new\nline",),
        ("a", "a/b"),
        ("",),
    ],
    ids=[
        "unsorted",
        "duplicate",
        "traversal",
        "absolute",
        "nested-traversal",
        "empty-part",
        "trailing-slash",
        "backslash",
        "newline",
        "file-and-directory",
        "empty",
    ],
)
def test_snapshots_refuse_unsafe_or_ambiguous_paths(paths: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="snapshot"):
        RepositorySnapshot(files=tuple(SnapshotFile(p, b"x") for p in paths), skipped={})


def test_archives_cannot_overwrite_or_escape(tmp_path: Path) -> None:
    snap = snapshot("a.txt", "dir/b.txt")

    for extra in ({"config/../repo/x": b""}, {"/abs": b""}, {"config//x": b""}, {"repo/x": b""}):
        with pytest.raises(ValueError, match="outside"):
            snap.archive("repo", extra)
    with pytest.raises(ValueError, match="unique"):
        snap.archive("repo", {"meta": b"", "meta/x": b""})

    with tarfile.open(fileobj=io.BytesIO(snap.archive("repo", {"meta/p.txt": b"x"}))) as opened:
        members = opened.getmembers()
    names = [member.name for member in members]
    assert len(names) == len(set(names))
    for member in members:
        assert member.isfile() or member.isdir()
        assert not member.name.startswith("/")
        assert ".." not in member.name.split("/")
        assert member.linkname == ""
        assert member.mode & ~0o755 == 0  # no setuid, setgid, sticky or world-write bits
        assert (member.uid, member.gid, member.mtime) == (0, 0, 0)


def test_the_extraction_digest_is_what_sha256sum_reports(tmp_path: Path) -> None:
    files = {"b dir/x.txt": "x", "a.txt": "a", "ünï.txt": "u", "-dash.txt": "d"}
    snap = snapshot_directory(str(make_repository(tmp_path, "repo", files)))

    # Independent computation in the format of BusyBox `sha256sum ./<path>`, sorted by
    # the byte order of the paths (as `LC_ALL=C sort` orders `find .` output).
    lines = sorted(
        (f"./{path}".encode(), hashlib.sha256(content.encode()).hexdigest())
        for path, content in files.items()
    )
    expected = hashlib.sha256(b"".join(h.encode() + b"  " + p + b"\n" for p, h in lines))

    assert snap.extraction_sha256 == expected.hexdigest()


def test_an_empty_repository_is_never_reported_as_clean_coverage() -> None:
    empty = RepositorySnapshot(files=(), skipped={})

    document, _ = document_of(empty, run_report([], [], 0))

    assert document["finding_count"] == 0
    assert document["input"]["files_scanned"] == 0
    assert "EMPTY_INPUT" in document["coverage"]["limitations"]


# --- D4: no exception chains, no content in errors -----------------------------------


@pytest.mark.parametrize(
    "stdout",
    [
        envelope(f'[{{"Secret": "{TOKEN}"'.encode()),
        envelope(f'{{"x": "{TOKEN}", "x": 1}}'.encode()),
        f'{{"artifacts": "{TOKEN}"}}'.encode(),
        TOKEN.encode() + b"\xff",
    ],
    ids=["truncated-json", "duplicate-keys", "bad-envelope", "garbage"],
)
def test_scanner_errors_carry_no_content_and_no_exception_chain(
    stdout: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG), pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(exited(41, stdout), snapshot("a.txt"), lease())

    error = raised.value
    assert error.__context__ is None
    assert error.__cause__ is None
    assert TOKEN not in str(error) + repr(error) + error.code
    assert TOKEN not in caplog.text


def test_scanner_stderr_is_never_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from sentinel_worker.sandbox.docker import SandboxRun
    from test_gitleaks_adapter import ScriptedSandbox

    make_repository(tmp_path, "repo", {"a.txt": "a"})
    noisy = SandboxRun(SandboxStatus.EXITED, 70, b"", f"error reading {TOKEN}", 0.1, 1, 1, True)
    executor = ScannerExecutor(
        ScriptedSandbox(noisy),
        ADAPTER,
        LocalFixtureRepositorySource(tmp_path),  # type: ignore[arg-type]
    )

    with caplog.at_level(logging.DEBUG):
        result = executor.execute(lease("repo"), threading.Event())

    assert result.failure_reason is FailureReason.SCANNER_ERROR
    assert TOKEN not in caplog.text


# --- Stdin writer: a failing runtime CLI never blocks or leaks threads ---------------


def writer_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "sentinel-sandbox-writer"]


def test_a_runtime_cli_that_exits_without_reading_stdin_releases_the_writer() -> None:
    # The "CLI" is the Python interpreter: it fails at once on Docker's arguments, without
    # reading stdin, while 30 MiB are being written to it.
    sandbox = DockerSandbox(
        DockerCli(sys.executable), ADAPTER.policy(timeout_seconds=30), monitor_interval=60
    )
    started = time.monotonic()

    run = sandbox.run(["/bin/sh", "-c", "exit 0"], threading.Event(), stdin=b"\0" * (30 << 20))

    assert run.status is SandboxStatus.START_FAILED
    assert time.monotonic() - started < 20
    assert writer_threads() == []


def test_oversized_stdin_is_refused_before_anything_starts() -> None:
    sandbox = DockerSandbox(DockerCli(sys.executable), SandboxPolicy(), monitor_interval=60)

    with pytest.raises(ValueError, match="stdin"):
        sandbox.run(["/bin/sh"], threading.Event(), stdin=b"x")
    assert writer_threads() == []


# --- Trust boundary ------------------------------------------------------------------


def test_gitleaks_runs_only_as_a_trusted_tool_and_never_as_untrusted_code() -> None:
    import dataclasses

    policy = ADAPTER.policy()

    assert policy.workload is Workload.TRUSTED_TOOL
    assert policy.runtime is None  # runc unless an allowlisted hardened runtime is configured
    with pytest.raises(ValueError, match="untrusted code"):
        dataclasses.replace(policy, workload=Workload.UNTRUSTED_CODE)
    assert ADAPTER.policy(runtime="runsc").runtime == "runsc"


def test_the_executor_warns_that_runc_is_not_a_boundary_for_hostile_content(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from test_gitleaks_adapter import ScriptedSandbox

    with caplog.at_level(logging.WARNING):
        ScannerExecutor(
            ScriptedSandbox(exited(0)),
            ADAPTER,
            LocalFixtureRepositorySource(tmp_path),  # type: ignore[arg-type]
        )

    assert "scanner.runc_boundary" in caplog.text


def test_completed_scans_with_findings_are_completed_not_failed(tmp_path: Path) -> None:
    from test_gitleaks_adapter import ScriptedSandbox

    make_repository(tmp_path, "repo", {"a.txt": "a"})
    executor = ScannerExecutor(
        ScriptedSandbox(run_report([report_entry("a.txt")], [], 41)),  # type: ignore[arg-type]
        ADAPTER,
        LocalFixtureRepositorySource(tmp_path),
    )

    result = executor.execute(lease("repo"), threading.Event())

    assert result.outcome is JobOutcome.COMPLETED

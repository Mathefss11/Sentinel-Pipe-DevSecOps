# ruff: noqa: S108 - /tmp paths are inside the sandbox, as Gitleaks reports them
"""The Gitleaks adapter and the scanner executor without containers (ADR-0010).

Exit-code semantics, strict parsing of untrusted reports, redaction checks, normalization
and deduplication, evidence bounds, input failures and settings. The real container is
exercised in tests/sandbox/test_gitleaks_sandbox.py.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from scanner_support import envelope, exited, lease, make_repository, report_entry
from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.execution.leases import FailureReason, JobLease, JobOutcome
from sentinel_worker.execution.runner import ExecutionResult
from sentinel_worker.execution.settings import ExecutionSettings
from sentinel_worker.messaging import contracts
from sentinel_worker.repository.snapshot import (
    InputError,
    InputErrorCode,
    LocalFixtureRepositorySource,
    RepositorySnapshot,
    SnapshotFile,
)
from sentinel_worker.sandbox.docker import SandboxRun, SandboxStatus
from sentinel_worker.sandbox.policy import GITLEAKS_IMAGE, new_sandbox_name, run_arguments
from sentinel_worker.scanners import findings as findings_module
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.executor import DispatchingExecutor, ScannerExecutor
from sentinel_worker.scanners.gitleaks import GitleaksAdapter

ADAPTER = GitleaksAdapter()
SNAPSHOT = RepositorySnapshot(
    files=(
        SnapshotFile("app.py", b"x"),
        SnapshotFile("config/ünï cødé.env", b"y"),
        SnapshotFile("z.txt", b"z"),
    ),
    skipped={},
)


def report(*entries: dict[str, Any]) -> bytes:
    return envelope(json.dumps(list(entries)).encode("utf-8"))


def interpret(run: SandboxRun, claimed: JobLease | None = None) -> dict[str, Any]:
    (artifact,) = ADAPTER.interpret(run, SNAPSHOT, claimed or lease())
    assert artifact.name == "findings.json"
    assert artifact.media_type == "application/json"
    document: dict[str, Any] = json.loads(artifact.content)
    validator = contracts.validator(contracts.FINDINGS_SCHEMA)
    assert list(validator.iter_errors(document)) == []
    return document


def failure(run: SandboxRun) -> ScannerError:
    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(run, SNAPSHOT, lease())
    return raised.value


# --- Successful runs -----------------------------------------------------------------


def test_a_clean_run_is_completed_without_findings_and_is_not_a_decision() -> None:
    claimed = lease()

    document = interpret(exited(0, report()), claimed)

    assert document["finding_count"] == 0
    assert document["findings"] == []
    assert document["execution"]["status"] == "NO_FINDINGS"
    assert document["context"]["job_id"] == str(claimed.job_id)
    assert document["context"]["organization_id"] == str(claimed.organization_id)
    assert document["input"]["commit_verified"] is False
    assert "COMMIT_NOT_VERIFIED" in document["coverage"]["limitations"]
    assert "decision" not in json.dumps(document).lower()


def test_findings_are_normalized_without_invented_attributes() -> None:
    document = interpret(
        exited(41, report(report_entry("config/ünï cødé.env", StartLine=3, EndLine=4)))
    )

    (finding,) = document["findings"]
    assert finding["rule_id"] == "github-pat"
    assert finding["category"] == "SECRET"
    assert finding["location"] == {
        "target": "FILE_CONTENT",
        "path": "config/ünï cødé.env",
        "path_redacted": False,
        "start_line": 3,
        "end_line": 4,
        "start_column": 10,
        "end_column": 49,
    }
    assert finding["severity"] is None
    assert finding["confidence"] is None
    assert finding["remediation"] is None
    assert finding["evidence"] == {"redacted": True, "excerpt": None}
    assert finding["status"] == "OPEN"
    assert finding["scanner"] == {"name": "gitleaks", "version": "8.30.1"}
    assert document["scanner"]["image"] == GITLEAKS_IMAGE
    assert document["execution"] == {
        "status": "FINDINGS_DETECTED",
        "exit_code": 41,
        "raw_report_sha256": document["execution"]["raw_report_sha256"],
    }


def test_multiple_findings_are_sorted_and_duplicates_merged_deterministically() -> None:
    entries = [
        report_entry("z.txt", StartLine=9, EndLine=9),
        report_entry("app.py", StartLine=2, EndLine=2),
        report_entry("app.py", StartLine=2, EndLine=2),  # same location and rule
        report_entry("app.py", RuleID="generic-api-key", StartLine=2, EndLine=2),
    ]
    claimed = lease()

    first = ADAPTER.interpret(exited(41, report(*entries)), SNAPSHOT, claimed)[0].content
    second = ADAPTER.interpret(exited(41, report(*reversed(entries))), SNAPSHOT, claimed)[0].content
    document = json.loads(first)

    assert document["finding_count"] == 3
    assert [
        (f["location"]["path"], f["rule_id"], f["occurrences"]) for f in document["findings"]
    ] == [
        ("app.py", "generic-api-key", 1),
        ("app.py", "github-pat", 2),
        ("z.txt", "github-pat", 1),
    ]
    # Identical findings, same bytes, regardless of the scanner's (concurrent) output order.
    assert json.loads(second)["findings"] == document["findings"]
    fingerprints = [f["fingerprint"] for f in document["findings"]]
    assert len(set(fingerprints)) == 3
    ids = {f["id"] for f in document["findings"]}
    assert len(ids) == 3
    # Ids are per job; fingerprints are not.
    other = json.loads(
        ADAPTER.interpret(exited(41, report(*entries)), SNAPSHOT, lease())[0].content
    )
    assert [f["fingerprint"] for f in other["findings"]] == fingerprints
    assert {f["id"] for f in other["findings"]}.isdisjoint(ids)


def test_scanner_prose_is_sanitized() -> None:
    # Assembled at run time: no credential-shaped literal in the source tree.
    description = "Leaked\x1b[31m value " + "AKIA" + "ABCDEFGHIJKLMNOPQRSTUV" + "\nin file"

    document = interpret(exited(41, report(report_entry("app.py", Description=description))))

    assert document["findings"][0]["description"] == "Leaked [31m value [redacted] in file"


# --- Exit-code semantics and failures ------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected_code", "reason"),
    [
        (70, "GITLEAKS_FAILED", FailureReason.SCANNER_ERROR),
        (71, "INPUT_EXTRACTION_FAILED", FailureReason.SCANNER_ERROR),
        (72, "INPUT_VERIFICATION_FAILED", FailureReason.SCANNER_ERROR),
        (73, "REPORT_MISSING", FailureReason.SCANNER_ERROR),
        (74, "REPORT_TOO_LARGE", FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (75, "INPUT_REJECTED", FailureReason.SCANNER_ERROR),
        (1, "UNEXPECTED_EXIT_CODE", FailureReason.SCANNER_ERROR),
        (2, "UNEXPECTED_EXIT_CODE", FailureReason.SCANNER_ERROR),
        (137, "TERMINATED", FailureReason.SANDBOX_ERROR),
        (None, "TERMINATED", FailureReason.SANDBOX_ERROR),
    ],
)
def test_nonzero_exit_codes_are_failures_never_clean_scans(
    code: int | None, expected_code: str, reason: FailureReason
) -> None:
    # Even with a well-formed, empty report on stdout.
    raised = failure(exited(code, report()))

    assert (raised.code, raised.reason) == (expected_code, reason)


def test_exit_codes_must_agree_with_the_report() -> None:
    assert failure(exited(0, report(report_entry("app.py")))).code == "INCONSISTENT_EXIT_CODE"
    assert failure(exited(41, report())).code == "INCONSISTENT_EXIT_CODE"


@pytest.mark.parametrize(
    ("stdout", "code"),
    [
        (b"", "INVALID_OUTPUT"),
        (b"not json", "INVALID_OUTPUT"),
        (envelope(b"[]", name="other.json"), "INVALID_OUTPUT"),
        (envelope(b"{not json"), "INVALID_REPORT"),
        (envelope(b'{"RuleID": "x"}'), "INVALID_REPORT"),
        (envelope(b"[NaN]"), "INVALID_REPORT"),
        (envelope(b"\xff\xfe"), "INVALID_REPORT"),
        (envelope(b"[" * 100000 + b"]" * 100000), "INVALID_REPORT"),
        (envelope(b'[{"RuleID":"a","RuleID":"b"}]'), "INVALID_REPORT"),
    ],
    ids=[
        "empty",
        "garbage",
        "artifact-name",
        "report-json",
        "not-a-list",
        "nan",
        "utf8",
        "deep-nesting",
        "duplicate-keys",
    ],
)
def test_malformed_output_fails_closed_with_a_code(stdout: bytes, code: str) -> None:
    raised = failure(exited(0, stdout))

    assert raised.code == code
    assert raised.reason is FailureReason.SCANNER_ERROR


@pytest.mark.parametrize(
    "overrides",
    [
        {"Extra": "field"},
        {"Commit": "deadbeef"},
        {"Email": "someone@example.com"},
        {"SymlinkFile": "/etc/passwd"},
        {"RuleID": "bad rule id"},
        {"RuleID": 7},
        {"StartLine": 0},
        {"StartLine": True},
        {"StartLine": 5, "EndLine": 4},
        {"StartColumn": -1},
        {"Description": None},
    ],
)
def test_unexpected_report_entries_are_refused(overrides: dict[str, Any]) -> None:
    entry = report_entry("app.py", **overrides)
    if "Extra" in overrides:
        entry["Extra"] = overrides["Extra"]

    assert failure(exited(41, report(entry))).code == "INVALID_REPORT"


@pytest.mark.parametrize(
    "file",
    [
        "/tmp/input/repo/not-in-snapshot.py",
        "/tmp/input/repo/../config/gitleaks.toml",
        "/etc/passwd",
        "/tmp/input/config/gitleaks.toml",
        "app.py",
    ],
)
def test_only_files_of_the_snapshot_can_be_reported(file: str) -> None:
    entry = report_entry("app.py", File=file)

    assert failure(exited(41, report(entry))).code == "UNKNOWN_PATH"


def test_an_unredacted_report_fails_closed_without_revealing_the_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "ghp" + "_" + "Unredacted" * 3 + "Value1"
    entries = [
        report_entry("app.py", Secret=secret, Match=secret),
        report_entry("app.py", Match=f"token = {secret}"),
    ]
    for entry in entries:
        with caplog.at_level(logging.DEBUG):
            raised = failure(exited(41, report(entry)))

        assert raised.code == "UNREDACTED_REPORT"
        assert secret not in str(raised)
        assert secret not in repr(raised)
    assert secret not in caplog.text


def test_findings_beyond_the_supported_bounds_fail_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(findings_module, "MAX_FINDINGS", 2)
    entries = [report_entry("app.py", StartLine=line, EndLine=line) for line in range(1, 4)]

    raised = failure(exited(41, report(*entries)))

    assert (raised.code, raised.reason) == (
        "FINDINGS_LIMIT_EXCEEDED",
        FailureReason.RESOURCE_LIMIT_EXCEEDED,
    )


def test_raw_report_entries_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinel_worker.scanners import gitleaks

    monkeypatch.setattr(gitleaks, "MAX_REPORT_ENTRIES", 1)

    raised = failure(exited(41, report(report_entry("app.py"), report_entry("z.txt"))))

    assert raised.reason is FailureReason.RESOURCE_LIMIT_EXCEEDED


# --- Command, input and policy -------------------------------------------------------


def test_the_command_is_constant_and_takes_only_worker_generated_values() -> None:
    argv = ADAPTER.command(SNAPSHOT)

    assert argv[:2] == ["/bin/sh", "-c"]
    assert argv[3:] == [
        "sentinel-gitleaks",
        "3",
        str(1024 * 1024),
        str(256 * 1024),
        SNAPSHOT.extraction_sha256,
    ]
    script = argv[2]
    for flag in (
        "--config",
        "--gitleaks-ignore-path",
        "--ignore-gitleaks-allow",
        "--redact=100",
        "--max-archive-depth 0",
        "--exit-code 42",
        "--report-format json",
    ):
        assert flag in script, flag
    # Nothing from the repository is part of the command; no option a scanner could
    # use to re-enable suppression or reach other inputs is ever passed.
    for name in SNAPSHOT.ordered_paths:
        assert all(name not in argument for argument in argv)
    for forbidden in ("--baseline-path", "--enable-rule", "--follow-symlinks", "--max-target",
                      "--diagnostics", "--report-template", "-v ", "--verbose"):  # fmt: skip
        assert forbidden not in script, forbidden


def test_the_input_carries_the_workers_ruleset_and_path_manifest_outside_the_repository() -> None:
    import io
    import tarfile

    from sentinel_worker.scanners.gitleaks import CONFIG

    with tarfile.open(fileobj=io.BytesIO(ADAPTER.stdin(SNAPSHOT))) as archive:
        names = archive.getnames()
        config = archive.extractfile("config/gitleaks.toml")
        manifest = archive.extractfile("meta/paths.txt")
        assert config is not None
        assert manifest is not None
        assert config.read() == CONFIG
        assert manifest.read() == "app.py\nconfig/ünï cødé.env\nz.txt\n".encode()
    assert "repo/app.py" in names
    assert not any(name.startswith(("repo/config/gitleaks", "repo/meta")) for name in names)


def test_the_ruleset_has_no_path_allowlists_and_keeps_every_upstream_rule() -> None:
    """Regression (security review D1): upstream's path allowlists let a repository hide
    secrets by file name (*.png, node_modules/, any path containing gitleaks.toml)."""
    import tomllib

    from sentinel_worker.scanners.gitleaks import CONFIG

    text = CONFIG.decode("utf-8")
    ruleset = tomllib.loads(text)

    assert "Gitleaks v8.30.1" in text
    assert "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf" in text
    assert "extend" not in ruleset  # a complete ruleset, not layered on built-in defaults
    assert "paths" not in ruleset["allowlist"]
    assert ruleset["allowlist"]["regexes"]
    assert ruleset["allowlist"]["stopwords"]
    assert len(ruleset["rules"]) == 222
    assert {"github-pat", "aws-access-token", "private-key", "generic-api-key"} <= {
        rule["id"] for rule in ruleset["rules"]
    }
    for rule in ruleset["rules"]:
        for allowlist in rule.get("allowlists", []):
            assert "paths" not in allowlist, rule["id"]


def test_the_gitleaks_policy_keeps_every_sandbox_control_and_mounts_nothing() -> None:
    policy = ADAPTER.policy(timeout_seconds=60)
    args = run_arguments(policy, new_sandbox_name(), ADAPTER.command(SNAPSHOT), {}, 1, True)
    joined = " ".join(args)

    assert policy.image == GITLEAKS_IMAGE
    assert 0 < policy.max_stdin_bytes <= 64 * 1024 * 1024
    for expected in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--user 65534:65534",
        "--security-opt no-new-privileges",
        "--pull never",
        "--interactive",
    ):
        assert expected in joined, expected
    for forbidden in ("-v", "--volume", "--mount", "-e", "--env", "--privileged", "docker.sock"):
        assert forbidden not in args, forbidden


def test_stdin_is_refused_by_policies_that_do_not_allow_it() -> None:
    from sentinel_worker.sandbox.policy import SandboxPolicy

    with pytest.raises(ValueError, match="stdin"):
        run_arguments(SandboxPolicy(), new_sandbox_name(), ["/bin/sh"], {}, 1, interactive=True)
    with pytest.raises(ValueError, match="stdin"):
        SandboxPolicy(max_stdin_bytes=65 * 1024 * 1024)


# --- The executor --------------------------------------------------------------------


class ScriptedSandbox:
    """Records the run and returns a prepared result; no container."""

    def __init__(self, result: SandboxRun) -> None:
        self.policy = ADAPTER.policy(timeout_seconds=60)
        self.result = result
        self.runs: list[dict[str, Any]] = []

    def run(
        self,
        argv: Sequence[str],
        stop: threading.Event,
        timeout_seconds: float | None = None,
        job_id: str | None = None,
        stdin: bytes | None = None,
    ) -> SandboxRun:
        self.runs.append({"argv": list(argv), "timeout": timeout_seconds, "stdin": stdin})
        return self.result

    def reap_expired(self) -> int:
        return 0


def executor(tmp_path: Path, result: SandboxRun) -> tuple[ScannerExecutor, ScriptedSandbox]:
    sandbox = ScriptedSandbox(result)
    return (
        ScannerExecutor(sandbox, ADAPTER, LocalFixtureRepositorySource(tmp_path)),  # type: ignore[arg-type]
        sandbox,
    )


def test_the_executor_scans_the_leased_repository_and_returns_evidence(tmp_path: Path) -> None:
    make_repository(tmp_path, "repo", {"app.py": "x"})
    run = exited(41, report(report_entry("app.py")))
    scanner, sandbox = executor(tmp_path, run)

    result = scanner.execute(lease("repo"), threading.Event())

    assert result.outcome is JobOutcome.COMPLETED
    assert [artifact.name for artifact in result.artifacts] == ["findings.json"]
    (recorded,) = sandbox.runs
    assert recorded["stdin"] is not None
    assert recorded["timeout"] <= 60


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (SandboxStatus.TIMED_OUT, FailureReason.EXECUTION_TIMEOUT),
        (SandboxStatus.OOM_KILLED, FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (SandboxStatus.OUTPUT_LIMIT, FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (SandboxStatus.PIDS_EXHAUSTED, FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (SandboxStatus.START_FAILED, FailureReason.SANDBOX_ERROR),
        (SandboxStatus.LOST, FailureReason.SANDBOX_ERROR),
        (SandboxStatus.CANCELLED, FailureReason.WORKER_SHUTDOWN),
    ],
)
def test_sandbox_outcomes_map_like_the_fixture(
    tmp_path: Path, status: SandboxStatus, reason: FailureReason
) -> None:
    make_repository(tmp_path, "repo", {"app.py": "x"})
    run = SandboxRun(status, 0, report(), "", 1.0, None, None, True)
    scanner, _ = executor(tmp_path, run)

    result = scanner.execute(lease("repo"), threading.Event())

    assert (result.outcome, result.failure_reason) == (JobOutcome.FAILED, reason)
    assert result.artifacts == ()


def test_input_problems_fail_without_starting_a_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    scanner, sandbox = executor(tmp_path, exited(0, report()))

    with caplog.at_level(logging.INFO):
        missing = scanner.execute(lease("missing"), threading.Event())
    assert missing.failure_reason is FailureReason.SCANNER_ERROR
    assert "REPOSITORY_NOT_FOUND" in caplog.text
    assert str(tmp_path) not in caplog.text

    make_repository(tmp_path, "big", {"a": "1"})

    def too_large(_: RepositorySnapshot) -> bytes:
        raise InputError(InputErrorCode.INPUT_TOO_LARGE)

    monkeypatch.setattr(ADAPTER, "stdin", too_large, raising=False)
    try:
        large = scanner.execute(lease("big"), threading.Event())
    finally:
        monkeypatch.undo()
    assert large.failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED
    assert sandbox.runs == []


def test_nothing_runs_for_other_scanners_stopped_jobs_or_passed_deadlines(
    tmp_path: Path,
) -> None:
    make_repository(tmp_path, "repo", {"app.py": "x"})
    scanner, sandbox = executor(tmp_path, exited(0, report()))
    expired = dataclasses.replace(
        lease("repo"), deadline_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    stopped = threading.Event()
    stopped.set()

    assert scanner.execute(lease("repo", "FIXTURE"), threading.Event()).failure_reason is (
        FailureReason.UNSUPPORTED_SCANNER
    )
    assert scanner.execute(expired, threading.Event()).failure_reason is (
        FailureReason.EXECUTION_TIMEOUT
    )
    assert scanner.execute(lease("repo"), stopped).failure_reason is FailureReason.WORKER_SHUTDOWN
    assert sandbox.runs == []


def test_the_executor_requires_the_adapters_image(tmp_path: Path) -> None:
    from sentinel_worker.sandbox.policy import SandboxPolicy

    sandbox = ScriptedSandbox(exited(0))
    sandbox.policy = SandboxPolicy()
    with pytest.raises(ValueError, match="image"):
        ScannerExecutor(sandbox, ADAPTER, LocalFixtureRepositorySource(tmp_path))  # type: ignore[arg-type]


def test_the_dispatcher_routes_by_scanner_type() -> None:
    class Fake:
        def __init__(self, scanner_type: str) -> None:
            self.scanner_types = frozenset({scanner_type})

        def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
            return ExecutionResult.completed()

    dispatcher = DispatchingExecutor([Fake("FIXTURE"), Fake("GITLEAKS")])

    assert dispatcher.scanner_types == {"FIXTURE", "GITLEAKS"}
    assert dispatcher.execute(lease(), threading.Event()).outcome is JobOutcome.COMPLETED
    assert (
        dispatcher.execute(lease(scanner_type="TRIVY"), threading.Event()).failure_reason
        is FailureReason.UNSUPPORTED_SCANNER
    )
    with pytest.raises(ValueError, match="two executors"):
        DispatchingExecutor([Fake("GITLEAKS"), Fake("GITLEAKS")])


# --- Settings ------------------------------------------------------------------------

DB_ENV = {"SENTINEL_WORKER_DB_USERNAME": "w", "SENTINEL_WORKER_DB_PASSWORD": "pw"}


def gitleaks_env(tmp_path: Path) -> dict[str, str]:
    import sys

    return DB_ENV | {
        "SENTINEL_WORKER_GITLEAKS_ENABLED": "true",
        "SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": str(tmp_path),
        "SENTINEL_WORKER_DOCKER_CLI": sys.executable,
    }


def test_gitleaks_can_be_the_only_enabled_scanner(tmp_path: Path) -> None:
    settings = ExecutionSettings.from_env(Environment.CI, gitleaks_env(tmp_path))

    assert settings.gitleaks_enabled
    assert not settings.fixture_enabled
    assert settings.repository_fixtures_dir == str(tmp_path)
    assert settings.gitleaks_policy == ADAPTER.policy()
    assert settings.sandbox_policy is None


def test_gitleaks_is_refused_in_production(tmp_path: Path) -> None:
    env = gitleaks_env(tmp_path) | {"SENTINEL_WORKER_DB_SSLMODE": "verify-full"}

    with pytest.raises(ConfigurationError, match="not permitted in production"):
        ExecutionSettings.from_env(Environment.PRODUCTION, env)


@pytest.mark.parametrize(
    "overrides",
    [
        {"SENTINEL_WORKER_GITLEAKS_ENABLED": "yes"},
        {"SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": ""},
        {"SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": "relative/dir"},
        {"SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": "/definitely/missing/dir"},
        {"SENTINEL_WORKER_DOCKER_CLI": "docker"},
        {"SENTINEL_WORKER_SANDBOX_RUNTIME": "runc"},
    ],
)
def test_unsafe_gitleaks_settings_are_refused(tmp_path: Path, overrides: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        ExecutionSettings.from_env(Environment.CI, gitleaks_env(tmp_path) | overrides)

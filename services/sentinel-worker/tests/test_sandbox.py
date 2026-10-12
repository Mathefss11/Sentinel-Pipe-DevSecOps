"""Unit tests of the sandbox policy, protocol, classification and executor (no Docker)."""

from __future__ import annotations

import base64
import json
import sys
import threading
import uuid
from datetime import timedelta
from typing import Any

import pytest

from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.execution.leases import FailureReason, JobOutcome
from sentinel_worker.execution.sandboxed import SandboxedFixtureExecutor, outcome_for
from sentinel_worker.execution.settings import ExecutionSettings
from sentinel_worker.sandbox import fixture
from sentinel_worker.sandbox.docker import (
    DockerCli,
    DockerSandbox,
    SandboxError,
    SandboxRun,
    SandboxStatus,
    cli_environment,
    sanitize,
)
from sentinel_worker.sandbox.policy import (
    FIXTURE_IMAGE,
    SandboxPolicy,
    new_sandbox_name,
    run_arguments,
)
from sentinel_worker.sandbox.protocol import InvalidOutputError, parse
from test_execution import T0, lease

ARGV = ["/bin/sh", "-c", "true"]


def arguments(**labels: str) -> list[str]:
    return run_arguments(SandboxPolicy(), new_sandbox_name(), ARGV, labels, 1_900_000_000)


def envelope(*artifacts: dict[str, Any], **overrides: Any) -> bytes:
    document: dict[str, Any] = {"schema_version": 1, "artifacts": list(artifacts)}
    document.update(overrides)
    return json.dumps(document).encode()


def artifact(
    name: str = "fixture-result.json", content: bytes = b"{}", **overrides: Any
) -> dict[str, Any]:
    entry = {
        "name": name,
        "media_type": "application/json",
        "content_base64": base64.b64encode(content).decode(),
    }
    entry.update(overrides)
    return entry


def run(status: SandboxStatus, exit_code: int | None = 0, stdout: bytes = b"") -> SandboxRun:
    return SandboxRun(status, exit_code, stdout, "", 1.0, 3, 1024, True)


# --- Policy and runtime arguments ----------------------------------------------------


def test_every_isolation_control_is_requested() -> None:
    args = arguments()
    joined = " ".join(args)

    for expected in [
        "--network none",
        "--ipc none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65534:65534",
        "--init",
        "--pull never",
        "--memory 268435456b",
        "--memory-swap 268435456b",
        "--cpus 1",
        "--pids-limit 64",
        "--ulimit nofile=256:256",
        "--ulimit core=0",
        "--log-driver none",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=33554432",
    ]:
        assert expected in joined, expected
    assert args[-len(ARGV) :] == [FIXTURE_IMAGE, *ARGV[1:]]
    assert args[args.index("--entrypoint") + 1] == "/bin/sh"


@pytest.mark.parametrize(
    "forbidden",
    [
        "-v",
        "--volume",
        "--mount",
        "--privileged",
        "docker.sock",
        "--cap-add",
        "--device",
        "-e",
        "--env",
        "--env-file",
        "--pid",
        "--userns",
        "host",
        "-p",
        "--publish",
        "--add-host",
        "--volumes-from",
    ],
)
def test_no_host_resource_is_ever_exposed(forbidden: str) -> None:
    assert forbidden not in arguments(**{"sentinelpipe.job": str(uuid.uuid4())})


def test_only_allowlisted_images_commands_and_runtimes_are_accepted() -> None:
    with pytest.raises(ValueError, match="image"):
        SandboxPolicy(image="alpine:latest")
    with pytest.raises(ValueError, match="image"):
        SandboxPolicy(image="evil.example/alpine@sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="runtime"):
        SandboxPolicy(runtime="privileged-runtime")
    assert "--runtime runsc" in " ".join(
        run_arguments(SandboxPolicy(runtime="runsc"), new_sandbox_name(), ARGV, {}, 1)
    )
    for argv in (["/usr/bin/python3", "-c", "x"], ["sh", "-c", "x"], [], ["/bin/sh", "a\x00b"]):
        with pytest.raises(ValueError, match=r"command|argument"):
            run_arguments(SandboxPolicy(), new_sandbox_name(), argv, {}, 1)


def test_names_and_labels_cannot_inject_options() -> None:
    with pytest.raises(ValueError, match="name"):
        run_arguments(SandboxPolicy(), "--privileged", ARGV, {}, 1)
    with pytest.raises(ValueError, match="label"):
        arguments(**{"sentinelpipe.job": "x --privileged"})
    with pytest.raises(ValueError, match="label"):
        arguments(**{"com.docker.custom": "1"})


@pytest.mark.parametrize(
    "overrides",
    [
        {"memory_bytes": 1024},
        {"cpus": 64},
        {"pids": 1},
        {"tmpfs_bytes": 1},
        {"timeout_seconds": 0},
        {"max_stdout_bytes": 10**9},
        {"open_files": 1},
    ],
)
def test_unsafe_limits_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="between"):
        SandboxPolicy(**overrides)


def test_the_runtime_cli_never_receives_sentinel_credentials() -> None:
    environment = cli_environment(
        {
            "PATH": "/bin",
            "SENTINEL_WORKER_DB_PASSWORD": "secret",
            "sentinel_x": "y",
            "DOCKER_HOST": "unix://",
        }
    )

    assert environment == {"PATH": "/bin", "DOCKER_HOST": "unix://"}


def test_the_runtime_cli_must_be_an_absolute_existing_path() -> None:
    with pytest.raises(SandboxError):
        DockerCli("docker")
    with pytest.raises(SandboxError):
        DockerCli("/definitely/not/docker")


def test_log_excerpts_are_bounded_and_sanitized() -> None:
    excerpt = sanitize(
        b"error\x1b[31m AKIAFAKEFAKEFAKE0000XYZ token=" + b"x" * 40 + b"\n" * 3 + b"y" * 1000
    )

    assert "AKIA" not in excerpt
    assert "\x1b" not in excerpt
    assert "[redacted]" in excerpt
    assert len(excerpt) <= 256


# --- Output protocol -----------------------------------------------------------------


def test_valid_output_yields_artifacts() -> None:
    (parsed,) = parse(envelope(artifact(content=b'{"ok":true}')))

    assert parsed.name == "fixture-result.json"
    assert parsed.content == b'{"ok":true}'


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "..",
        "a/../b",
        "a\\b",
        "C:\\x",
        "x/y",
        "UPPER",
        ".env",
        "a..b",
        "file:///etc/passwd",
        "x" * 65,
        "evil\n.json",
        "",
    ],
)
def test_artifact_names_are_never_paths(name: str) -> None:
    with pytest.raises(InvalidOutputError):
        parse(envelope(artifact(name=name)))


@pytest.mark.parametrize(
    ("stdout", "code"),
    [
        (b"not json", "INVALID_JSON"),
        (b"\xff\xfe", "INVALID_JSON"),
        (b'{"schema_version":1,"schema_version":1,"artifacts":[]}', "DUPLICATE_KEYS"),
        (b'{"schema_version":1,"artifacts":[],"x":NaN}', "INVALID_JSON"),
        (b"[]", "INVALID_JSON"),
        (b'{"schema_version":2,"artifacts":[]}', "UNSUPPORTED_SCHEMA_VERSION"),
        (b'{"schema_version":1,"artifacts":[],"path":"/etc"}', "SCHEMA_VIOLATION"),
        (b"[" * 100000 + b"]" * 100000, "INVALID_JSON"),
    ],
    ids=[
        "text",
        "encoding",
        "duplicate-keys",
        "nan",
        "array",
        "version",
        "unknown-key",
        "deep-nesting",
    ],
)
def test_malformed_output_is_rejected_with_a_code(stdout: bytes, code: str) -> None:
    with pytest.raises(InvalidOutputError) as raised:
        parse(stdout)

    assert raised.value.code == code


def test_artifact_content_and_counts_are_bounded() -> None:
    with pytest.raises(InvalidOutputError):
        parse(envelope(artifact(content_base64="not base64!")))
    with pytest.raises(InvalidOutputError):
        parse(envelope(artifact(content=b"x" * (1024 * 1024 + 1))))
    with pytest.raises(InvalidOutputError):
        parse(envelope(artifact(), artifact()))
    with pytest.raises(InvalidOutputError):
        parse(envelope(*[artifact(name=f"a{i}.json") for i in range(17)]))
    with pytest.raises(InvalidOutputError):
        parse(envelope(artifact(media_type="text/html")))
    with pytest.raises(InvalidOutputError):
        parse(envelope(artifact(extra="x")))


# --- Classification ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sandbox", "expected"),
    [
        (run(SandboxStatus.EXITED, 3), FailureReason.SCANNER_ERROR),
        (run(SandboxStatus.EXITED, 137), FailureReason.SANDBOX_ERROR),
        (run(SandboxStatus.EXITED, None), FailureReason.SANDBOX_ERROR),
        (run(SandboxStatus.EXITED, 0, b"garbage"), FailureReason.SCANNER_ERROR),
        (run(SandboxStatus.TIMED_OUT, 137), FailureReason.EXECUTION_TIMEOUT),
        (run(SandboxStatus.OOM_KILLED, 137), FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (run(SandboxStatus.PIDS_EXHAUSTED, 2), FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (run(SandboxStatus.OUTPUT_LIMIT, 137), FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (run(SandboxStatus.START_FAILED, 125), FailureReason.SANDBOX_ERROR),
        (run(SandboxStatus.CANCELLED, 137), FailureReason.WORKER_SHUTDOWN),
    ],
)
def test_sandbox_outcomes_map_to_existing_failure_reasons(
    sandbox: SandboxRun, expected: FailureReason
) -> None:
    result = outcome_for(sandbox)

    assert result.outcome is JobOutcome.FAILED
    assert result.failure_reason is expected
    assert result.artifacts == ()


def test_a_successful_run_completes_with_its_artifacts() -> None:
    result = outcome_for(run(SandboxStatus.EXITED, 0, envelope(artifact())))

    assert result.outcome is JobOutcome.COMPLETED
    assert [a.name for a in result.artifacts] == ["fixture-result.json"]


def classifier(pids: int = 32) -> DockerSandbox:
    return DockerSandbox(DockerCli(sys.executable), SandboxPolicy(pids=pids))


STARTED = {"StartedAt": "2026-10-10T12:00:00Z", "ExitCode": 0, "OOMKilled": False}


@pytest.mark.parametrize(
    ("reason", "state", "overflowed", "peak", "expected"),
    [
        (None, STARTED, False, 3, SandboxStatus.EXITED),
        (SandboxStatus.CANCELLED, STARTED | {"OOMKilled": True}, True, 32, SandboxStatus.CANCELLED),
        (None, None, False, None, SandboxStatus.START_FAILED),
        (
            None,
            STARTED | {"StartedAt": "0001-01-01T00:00:00Z"},
            False,
            None,
            SandboxStatus.START_FAILED,
        ),
        (
            SandboxStatus.TIMED_OUT,
            STARTED | {"OOMKilled": True},
            False,
            3,
            SandboxStatus.OOM_KILLED,
        ),
        (SandboxStatus.TIMED_OUT, STARTED, True, 3, SandboxStatus.OUTPUT_LIMIT),
        (SandboxStatus.TIMED_OUT, STARTED, False, 32, SandboxStatus.PIDS_EXHAUSTED),
        (SandboxStatus.TIMED_OUT, STARTED, False, 31, SandboxStatus.TIMED_OUT),
    ],
)
def test_classification_prefers_the_most_specific_cause(
    reason: SandboxStatus | None,
    state: dict[str, Any] | None,
    overflowed: bool,
    peak: int | None,
    expected: SandboxStatus,
) -> None:
    status, _ = classifier()._classify(reason, state, overflowed, peak)

    assert status is expected


# --- Executor ------------------------------------------------------------------------


class FakeSandbox:
    def __init__(self, result: SandboxRun | Exception) -> None:
        self.policy = SandboxPolicy(timeout_seconds=300)
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def run(
        self, argv: list[str], stop: threading.Event, timeout_seconds: float, job_id: str
    ) -> SandboxRun:
        self.calls.append({"argv": argv, "timeout": timeout_seconds, "job_id": job_id})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def reap_expired(self) -> int:
        return 0


def executor(
    result: SandboxRun | Exception, now_offset: timedelta = timedelta(0)
) -> tuple[Any, FakeSandbox]:
    sandbox = FakeSandbox(result)
    executor = SandboxedFixtureExecutor(sandbox, clock=lambda: T0 + now_offset)  # type: ignore[arg-type]
    return executor, sandbox


def test_the_attempt_timeout_never_exceeds_the_scans_deadline() -> None:
    run_executor, sandbox = executor(
        run(SandboxStatus.EXITED, 0, envelope(artifact())), timedelta(minutes=14)
    )

    run_executor.execute(lease(), threading.Event())

    # The deadline is 15 minutes after T0; 60 s remain, minus a 5 s reporting margin.
    assert sandbox.calls[0]["timeout"] == pytest.approx(55)


def test_nothing_runs_once_the_deadline_has_passed() -> None:
    run_executor, sandbox = executor(run(SandboxStatus.EXITED), timedelta(minutes=16))

    result = run_executor.execute(lease(), threading.Event())

    assert result.failure_reason is FailureReason.EXECUTION_TIMEOUT
    assert sandbox.calls == []


def test_an_unavailable_runtime_is_a_retryable_sandbox_error() -> None:
    run_executor, _ = executor(SandboxError("down"))

    assert (
        run_executor.execute(lease(), threading.Event()).failure_reason
        is FailureReason.SANDBOX_ERROR
    )


def test_other_scanners_are_never_started() -> None:
    run_executor, sandbox = executor(run(SandboxStatus.EXITED))

    result = run_executor.execute(lease(scanner_type="SEMGREP"), threading.Event())

    assert result.failure_reason is FailureReason.UNSUPPORTED_SCANNER
    assert sandbox.calls == []


def test_fixture_arguments_are_validated_and_never_interpolated() -> None:
    claimed = lease()
    argv = fixture.command(fixture.FixtureMode.SUCCESS, claimed, 1)

    assert argv[:2] == ["/bin/sh", "-c"]
    assert str(claimed.job_id) not in argv[2]
    assert argv[4:] == [str(claimed.job_id), str(claimed.scan_id), "1", "1", "1"]
    with pytest.raises(ValueError, match="identifiers"):
        fixture.script_command(
            fixture.FixtureMode.SUCCESS, "x; rm -rf /", str(uuid.uuid4()), 1, 1, 1
        )
    with pytest.raises(ValueError, match="duration"):
        fixture.command(fixture.FixtureMode.SUCCESS, claimed, 10_000)


# --- Settings ------------------------------------------------------------------------

BASE = {
    "SENTINEL_WORKER_DB_USERNAME": "w",
    "SENTINEL_WORKER_DB_PASSWORD": "pw",
    "SENTINEL_WORKER_FIXTURE_ENABLED": "true",
    "SENTINEL_WORKER_DOCKER_CLI": sys.executable,
}


def test_the_sandbox_is_the_default_executor_with_bounded_limits() -> None:
    settings = ExecutionSettings.from_env(Environment.CI, BASE)

    assert settings.fixture_executor == "sandbox"
    assert settings.sandbox_policy == SandboxPolicy()
    custom = ExecutionSettings.from_env(
        Environment.CI,
        BASE
        | {
            "SENTINEL_WORKER_SANDBOX_MEMORY_MB": "64",
            "SENTINEL_WORKER_SANDBOX_PIDS": "32",
            "SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS": "30",
            "SENTINEL_WORKER_FIXTURE_MODE": "timeout",
        },
    )
    assert custom.sandbox_policy is not None
    assert custom.sandbox_policy.memory_bytes == 64 * 1024 * 1024
    assert custom.fixture_mode is fixture.FixtureMode.TIMEOUT


@pytest.mark.parametrize(
    "overrides",
    [
        {"SENTINEL_WORKER_FIXTURE_EXECUTOR": "subprocess"},
        {"SENTINEL_WORKER_FIXTURE_MODE": "rm -rf /"},
        {"SENTINEL_WORKER_FIXTURE_EXECUTOR": "inline", "SENTINEL_WORKER_FIXTURE_MODE": "memory"},
        {"SENTINEL_WORKER_SANDBOX_RUNTIME": "runc --privileged"},
        {"SENTINEL_WORKER_DOCKER_CLI": "docker"},
        {"SENTINEL_WORKER_SANDBOX_MEMORY_MB": "8"},
        {"SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS": "3600"},
    ],
)
def test_unsafe_execution_settings_are_refused(overrides: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        ExecutionSettings.from_env(Environment.CI, BASE | overrides)


def test_the_fixture_and_its_sandbox_modes_are_refused_in_production() -> None:
    with pytest.raises(ConfigurationError, match="production"):
        ExecutionSettings.from_env(
            Environment.PRODUCTION, BASE | {"SENTINEL_WORKER_DB_SSLMODE": "verify-full"}
        )


# --- Review fixes: trust policy, ownership, lost runtime, cancellation before start ----


def test_untrusted_code_never_runs_under_the_default_runc_boundary() -> None:
    from sentinel_worker.sandbox.policy import Workload

    assert SandboxPolicy().workload is Workload.TRUSTED_TOOL
    with pytest.raises(ValueError, match="untrusted code"):
        SandboxPolicy(workload=Workload.UNTRUSTED_CODE)
    for runtime in ("runsc", "kata-runtime", "kata"):
        assert SandboxPolicy(workload=Workload.UNTRUSTED_CODE, runtime=runtime).runtime == runtime


def test_a_lost_runtime_with_a_running_container_fails_closed() -> None:
    status, exit_code = classifier()._classify(None, STARTED | {"Running": True}, False, 3)

    assert status is SandboxStatus.LOST
    assert exit_code is None
    assert outcome_for(run(SandboxStatus.LOST, None, envelope(artifact()))).failure_reason is (
        FailureReason.SANDBOX_ERROR
    )


def test_nothing_starts_when_the_job_was_already_stopped() -> None:
    stop = threading.Event()
    stop.set()

    result = classifier().run(ARGV, stop)

    assert result.status is SandboxStatus.CANCELLED
    with pytest.raises(ValueError, match="positive"):
        classifier().run(ARGV, threading.Event(), timeout_seconds=0)


class ScriptedCli(DockerCli):
    """Answers ``docker ps`` with a fixed listing and records removals."""

    def __init__(self, listing: str) -> None:
        self.listing = listing
        self.removed: list[str] = []

    def call(self, arguments: Any, timeout: float = 30) -> Any:
        import subprocess

        if arguments[0] == "rm":
            self.removed.append(arguments[-1])
        stdout = self.listing.encode() if arguments[0] == "ps" else b""
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")


def test_the_reaper_never_removes_a_live_sandbox_or_foreign_containers() -> None:
    now = 1_900_000_000
    live, expired, unlabelled_live, unlabelled_done = (new_sandbox_name() for _ in range(4))
    cli = ScriptedCli(
        "\n".join(
            [
                f"{live}\trunning\t{now + 100}",
                f"{expired}\trunning\t{now - 1}",
                f"{unlabelled_live}\trunning\t",
                f"{unlabelled_done}\texited\tnot-a-number",
                f"postgres\texited\t{now - 1}",
                f"sentinel-sandbox-evil\texited\t{now - 1}",
            ]
        )
    )
    sandbox = DockerSandbox(cli, SandboxPolicy(), wall_clock=lambda: now)

    assert sandbox.reap_expired() == 2

    assert cli.removed == [expired, unlabelled_done]


# --- Security review (Slice 5): mounts and runtime CLI failures ----------------------


def test_only_runtime_created_mounts_are_accepted() -> None:
    from sentinel_worker.sandbox.isolation import unexpected_mounts

    # Mount targets inside the container (not host temporary files).
    runtime = ["/", "/proc", "/dev", "/dev/pts", "/sys", "/sys/fs/cgroup", "/dev/mqueue",
               "/sbin/docker-init", "/tmp", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts",  # noqa: S108
               "/proc/kcore", "/sys/firmware"]  # fmt: skip
    assert unexpected_mounts(runtime) == []
    hostile = [
        "/var/run/docker.sock",
        "/host",
        "/home/runner/work",
        "/procfs",
        "/devices",
        "/etc/passwd",
    ]
    assert unexpected_mounts(runtime + hostile) == hostile


class LyingCli(DockerCli):
    """A runtime CLI that exits 0 and prints a perfect envelope, but no container exists."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def start(self, arguments: Any) -> Any:
        import subprocess

        envelope_text = envelope(artifact()).decode()
        return subprocess.Popen(  # noqa: S603 - test double
            [sys.executable, "-c", f"import sys; sys.stdout.write({envelope_text!r})"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def call(self, arguments: Any, timeout: float = 30) -> Any:
        import subprocess

        self.calls.append(list(arguments))
        return subprocess.CompletedProcess(arguments, 1, b"", b"Error: No such object")


def test_runtime_cli_output_without_a_real_container_is_never_success() -> None:
    sandbox = DockerSandbox(LyingCli(), SandboxPolicy(), monitor_interval=60)

    run_result = sandbox.run(ARGV, threading.Event())

    assert run_result.status is SandboxStatus.START_FAILED
    assert outcome_for(run_result).failure_reason is FailureReason.SANDBOX_ERROR


class LateOomCli(DockerCli):
    """A runtime CLI whose container exits with ``exit_code``; ``inspect`` returns the
    scripted states in order (the last one repeats), like a daemon that records the OOM
    kill only after it has handled the exit."""

    def __init__(self, exit_code: int, oom_flags: list[bool]) -> None:
        self.exit_code = exit_code
        self.oom_flags = oom_flags
        self.calls: list[str] = []

    def start(self, arguments: Any, stdin: bool = False) -> Any:
        import subprocess

        return subprocess.Popen(  # noqa: S603 - test double
            [sys.executable, "-c", f"raise SystemExit({self.exit_code})"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def call(self, arguments: Any, timeout: float = 30) -> Any:
        import subprocess

        self.calls.append(arguments[0])
        if arguments[0] == "inspect":
            oom = self.oom_flags[min(self.calls.count("inspect"), len(self.oom_flags)) - 1]
            state = STARTED | {"Running": False, "ExitCode": self.exit_code, "OOMKilled": oom}
            return subprocess.CompletedProcess(arguments, 0, json.dumps(state).encode(), b"")
        if arguments[0] == "rm":
            return subprocess.CompletedProcess(arguments, 0, b"", b"")
        return subprocess.CompletedProcess(arguments, 1, b"", b"")


def late_oom_sandbox(cli: LateOomCli, sleeps: list[float]) -> DockerSandbox:
    return DockerSandbox(cli, SandboxPolicy(), monitor_interval=60, sleep=sleeps.append)


def test_an_oom_kill_recorded_after_the_exit_is_still_a_resource_limit() -> None:
    # CI #17: the fixture's process was OOM-killed and its shell then exited 1, but the
    # first inspect did not show OOMKilled yet, so the run was retried as SCANNER_ERROR.
    cli = LateOomCli(1, [False, False, True])
    sleeps: list[float] = []

    run_result = late_oom_sandbox(cli, sleeps).run(ARGV, threading.Event())

    assert run_result.status is SandboxStatus.OOM_KILLED
    assert run_result.exit_code == 1
    assert outcome_for(run_result).failure_reason is FailureReason.RESOURCE_LIMIT_EXCEEDED
    assert cli.calls.count("inspect") == 3
    # The container is inspected before it is removed, and still removed.
    assert cli.calls[-1] == "rm"
    assert run_result.removed


def test_a_scanner_error_without_an_oom_kill_waits_a_bounded_time() -> None:
    cli = LateOomCli(1, [False])
    sleeps: list[float] = []

    run_result = late_oom_sandbox(cli, sleeps).run(ARGV, threading.Event())

    assert run_result.status is SandboxStatus.EXITED
    assert outcome_for(run_result).failure_reason is FailureReason.SCANNER_ERROR
    assert cli.calls.count("inspect") == 21
    assert sum(sleeps) == pytest.approx(2.0)
    assert cli.calls[-1] == "rm"


def test_a_successful_exit_is_not_re_inspected() -> None:
    cli = LateOomCli(0, [False, True])
    sleeps: list[float] = []

    run_result = late_oom_sandbox(cli, sleeps).run(ARGV, threading.Event())

    assert run_result.status is SandboxStatus.EXITED
    assert run_result.exit_code == 0
    assert cli.calls.count("inspect") == 1
    assert sleeps == []

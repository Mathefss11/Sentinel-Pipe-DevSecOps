"""Adversarial tests of the sandbox against the real container runtime (ADR-0009).

Every isolation property is checked from inside a running sandbox, and every lifecycle
path (success, failure, limits, timeout, cancellation, crash) is checked to end with the
container removed. Requires Docker and the pinned fixture image (CI's sandbox job).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from sentinel_worker.execution.leases import FailureReason, JobLease, JobOutcome, Repository
from sentinel_worker.execution.sandboxed import SandboxedFixtureExecutor
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxStatus
from sentinel_worker.sandbox.fixture import FixtureMode, command
from sentinel_worker.sandbox.isolation import probe_command, verify
from sentinel_worker.sandbox.policy import JOB_LABEL, SANDBOX_LABEL

pytestmark = pytest.mark.sandbox

MakeSandbox = Callable[..., DockerSandbox]


def lease() -> JobLease:
    now = datetime.now(UTC)
    return JobLease(
        job_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        commit_sha="a" * 40,
        branch="main",
        repository=Repository("GITHUB", "acme", "repo"),
        scanner_type="FIXTURE",
        attempt=1,
        max_attempts=3,
        epoch=1,
        token="ab" * 32,
        expires_at=now + timedelta(seconds=60),
        lease_duration_seconds=60,
        deadline_at=now + timedelta(minutes=15),
    )


def containers(docker: DockerCli, label: str) -> list[str]:
    result = docker.call(["ps", "--all", "--filter", f"label={label}", "--format", "{{.Names}}"])
    return result.stdout.decode().split()


def evidence(sandbox: DockerSandbox, mode: FixtureMode, claimed: JobLease) -> dict[str, object]:
    result = SandboxedFixtureExecutor(sandbox, mode, 0.2).execute(claimed, threading.Event())
    assert result.outcome is JobOutcome.COMPLETED, result
    (artifact,) = result.artifacts
    document: dict[str, object] = json.loads(artifact.content)
    return document


# --- Isolation boundaries ------------------------------------------------------------


def test_every_isolation_control_is_effective_inside_the_sandbox(
    docker_cli: DockerCli, make_sandbox: MakeSandbox
) -> None:
    # The worker's own credentials are present in its environment...
    secret_cli = DockerCli(
        docker_cli.executable, os.environ | {"SENTINEL_WORKER_DB_PASSWORD": "must-not-leak"}
    )
    sandbox = DockerSandbox(secret_cli, make_sandbox().policy, monitor_interval=0.5)

    run = sandbox.run(probe_command(), threading.Event())

    # ... and none of them, nor any other host variable, reaches the sandbox.
    report = verify(run, sandbox.policy)
    assert report["healthy"], report
    assert all(report["controls"].values())
    assert b"must-not-leak" not in run.stdout


def test_network_access_is_denied(make_sandbox: MakeSandbox) -> None:
    claimed = lease()

    observed = evidence(make_sandbox(), FixtureMode.NETWORK, claimed)

    assert observed == {
        "database_reachable": False,
        "dns_resolved": False,
        "fixture": "harmless",
        "internet_reachable": False,
        "job_id": str(claimed.job_id),
    }


def test_successful_evidence_describes_only_this_job(make_sandbox: MakeSandbox) -> None:
    claimed = lease()

    observed = evidence(make_sandbox(), FixtureMode.SUCCESS, claimed)

    assert observed["job_id"] == str(claimed.job_id)
    assert observed["sandboxed"] is True
    assert observed["repository_content_read"] is False


# --- Failure modes, limits and their mapping -----------------------------------------


@pytest.mark.parametrize(
    ("mode", "timeout", "expected"),
    [
        (FixtureMode.NONZERO_EXIT, 20, FailureReason.SCANNER_ERROR),
        (FixtureMode.TIMEOUT, 3, FailureReason.EXECUTION_TIMEOUT),
        (FixtureMode.MEMORY, 20, FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (FixtureMode.CPU, 3, FailureReason.EXECUTION_TIMEOUT),
        (FixtureMode.PIDS, 6, FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (FixtureMode.CRASH, 20, FailureReason.SANDBOX_ERROR),
        (FixtureMode.OVERSIZED_OUTPUT, 20, FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (FixtureMode.MALICIOUS_OUTPUT, 20, FailureReason.SCANNER_ERROR),
    ],
    ids=lambda value: getattr(value, "value", str(value)),
)
def test_failure_modes_map_to_existing_reasons_and_leave_nothing_behind(
    docker_cli: DockerCli,
    make_sandbox: MakeSandbox,
    mode: FixtureMode,
    timeout: int,
    expected: FailureReason,
) -> None:
    claimed = lease()
    started = time.monotonic()

    result = SandboxedFixtureExecutor(make_sandbox(timeout_seconds=timeout), mode, 0).execute(
        claimed, threading.Event()
    )

    assert result.outcome is JobOutcome.FAILED
    assert result.failure_reason is expected
    assert result.artifacts == ()
    assert time.monotonic() - started < timeout + 15
    assert containers(docker_cli, f"{JOB_LABEL}={claimed.job_id}") == []


def test_resource_exhaustion_is_contained_by_the_limits(make_sandbox: MakeSandbox) -> None:
    sandbox = make_sandbox(timeout_seconds=6)

    pids = sandbox.run(command(FixtureMode.PIDS, lease(), 0), threading.Event())
    memory = sandbox.run(command(FixtureMode.MEMORY, lease(), 0), threading.Event())

    assert pids.status is SandboxStatus.PIDS_EXHAUSTED
    assert pids.peak_pids is not None
    assert pids.peak_pids <= sandbox.policy.pids
    assert memory.status is SandboxStatus.OOM_KILLED
    if memory.peak_memory_bytes is not None:
        assert memory.peak_memory_bytes <= sandbox.policy.memory_bytes * 1.05


def test_the_worker_stays_responsive_while_a_sandbox_burns_cpu(make_sandbox: MakeSandbox) -> None:
    gaps: list[float] = []
    finished = threading.Event()

    def tick() -> None:
        last = time.monotonic()
        while not finished.wait(0.1):
            now = time.monotonic()
            gaps.append(now - last)
            last = now

    ticker = threading.Thread(target=tick)
    ticker.start()
    try:
        run = make_sandbox(timeout_seconds=4).run(
            command(FixtureMode.CPU, lease(), 0), threading.Event()
        )
    finally:
        finished.set()
        ticker.join()

    assert run.status is SandboxStatus.TIMED_OUT
    assert max(gaps) < 1.0


def test_output_is_bounded_and_overflow_stops_the_sandbox(make_sandbox: MakeSandbox) -> None:
    sandbox = make_sandbox(max_stdout_bytes=64 * 1024)

    run = sandbox.run(command(FixtureMode.OVERSIZED_OUTPUT, lease(), 0), threading.Event())

    assert run.status is SandboxStatus.OUTPUT_LIMIT
    assert len(run.stdout) <= 64 * 1024
    assert run.removed


def test_the_next_job_runs_normally_after_exhaustion(make_sandbox: MakeSandbox) -> None:
    sandbox = make_sandbox()
    sandbox.run(command(FixtureMode.MEMORY, lease(), 0), threading.Event())

    assert evidence(sandbox, FixtureMode.SUCCESS, lease())["fixture"] == "harmless"


# --- Cancellation, cleanup and crashes -----------------------------------------------


def test_cancellation_kills_the_sandbox_promptly(
    docker_cli: DockerCli, make_sandbox: MakeSandbox
) -> None:
    claimed = lease()
    stop = threading.Event()
    threading.Timer(1.5, stop.set).start()
    started = time.monotonic()

    run = make_sandbox(timeout_seconds=60).run(
        command(FixtureMode.TIMEOUT, claimed, 0), stop, job_id=str(claimed.job_id)
    )

    assert run.status is SandboxStatus.CANCELLED
    assert time.monotonic() - started < 15
    assert run.removed
    assert containers(docker_cli, f"{JOB_LABEL}={claimed.job_id}") == []


def test_an_unusable_runtime_fails_closed(docker_cli: DockerCli, make_sandbox: MakeSandbox) -> None:
    # gVisor is allowlisted but not installed here: the runtime refuses to start the sandbox.
    available = docker_cli.call(["info", "--format", "{{json .Runtimes}}"]).stdout.decode()
    if "runsc" in available:
        pytest.skip("runsc is installed on this host")
    claimed = lease()

    result = SandboxedFixtureExecutor(
        make_sandbox(runtime="runsc"), FixtureMode.SUCCESS, 0
    ).execute(claimed, threading.Event())

    assert result.failure_reason is FailureReason.SANDBOX_ERROR
    assert containers(docker_cli, f"{JOB_LABEL}={claimed.job_id}") == []


_CRASHING_WORKER = textwrap.dedent(
    """
    import shutil, sys, threading
    from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
    from sentinel_worker.sandbox.fixture import FixtureMode, script_command
    from sentinel_worker.sandbox.policy import SandboxPolicy
    sandbox = DockerSandbox(DockerCli(shutil.which("docker")),
                            SandboxPolicy(timeout_seconds=30, expiry_grace_seconds=1))
    argv = script_command(FixtureMode.TIMEOUT, sys.argv[1], sys.argv[1], 1, 1, 0)
    sandbox.run(argv, threading.Event(), job_id=sys.argv[1])
    """
)


def test_sandboxes_of_a_crashed_worker_are_reaped_after_they_expire(
    docker_cli: DockerCli, make_sandbox: MakeSandbox
) -> None:
    job = str(uuid.uuid4())
    worker = subprocess.Popen([sys.executable, "-c", _CRASHING_WORKER, job])  # noqa: S603
    try:
        deadline = time.monotonic() + 30
        while not containers(docker_cli, f"{JOB_LABEL}={job}"):
            assert time.monotonic() < deadline, "the sandbox never started"
            time.sleep(0.2)
    finally:
        worker.kill()  # hard crash: no cleanup code runs
        worker.wait()
    orphan = containers(docker_cli, f"{JOB_LABEL}={job}")
    assert orphan, "the orphaned sandbox should outlive the crashed worker"

    # A live (unexpired) sandbox is never reaped...
    make_sandbox().reap_expired()
    assert containers(docker_cli, f"{JOB_LABEL}={job}") == orphan
    # ... an expired one is removed by the next worker.
    later = DockerSandbox(docker_cli, make_sandbox().policy, wall_clock=lambda: time.time() + 3600)
    assert later.reap_expired() >= 1
    assert containers(docker_cli, f"{JOB_LABEL}={job}") == []


def test_no_sandbox_is_left_running_by_this_suite(docker_cli: DockerCli) -> None:
    assert [
        name
        for name in containers(docker_cli, f"{SANDBOX_LABEL}=1")
        if name.startswith("sentinel-sandbox-")
    ] == []


def test_one_worker_never_reaps_another_workers_live_sandbox(
    docker_cli: DockerCli, make_sandbox: MakeSandbox
) -> None:
    owner = make_sandbox(timeout_seconds=60)
    claimed = lease()
    stop = threading.Event()
    running = threading.Thread(
        target=owner.run,
        args=(command(FixtureMode.TIMEOUT, claimed, 0), stop),
        kwargs={"job_id": str(claimed.job_id)},
    )
    running.start()
    try:
        deadline = time.monotonic() + 30
        while not containers(docker_cli, f"{JOB_LABEL}={claimed.job_id}"):
            assert time.monotonic() < deadline
            time.sleep(0.2)

        # Another worker on the same host reaps: the live, unexpired sandbox stays.
        make_sandbox().reap_expired()

        assert containers(docker_cli, f"{JOB_LABEL}={claimed.job_id}")
    finally:
        stop.set()
        running.join(timeout=30)
    assert containers(docker_cli, f"{JOB_LABEL}={claimed.job_id}") == []


def test_the_mount_check_detects_a_real_host_mount(docker_cli: DockerCli, tmp_path: object) -> None:
    """Negative control: a container started outside the policy, with a bind mount, must
    fail the no_host_mounts control (proves the check observes real mounts)."""
    from sentinel_worker.sandbox.isolation import observations, unexpected_mounts
    from sentinel_worker.sandbox.policy import FIXTURE_IMAGE

    argv = probe_command()
    result = docker_cli.call(
        ["run", "--rm", "--network", "none", "--pull", "never", "-v", f"{tmp_path}:/hostdir:ro",
         "--entrypoint", argv[0], FIXTURE_IMAGE, *argv[1:]],
        timeout=60,
    )  # fmt: skip
    assert result.returncode == 0
    from sentinel_worker.sandbox.docker import SandboxRun

    seen = observations(SandboxRun(SandboxStatus.EXITED, 0, result.stdout, "", 0, None, None, True))
    assert unexpected_mounts(str(seen["mounts"]).split()) == ["/hostdir"]

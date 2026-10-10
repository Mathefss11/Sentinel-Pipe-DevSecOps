"""The sandboxed FIXTURE through the whole execution protocol: real PostgreSQL, the
worker's least-privileged login and real sandbox containers. Cancellation and lease loss
stop the sandbox; stale workers never get a result accepted; evidence flows through
the verified pipeline (ADR-0008, ADR-0009)."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from infrastructure import ControlPlane, SeededJob

from sentinel_worker.execution.leases import JobLease, JobLeaseClient
from sentinel_worker.execution.runner import ExecutionLoop, RunOutcome
from sentinel_worker.execution.sandboxed import SandboxedFixtureExecutor
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
from sentinel_worker.sandbox.fixture import FixtureMode
from sentinel_worker.sandbox.policy import JOB_LABEL

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]


def client(control_plane: ControlPlane, name: str) -> JobLeaseClient:
    return JobLeaseClient(control_plane.worker_settings(), f"sentinel-tests-{name}")


def containers(docker: DockerCli, job: SeededJob) -> list[str]:
    result = docker.call(
        ["ps", "--all", "--filter", f"label={JOB_LABEL}={job.job_id}", "--format", "{{.Names}}"]
    )
    return result.stdout.decode().split()


def run_in_background(
    control_plane: ControlPlane, executor: SandboxedFixtureExecutor, job: SeededJob
) -> tuple[threading.Thread, list[RunOutcome], JobLease]:
    worker = client(control_plane, "sandboxed")
    heartbeats = client(control_plane, "sandboxed-hb")
    lease = worker.claim(["FIXTURE"], job.scan_id)
    assert lease is not None
    outcomes: list[RunOutcome] = []

    def execute() -> None:
        try:
            outcomes.append(ExecutionLoop(worker, heartbeats, executor).run_one(lease))
        finally:
            worker.close()
            heartbeats.close()

    thread = threading.Thread(target=execute)
    thread.start()
    return thread, outcomes, lease


def wait_for(condition: Callable[[], Any], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        time.sleep(0.2)


def test_sandboxed_evidence_is_verified_and_stored(
    control_plane: ControlPlane, make_sandbox: Callable[..., DockerSandbox], docker_cli: DockerCli
) -> None:
    job = control_plane.seed_fixture_job()
    thread, outcomes, _ = run_in_background(
        control_plane, SandboxedFixtureExecutor(make_sandbox(), FixtureMode.SUCCESS, 0.2), job
    )
    thread.join(timeout=60)

    assert outcomes == [RunOutcome.REPORTED]
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"
    with control_plane.admin() as connection:
        (content,) = connection.execute(
            "SELECT o.content FROM evidence.result_artifacts r"
            " JOIN evidence.job_artifacts u USING (job_id, lease_epoch, name)"
            " JOIN evidence.objects o"
            " ON o.organization_id = u.organization_id AND o.sha256 = u.sha256"
            " WHERE r.job_id = %s",
            (job.job_id,),
        ).fetchone()
    observed = json.loads(bytes(content))
    assert observed["sandboxed"] is True
    assert observed["job_id"] == str(job.job_id)
    assert containers(docker_cli, job) == []


@pytest.mark.parametrize(
    ("mode", "status", "reason"),
    [
        (FixtureMode.NONZERO_EXIT, "QUEUED", "SCANNER_ERROR"),
        (FixtureMode.CRASH, "QUEUED", "SANDBOX_ERROR"),
        (FixtureMode.MEMORY, "FAILED", "RESOURCE_LIMIT_EXCEEDED"),
        (FixtureMode.MALICIOUS_OUTPUT, "QUEUED", "SCANNER_ERROR"),
    ],
    ids=lambda value: getattr(value, "value", str(value)),
)
def test_sandbox_failures_are_reported_with_existing_reasons(
    control_plane: ControlPlane,
    make_sandbox: Callable[..., DockerSandbox],
    mode: FixtureMode,
    status: str,
    reason: str,
) -> None:
    job = control_plane.seed_fixture_job()
    thread, outcomes, _ = run_in_background(
        control_plane, SandboxedFixtureExecutor(make_sandbox(), mode, 0), job
    )
    thread.join(timeout=60)

    assert outcomes == [RunOutcome.REPORTED]
    state = control_plane.job_state(job.job_id)
    assert (state["status"], state["failure_reason"]) == (status, reason)


def test_cancellation_stops_the_running_sandbox(
    control_plane: ControlPlane, make_sandbox: Callable[..., DockerSandbox], docker_cli: DockerCli
) -> None:
    # Shortest permitted lease: heartbeats every 3.75 s.
    job = control_plane.seed_fixture_job(lease_seconds=15)
    thread, outcomes, _ = run_in_background(
        control_plane,
        SandboxedFixtureExecutor(make_sandbox(timeout_seconds=120), FixtureMode.TIMEOUT),
        job,
    )
    wait_for(lambda: containers(docker_cli, job))
    started = time.monotonic()

    assert control_plane.cancel(job.scan_id) == "CANCELLED"
    thread.join(timeout=30)

    assert outcomes == [RunOutcome.ABANDONED]
    assert time.monotonic() - started < 15
    assert containers(docker_cli, job) == []
    assert control_plane.job_state(job.job_id)["status"] == "CANCELLED"


def test_a_lost_lease_stops_the_sandbox_and_its_result_is_never_accepted(
    control_plane: ControlPlane, make_sandbox: Callable[..., DockerSandbox], docker_cli: DockerCli
) -> None:
    job = control_plane.seed_fixture_job(lease_seconds=15)
    thread, outcomes, _ = run_in_background(
        control_plane,
        SandboxedFixtureExecutor(make_sandbox(timeout_seconds=120), FixtureMode.TIMEOUT),
        job,
    )
    wait_for(lambda: containers(docker_cli, job))

    # The lease expires (e.g. a partition) and the supervisor reclaims the job.
    control_plane.expire_lease(job.job_id)
    control_plane.supervise()
    thread.join(timeout=30)

    assert outcomes == [RunOutcome.ABANDONED]
    assert containers(docker_cli, job) == []
    assert control_plane.job_state(job.job_id)["status"] == "QUEUED"
    with control_plane.admin() as connection:
        reports = connection.execute(
            "SELECT count(*) FROM lifecycle.job_reports WHERE job_id = %s", (job.job_id,)
        ).fetchone()[0]
    assert reports == 0

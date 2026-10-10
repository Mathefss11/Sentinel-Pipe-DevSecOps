"""The worker side of the execution protocol against real PostgreSQL (Flyway V007), with
the worker's real, least-privileged login."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from infrastructure import ControlPlane, SeededJob

from sentinel_worker.execution import results
from sentinel_worker.execution.fixture import FixtureExecutor
from sentinel_worker.execution.leases import (
    FailureReason,
    HeartbeatStatus,
    JobLease,
    JobLeaseClient,
    JobOutcome,
    ReportOutcome,
)
from sentinel_worker.execution.runner import ExecutionLoop, RunOutcome

pytestmark = pytest.mark.integration


def result(lease: JobLease, outcome: JobOutcome, reason: FailureReason | None = None) -> bytes:
    now = datetime.now(UTC)
    return results.build(lease, outcome, reason, now, now)


def client(control_plane: ControlPlane, name: str = "worker") -> JobLeaseClient:
    return JobLeaseClient(control_plane.worker_settings(), f"sentinel-tests-{name}")


def claim(control_plane: ControlPlane, job: SeededJob) -> JobLease:
    with client(control_plane) as worker:
        lease = worker.claim(["FIXTURE"], job.scan_id)
    assert lease is not None
    return lease


def wait_for(condition: Any, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        time.sleep(0.05)


def test_a_claim_carries_only_authoritative_context(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()

    lease = claim(control_plane, job)

    assert lease.job_id == job.job_id
    assert lease.scan_id == job.scan_id
    assert lease.organization_id == job.organization_id
    assert lease.project_id == job.project_id
    assert lease.commit_sha == job.commit_sha
    assert lease.repository.name == job.repository_name
    assert (lease.attempt, lease.max_attempts, lease.epoch) == (1, 3, 1)
    assert lease.heartbeat_interval.total_seconds() == 15
    assert control_plane.job_state(job.job_id)["owner"] == "sentinel_worker_app"
    assert control_plane.scan_status(job.scan_id) == "RUNNING"


def test_heartbeat_and_report_move_the_scan_to_evaluation(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    lease = claim(control_plane, job)

    with client(control_plane) as worker:
        status, expires_at = worker.heartbeat(lease)
        assert status is HeartbeatStatus.RENEWED
        assert expires_at is not None
        assert expires_at >= lease.expires_at
        document = result(lease, JobOutcome.COMPLETED)
        assert worker.submit_result(lease, document) is ReportOutcome.ACCEPTED
        # A retry resubmits the same bytes (e.g. after an ambiguous commit).
        assert worker.submit_result(lease, document) is ReportOutcome.DUPLICATE

    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"
    # Execution finished; the security decision is the control plane's (never PASS here).
    assert control_plane.scan_status(job.scan_id) == "EVALUATING"


def test_the_execution_loop_runs_the_fixture_end_to_end(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker, client(control_plane, "heartbeat") as heartbeats:
        loop = ExecutionLoop(worker, heartbeats, FixtureExecutor(0.2), poll_interval=0.1)

        summary = loop.run(idle_timeout=0.5)

    assert summary.reported >= 1
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"
    assert control_plane.scan_status(job.scan_id) == "EVALUATING"


def test_concurrent_workers_claim_a_job_exactly_once(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    leases: list[JobLease | None] = []
    barrier = threading.Barrier(6)

    def race(index: int) -> None:
        with client(control_plane, f"racer-{index}") as worker:
            barrier.wait()
            leases.append(worker.claim(["FIXTURE"], job.scan_id))

    threads = [threading.Thread(target=race, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len([lease for lease in leases if lease is not None]) == 1
    assert control_plane.job_state(job.job_id)["epoch"] == 1


def test_a_crashed_workers_job_is_recovered_and_its_late_report_is_fenced(
    control_plane: ControlPlane,
) -> None:
    job = control_plane.seed_fixture_job()
    crashed = claim(control_plane, job)
    # The worker dies: no heartbeats. The lease expires and the supervisor reclaims it.
    control_plane.expire_lease(job.job_id)
    control_plane.supervise()
    assert control_plane.job_state(job.job_id)["failure_reason"] == "LEASE_EXPIRED"
    control_plane.make_retry_due(job.job_id)

    retry = claim(control_plane, job)
    with client(control_plane) as worker:
        assert (
            worker.submit_result(crashed, result(crashed, JobOutcome.COMPLETED))
            is ReportOutcome.REJECTED_STALE_EPOCH
        )
        assert worker.heartbeat(crashed)[0] is HeartbeatStatus.LEASE_LOST
        assert worker.submit_result(
            retry, result(retry, JobOutcome.FAILED, FailureReason.UNSUPPORTED_SCANNER)
        ) is (ReportOutcome.ACCEPTED)

    assert control_plane.job_state(job.job_id) | {"owner": None} == {
        "status": "FAILED",
        "attempts": 2,
        "epoch": 2,
        "owner": None,
        "failure_reason": "UNSUPPORTED_SCANNER",
    }


def test_a_lost_database_connection_is_survived(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker, client(control_plane, "heartbeat") as heartbeats:
        lease = worker.claim(["FIXTURE"], job.scan_id)
        assert lease is not None
        loop = ExecutionLoop(worker, heartbeats, FixtureExecutor(0.0), report_backoff=0.1)
        # Failure injection: PostgreSQL drops every worker connection mid-execution.
        assert control_plane.terminate_worker_connections() >= 1

        outcome = loop.run_one(lease)

    assert outcome is RunOutcome.REPORTED
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"


def test_a_cancelled_job_is_stopped_at_the_next_heartbeat(control_plane: ControlPlane) -> None:
    # Shortest permitted lease (15 s): heartbeats every 3.75 s.
    job = control_plane.seed_fixture_job(lease_seconds=15)
    outcomes: list[RunOutcome] = []
    with client(control_plane) as worker, client(control_plane, "heartbeat") as heartbeats:
        lease = worker.claim(["FIXTURE"], job.scan_id)
        assert lease is not None
        loop = ExecutionLoop(worker, heartbeats, FixtureExecutor(60.0))
        runner = threading.Thread(target=lambda: outcomes.append(loop.run_one(lease)))
        started = time.monotonic()
        runner.start()

        assert control_plane.cancel(job.scan_id) == "CANCELLED"
        runner.join(timeout=20)

    assert outcomes == [RunOutcome.ABANDONED]
    assert time.monotonic() - started < 10
    assert control_plane.job_state(job.job_id)["status"] == "CANCELLED"
    assert control_plane.scan_status(job.scan_id) == "CANCELLED"

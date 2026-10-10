"""Result integrity against real PostgreSQL (Flyway V008, ADR-0008) with the worker's real,
least-privileged login: evidence digests computed by the database, lease- and
tenant-bound references, idempotent submission, storage failures and log hygiene."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

import pytest
from infrastructure import ControlPlane, SeededJob

from sentinel_worker.execution import results
from sentinel_worker.execution.evidence import (
    Artifact,
    DatabaseEvidenceStore,
    EvidenceError,
    EvidenceRef,
)
from sentinel_worker.execution.fixture import FixtureExecutor
from sentinel_worker.execution.leases import (
    FailureReason,
    JobLease,
    JobLeaseClient,
    JobOutcome,
    ReportOutcome,
)
from sentinel_worker.execution.runner import ExecutionLoop, ExecutionResult, RunOutcome
from sentinel_worker.metrics import ExecutionMetrics

pytestmark = pytest.mark.integration

EVIDENCE = b'{"fixture":"harmless","ok":true}'
SECRET_LOOKING = b'{"aws_key":"AKIAFAKEFAKEFAKE0000"}'


def client(control_plane: ControlPlane, name: str = "worker") -> JobLeaseClient:
    return JobLeaseClient(control_plane.worker_settings(), f"sentinel-tests-{name}")


def claim(worker: JobLeaseClient, job: SeededJob) -> JobLease:
    lease = worker.claim(["FIXTURE"], job.scan_id)
    assert lease is not None
    return lease


def build(lease: JobLease, *references: EvidenceRef) -> bytes:
    now = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
    return results.build(lease, JobOutcome.COMPLETED, None, now, now, references)


def admin_query(control_plane: ControlPlane, sql: str, *parameters: Any) -> list[tuple[Any, ...]]:
    with control_plane.admin() as connection:
        return connection.execute(sql, parameters).fetchall()


class _Executor:
    scanner_types = frozenset({"FIXTURE"})

    def __init__(self, result: ExecutionResult) -> None:
        self.result = result

    def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
        return self.result


def test_the_fixture_run_stores_verified_evidence_of_record(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker, client(control_plane, "hb") as heartbeats:
        lease = claim(worker, job)
        outcome = ExecutionLoop(worker, heartbeats, FixtureExecutor(0.0)).run_one(lease)

    assert outcome is RunOutcome.REPORTED
    ((name, sha, size, organization, content),) = admin_query(
        control_plane,
        "SELECT u.name, u.sha256, u.size_bytes, u.organization_id, o.content"
        " FROM evidence.result_artifacts r"
        " JOIN evidence.job_artifacts u USING (job_id, lease_epoch, name)"
        " JOIN evidence.objects o ON o.organization_id = u.organization_id AND o.sha256 = u.sha256"
        " WHERE r.job_id = %s",
        job.job_id,
    )
    assert name == "fixture-result.json"
    assert organization == job.organization_id
    assert sha == hashlib.sha256(bytes(content)).hexdigest()
    assert size == len(bytes(content))
    assert json.loads(bytes(content))["repository_content_read"] is False
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"


def test_a_digest_the_database_did_not_compute_is_rejected(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker:
        lease = claim(worker, job)
        stored = DatabaseEvidenceStore(worker).put(
            lease, Artifact("fixture-result.json", "application/json", EVIDENCE)
        )
        forged = EvidenceRef(stored.name, stored.media_type, "f" * 64, stored.size_bytes)

        assert worker.submit_result(lease, build(lease, forged)) is (
            ReportOutcome.REJECTED_ARTIFACT_MISMATCH
        )
        assert worker.submit_result(lease, build(lease, stored)) is ReportOutcome.ACCEPTED


def test_another_tenants_evidence_cannot_be_substituted(control_plane: ControlPlane) -> None:
    victim_job = control_plane.seed_fixture_job()
    attacker_job = control_plane.seed_fixture_job()
    assert victim_job.organization_id != attacker_job.organization_id
    with client(control_plane) as worker:
        victim = claim(worker, victim_job)
        attacker = claim(worker, attacker_job)
        victim_evidence = DatabaseEvidenceStore(worker).put(
            victim, Artifact("fixture-result.json", "application/json", EVIDENCE)
        )

        assert worker.submit_result(attacker, build(attacker, victim_evidence)) is (
            ReportOutcome.REJECTED_MISSING_ARTIFACT
        )
    assert control_plane.job_state(attacker_job.job_id)["status"] == "RUNNING"


def test_uploads_under_a_stale_lease_are_refused(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker:
        stale = claim(worker, job)
        control_plane.expire_lease(job.job_id)
        control_plane.supervise()
        control_plane.make_retry_due(job.job_id)
        claim(worker, job)

        with pytest.raises(EvidenceError) as raised:
            DatabaseEvidenceStore(worker).put(
                stale, Artifact("fixture-result.json", "application/json", EVIDENCE)
            )
    assert not raised.value.transient
    assert "REJECTED_STALE_EPOCH" in str(raised.value)


def test_concurrent_identical_submissions_are_accepted_once(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker:
        lease = claim(worker, job)
        stored = DatabaseEvidenceStore(worker).put(
            lease, Artifact("fixture-result.json", "application/json", EVIDENCE)
        )
    document = build(lease, stored)
    answers: list[ReportOutcome] = []
    barrier = threading.Barrier(6)

    def submit(index: int) -> None:
        with client(control_plane, f"submitter-{index}") as submitter:
            barrier.wait()
            answers.append(submitter.submit_result(lease, document))

    threads = [threading.Thread(target=submit, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(answers) == sorted([ReportOutcome.ACCEPTED] + [ReportOutcome.DUPLICATE] * 5)


def test_a_database_outage_during_upload_is_survived(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    with client(control_plane) as worker, client(control_plane, "hb") as heartbeats:
        lease = claim(worker, job)
        # Failure injection: PostgreSQL drops every worker connection before the upload.
        assert control_plane.terminate_worker_connections() >= 1
        artifact = Artifact("fixture-result.json", "application/json", EVIDENCE)
        loop = ExecutionLoop(
            worker,
            heartbeats,
            _Executor(ExecutionResult.completed((artifact,))),
            report_backoff=0.1,
        )

        assert loop.run_one(lease) is RunOutcome.REPORTED

    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"


def test_unstorable_evidence_fails_the_attempt_for_a_retry(control_plane: ControlPlane) -> None:
    job = control_plane.seed_fixture_job()
    metrics = ExecutionMetrics()
    # Seventeen artifacts exceed the per-lease quota: the database refuses the 17th.
    artifacts = tuple(
        Artifact(f"part-{i:02}.json", "application/json", b'{"i":%d}' % i) for i in range(17)
    )
    with client(control_plane) as worker, client(control_plane, "hb") as heartbeats:
        lease = claim(worker, job)
        loop = ExecutionLoop(
            worker,
            heartbeats,
            _Executor(ExecutionResult.completed(artifacts)),
            report_backoff=0.0,
            metrics=metrics,
        )

        assert loop.run_one(lease) is RunOutcome.REPORTED

    state = control_plane.job_state(job.job_id)
    assert state["status"] == "QUEUED"
    assert state["failure_reason"] == FailureReason.EVIDENCE_UNAVAILABLE.value
    assert (
        metrics.registry.get_sample_value(
            "sentinel_worker_evidence_uploads_total", {"outcome": "refused"}
        )
        == 1
    )


def test_no_token_or_evidence_content_reaches_logs_or_audit_records(
    control_plane: ControlPlane, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    job = control_plane.seed_fixture_job()
    artifact = Artifact("fixture-result.json", "application/json", SECRET_LOOKING)
    with client(control_plane) as worker, client(control_plane, "hb") as heartbeats:
        lease = claim(worker, job)
        forged = dataclasses.replace(lease, token="c" * 64)
        worker.submit_result(forged, build(forged))
        ExecutionLoop(
            worker, heartbeats, _Executor(ExecutionResult.completed((artifact,)))
        ).run_one(lease)

    assert free_of_secrets(caplog.text, lease.token)
    audit = admin_query(
        control_plane,
        "SELECT row_to_json(e)::text FROM lifecycle.execution_events e WHERE e.scan_id = %s"
        " UNION ALL SELECT row_to_json(r)::text FROM lifecycle.report_rejections r"
        " WHERE r.job_id = %s"
        " UNION ALL SELECT row_to_json(j)::text FROM lifecycle.job_reports j WHERE j.job_id = %s",
        job.scan_id,
        job.job_id,
        job.job_id,
    )
    text = "\n".join(row[0] for row in audit)
    assert text
    assert free_of_secrets(text, lease.token)
    assert "c" * 64 not in text


def free_of_secrets(text: str, token: str) -> bool:
    return token not in text and "AKIA" not in text

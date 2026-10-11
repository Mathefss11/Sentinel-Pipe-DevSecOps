"""Trivy through the whole execution protocol: real PostgreSQL, the worker's
least-privileged login and real Trivy sandboxes with the verified synthetic database
(ADR-0007/0008/0012).

Findings are database-verified evidence bound to the job, lease and tenant; advisory prose
and raw reports are never stored; stale, crashed or cancelled attempts never get a result
accepted; completing a scan with or without findings never yields PASS.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from infrastructure import ControlPlane, SeededJob

from scanner_support import make_repository
from sentinel_worker.execution.leases import JobLease, JobLeaseClient
from sentinel_worker.execution.runner import ExecutionLoop, RunOutcome
from sentinel_worker.repository.snapshot import LocalFixtureRepositorySource
from sentinel_worker.sandbox.docker import DockerSandbox
from sentinel_worker.sandbox.policy import JOB_LABEL
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.trivy import TrivyAdapter
from trivy_images import TrivyImages
from trivy_support import MAVEN_ADVISORY, NPM_ADVISORY, npm_lock, pom

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]

PROSE = b"SYNTHETIC SentinelPipe test advisory"


def executor(images: TrivyImages, root: Path) -> ScannerExecutor:
    adapter = TrivyAdapter(images.image("fresh"))
    sandbox = DockerSandbox(images.cli, adapter.policy(timeout_seconds=120), monitor_interval=0.5)
    return ScannerExecutor(sandbox, adapter, LocalFixtureRepositorySource(root))


def client(control_plane: ControlPlane, name: str) -> JobLeaseClient:
    return JobLeaseClient(control_plane.worker_settings(), f"sentinel-tests-{name}")


def seed(control_plane: ControlPlane, root: Path, files: dict[str, str]) -> SeededJob:
    name = f"repo-{uuid.uuid4().hex[:10]}"
    make_repository(root, name, files)
    return control_plane.seed_fixture_job(scanner_type="TRIVY", repository_name=name)


def claim(control_plane: ControlPlane, job: SeededJob, name: str = "trivy") -> JobLease:
    with client(control_plane, f"{name}-claim") as worker:
        lease = worker.claim(["TRIVY"], job.scan_id)
    assert lease is not None
    return lease


def run_one(control_plane: ControlPlane, scanner: ScannerExecutor, lease: JobLease) -> RunOutcome:
    with client(control_plane, "trivy") as worker, client(control_plane, "trivy-hb") as hb:
        return ExecutionLoop(worker, hb, scanner, report_backoff=0.05).run_one(lease)


def stored_findings(control_plane: ControlPlane, job: SeededJob) -> tuple[dict[str, Any], Any]:
    with control_plane.admin() as connection:
        rows = connection.execute(
            "SELECT r.name, o.content, o.organization_id FROM evidence.result_artifacts r"
            " JOIN evidence.job_artifacts u USING (job_id, lease_epoch, name)"
            " JOIN evidence.objects o"
            " ON o.organization_id = u.organization_id AND o.sha256 = u.sha256"
            " WHERE r.job_id = %s",
            (job.job_id,),
        ).fetchall()
    assert [row[0] for row in rows] == ["findings.json"]
    return json.loads(bytes(rows[0][1])), rows[0][2]


def report_count(control_plane: ControlPlane, job: SeededJob) -> int:
    with control_plane.admin() as connection:
        return int(
            connection.execute(
                "SELECT count(*) FROM lifecycle.job_reports WHERE job_id = %s", (job.job_id,)
            ).fetchone()[0]
        )


def test_dependency_findings_are_verified_evidence_and_never_a_pass(
    control_plane: ControlPlane, trivy_images: TrivyImages, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"package-lock.json": npm_lock(), "pom.xml": pom()})

    outcome = run_one(control_plane, executor(trivy_images, tmp_path), claim(control_plane, job))

    assert outcome is RunOutcome.REPORTED
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"
    findings, organization = stored_findings(control_plane, job)
    assert organization == job.organization_id
    assert findings["scanner"]["name"] == "trivy"
    assert {NPM_ADVISORY, MAVEN_ADVISORY} <= {f["rule_id"] for f in findings["findings"]}
    assert findings["vulnerability_database"]["source"]["kind"] == "SYNTHETIC_FIXTURE"
    with control_plane.admin() as connection:
        leaked = connection.execute(
            "SELECT (SELECT count(*) FROM evidence.objects WHERE position(%s IN content) > 0)"
            " + (SELECT count(*) FROM lifecycle.job_reports"
            " WHERE position(%s IN result::text) > 0)",
            (PROSE, PROSE.decode()),
        ).fetchone()[0]
        decision = connection.execute(
            "SELECT execution_status, security_decision FROM scans WHERE id = %s", (job.scan_id,)
        ).fetchone()
    assert leaked == 0
    # Evaluation belongs to the control plane (M4); never PASS.
    assert tuple(decision) == ("EVALUATING", "PENDING")


def test_a_clean_scan_is_completed_without_findings(
    control_plane: ControlPlane, trivy_images: TrivyImages, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"package-lock.json": npm_lock("2.0.1", "1.0.5")})

    assert (
        run_one(control_plane, executor(trivy_images, tmp_path), claim(control_plane, job))
        is RunOutcome.REPORTED
    )

    findings, _ = stored_findings(control_plane, job)
    assert findings["finding_count"] == 0
    assert findings["coverage"]["files_analyzed"] == 1


def test_two_tenants_get_separate_evidence(
    control_plane: ControlPlane, trivy_images: TrivyImages, tmp_path: Path
) -> None:
    files = {"package-lock.json": npm_lock()}
    first, second = seed(control_plane, tmp_path, files), seed(control_plane, tmp_path, files)
    scanner = executor(trivy_images, tmp_path)

    for job in (first, second):
        assert run_one(control_plane, scanner, claim(control_plane, job)) is RunOutcome.REPORTED

    (doc_a, org_a), (doc_b, org_b) = (stored_findings(control_plane, j) for j in (first, second))
    assert (org_a, org_b) == (first.organization_id, second.organization_id)
    assert doc_a["context"]["organization_id"] == str(first.organization_id)
    assert doc_b["context"]["organization_id"] == str(second.organization_id)
    assert {f["id"] for f in doc_a["findings"]}.isdisjoint({f["id"] for f in doc_b["findings"]})


def test_lost_leases_and_cancelled_scans_never_get_findings_accepted(
    control_plane: ControlPlane, trivy_images: TrivyImages, tmp_path: Path
) -> None:
    scanner = executor(trivy_images, tmp_path)
    lost = seed(control_plane, tmp_path, {"package-lock.json": npm_lock()})
    lost_lease = claim(control_plane, lost)
    control_plane.expire_lease(lost.job_id)
    control_plane.supervise()
    cancelled = seed(control_plane, tmp_path, {"pom.xml": pom()})
    cancelled_lease = claim(control_plane, cancelled)
    assert control_plane.cancel(cancelled.scan_id) == "CANCELLED"

    assert run_one(control_plane, scanner, lost_lease) is RunOutcome.REJECTED
    assert run_one(control_plane, scanner, cancelled_lease) is RunOutcome.REJECTED

    assert report_count(control_plane, lost) == report_count(control_plane, cancelled) == 0
    assert control_plane.job_state(cancelled.job_id)["status"] == "CANCELLED"
    for job in (lost, cancelled):
        listing = trivy_images.cli.call(
            ["ps", "--all", "--filter", f"label={JOB_LABEL}={job.job_id}", "--format", "{{.Names}}"]
        )
        assert listing.stdout.strip() == b""

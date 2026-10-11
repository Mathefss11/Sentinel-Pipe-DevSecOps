"""Semgrep through the whole execution protocol: real PostgreSQL, the worker's
least-privileged login and real Semgrep sandboxes (ADR-0007/0008/0011).

Findings are database-verified evidence bound to the job, lease and tenant; source
excerpts are never stored; stale, crashed or cancelled attempts never get a result
accepted; completing a scan with or without findings never yields PASS.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from infrastructure import ControlPlane, SeededJob

from scanner_support import make_repository
from semgrep_support import CLEAN, VULNERABLE
from sentinel_worker.execution.leases import JobLease, JobLeaseClient
from sentinel_worker.execution.runner import ExecutionLoop, RunOutcome
from sentinel_worker.repository.snapshot import LocalFixtureRepositorySource
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
from sentinel_worker.sandbox.policy import JOB_LABEL, SEMGREP_IMAGE
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.semgrep import SemgrepAdapter

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]

MARKER = "SENTINEL_PROPRIETARY_SOURCE_" + "I" * 24


@pytest.fixture(scope="module")
def semgrep_cli(docker_cli: DockerCli) -> DockerCli:
    if docker_cli.call(["image", "inspect", SEMGREP_IMAGE]).returncode != 0:
        problem = f"Semgrep image not present; pull {SEMGREP_IMAGE}"
        if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    return docker_cli


def executor(cli: DockerCli, root: Path) -> ScannerExecutor:
    adapter = SemgrepAdapter()
    sandbox = DockerSandbox(cli, adapter.policy(timeout_seconds=120), monitor_interval=0.5)
    return ScannerExecutor(sandbox, adapter, LocalFixtureRepositorySource(root))


def client(control_plane: ControlPlane, name: str) -> JobLeaseClient:
    return JobLeaseClient(control_plane.worker_settings(), f"sentinel-tests-{name}")


def seed(control_plane: ControlPlane, root: Path, files: dict[str, str]) -> SeededJob:
    name = f"repo-{uuid.uuid4().hex[:10]}"
    make_repository(root, name, files)
    return control_plane.seed_fixture_job(scanner_type="SEMGREP", repository_name=name)


def claim(control_plane: ControlPlane, job: SeededJob, name: str = "semgrep") -> JobLease:
    with client(control_plane, f"{name}-claim") as worker:
        lease = worker.claim(["SEMGREP"], job.scan_id)
    assert lease is not None
    return lease


def run_one(control_plane: ControlPlane, scanner: ScannerExecutor, lease: JobLease) -> RunOutcome:
    with client(control_plane, "semgrep") as worker, client(control_plane, "semgrep-hb") as hb:
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


def test_findings_are_verified_evidence_without_source_and_never_a_pass(
    control_plane: ControlPlane, semgrep_cli: DockerCli, tmp_path: Path
) -> None:
    path, code, _ = VULNERABLE["python"]
    job = seed(control_plane, tmp_path, {path: f"# {MARKER}\n" + code})

    outcome = run_one(control_plane, executor(semgrep_cli, tmp_path), claim(control_plane, job))

    assert outcome is RunOutcome.REPORTED
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"
    findings, organization = stored_findings(control_plane, job)
    assert organization == job.organization_id
    assert findings["scanner"]["name"] == "semgrep"
    assert findings["finding_count"] == 8
    with control_plane.admin() as connection:
        leaked = connection.execute(
            "SELECT (SELECT count(*) FROM evidence.objects WHERE position(%s IN content) > 0)"
            " + (SELECT count(*) FROM lifecycle.job_reports WHERE position(%s IN result::text) > 0)"
            " + (SELECT count(*) FROM lifecycle.execution_events e"
            " WHERE position(%s IN row_to_json(e)::text) > 0)",
            (MARKER.encode(), MARKER, MARKER),
        ).fetchone()[0]
        decision = connection.execute(
            "SELECT execution_status, security_decision FROM scans WHERE id = %s", (job.scan_id,)
        ).fetchone()
    assert leaked == 0
    # Evaluation belongs to the control plane (Java supervisor, end-to-end tested), which
    # records INCOMPLETE until policies exist (M4). Never PASS.
    assert tuple(decision) == ("EVALUATING", "PENDING")


def test_a_clean_scan_is_completed_without_findings(
    control_plane: ControlPlane, semgrep_cli: DockerCli, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, dict(CLEAN.values()))

    assert run_one(control_plane, executor(semgrep_cli, tmp_path), claim(control_plane, job)) is (
        RunOutcome.REPORTED
    )

    findings, _ = stored_findings(control_plane, job)
    assert findings["finding_count"] == 0
    assert findings["coverage"]["files_analyzed"] == 4


def test_two_tenants_get_separate_evidence(
    control_plane: ControlPlane, semgrep_cli: DockerCli, tmp_path: Path
) -> None:
    files = {VULNERABLE["javascript"][0]: VULNERABLE["javascript"][1]}
    first, second = seed(control_plane, tmp_path, files), seed(control_plane, tmp_path, files)
    scanner = executor(semgrep_cli, tmp_path)

    for job in (first, second):
        assert run_one(control_plane, scanner, claim(control_plane, job)) is RunOutcome.REPORTED

    (doc_a, org_a), (doc_b, org_b) = (stored_findings(control_plane, j) for j in (first, second))
    assert (org_a, org_b) == (first.organization_id, second.organization_id)
    assert doc_a["context"]["organization_id"] == str(first.organization_id)
    assert doc_b["context"]["organization_id"] == str(second.organization_id)
    assert [f["fingerprint"] for f in doc_a["findings"]] == [
        f["fingerprint"] for f in doc_b["findings"]
    ]


def test_a_crashed_attempt_is_retried_and_only_the_new_lease_is_accepted(
    control_plane: ControlPlane, semgrep_cli: DockerCli, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"a.py": "eval(input())\n"})
    crashed = claim(control_plane, job, "crashed")
    control_plane.expire_lease(job.job_id)
    control_plane.supervise()
    control_plane.make_retry_due(job.job_id)
    scanner = executor(semgrep_cli, tmp_path)

    retried = claim(control_plane, job, "retry")
    assert run_one(control_plane, scanner, retried) is RunOutcome.REPORTED
    assert run_one(control_plane, scanner, crashed) is RunOutcome.REJECTED

    state = control_plane.job_state(job.job_id)
    assert (state["status"], state["attempts"]) == ("COMPLETED", 2)
    assert report_count(control_plane, job) == 1


def test_lost_leases_and_cancelled_scans_never_get_findings_accepted(
    control_plane: ControlPlane, semgrep_cli: DockerCli, tmp_path: Path
) -> None:
    scanner = executor(semgrep_cli, tmp_path)
    lost = seed(control_plane, tmp_path, {"a.py": "eval(input())\n"})
    lost_lease = claim(control_plane, lost)
    control_plane.expire_lease(lost.job_id)
    control_plane.supervise()
    cancelled = seed(control_plane, tmp_path, {"b.py": "eval(input())\n"})
    cancelled_lease = claim(control_plane, cancelled)
    assert control_plane.cancel(cancelled.scan_id) == "CANCELLED"

    assert run_one(control_plane, scanner, lost_lease) is RunOutcome.REJECTED
    assert run_one(control_plane, scanner, cancelled_lease) is RunOutcome.REJECTED

    assert report_count(control_plane, lost) == report_count(control_plane, cancelled) == 0
    assert control_plane.job_state(cancelled.job_id)["status"] == "CANCELLED"
    for job in (lost, cancelled):
        listing = semgrep_cli.call(
            ["ps", "--all", "--filter", f"label={JOB_LABEL}={job.job_id}", "--format", "{{.Names}}"]
        )
        assert listing.stdout.strip() == b""

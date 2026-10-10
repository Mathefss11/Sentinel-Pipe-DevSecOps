"""Gitleaks through the whole execution protocol: real PostgreSQL, the worker's
least-privileged login and real Gitleaks sandboxes (ADR-0007/0008/0010).

Findings are database-verified evidence bound to the job, lease and tenant; raw secrets
are never stored; a stale, crashed or cancelled attempt never gets a result accepted; and
completing a scan with or without findings never yields PASS.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from infrastructure import ControlPlane, SeededJob

from scanner_support import make_repository, synthetic_github_token
from sentinel_worker.execution.leases import JobLease, JobLeaseClient
from sentinel_worker.execution.runner import ExecutionLoop, RunOutcome
from sentinel_worker.repository.snapshot import LocalFixtureRepositorySource
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
from sentinel_worker.sandbox.policy import GITLEAKS_IMAGE, JOB_LABEL
from sentinel_worker.scanners.executor import ScannerExecutor
from sentinel_worker.scanners.gitleaks import GitleaksAdapter

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]

TOKEN = synthetic_github_token(21)


@pytest.fixture(scope="module")
def gitleaks_cli(docker_cli: DockerCli) -> DockerCli:
    if docker_cli.call(["image", "inspect", GITLEAKS_IMAGE]).returncode != 0:
        problem = f"Gitleaks image not present; pull {GITLEAKS_IMAGE}"
        if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    return docker_cli


def executor(cli: DockerCli, root: Path) -> ScannerExecutor:
    adapter = GitleaksAdapter()
    sandbox = DockerSandbox(cli, adapter.policy(timeout_seconds=60), monitor_interval=0.5)
    return ScannerExecutor(sandbox, adapter, LocalFixtureRepositorySource(root))


def client(control_plane: ControlPlane, name: str) -> JobLeaseClient:
    return JobLeaseClient(control_plane.worker_settings(), f"sentinel-tests-{name}")


def seed(control_plane: ControlPlane, root: Path, files: dict[str, str]) -> SeededJob:
    name = f"repo-{uuid.uuid4().hex[:10]}"
    make_repository(root, name, files)
    return control_plane.seed_fixture_job(scanner_type="GITLEAKS", repository_name=name)


def claim(control_plane: ControlPlane, job: SeededJob, name: str = "gitleaks") -> JobLease:
    with client(control_plane, f"{name}-claim") as worker:
        lease = worker.claim(["GITLEAKS"], job.scan_id)
    assert lease is not None
    return lease


def run_one(control_plane: ControlPlane, scanner: ScannerExecutor, lease: JobLease) -> RunOutcome:
    with client(control_plane, "gitleaks") as worker, client(control_plane, "gitleaks-hb") as hb:
        return ExecutionLoop(worker, hb, scanner, report_backoff=0.05).run_one(lease)


def stored_findings(control_plane: ControlPlane, job: SeededJob) -> tuple[dict[str, Any], Any]:
    """The accepted findings.json of the job and the organization its object belongs to."""
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


def containers(cli: DockerCli, job: SeededJob) -> list[str]:
    result = cli.call(
        ["ps", "--all", "--filter", f"label={JOB_LABEL}={job.job_id}", "--format", "{{.Names}}"]
    )
    return result.stdout.decode().split()


def test_findings_are_verified_evidence_and_never_a_pass(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"app/config.py": f'TOKEN = "{TOKEN}"\n'})

    outcome = run_one(control_plane, executor(gitleaks_cli, tmp_path), claim(control_plane, job))

    assert outcome is RunOutcome.REPORTED
    assert control_plane.job_state(job.job_id)["status"] == "COMPLETED"
    findings, organization = stored_findings(control_plane, job)
    assert organization == job.organization_id
    assert findings["context"]["organization_id"] == str(job.organization_id)
    assert findings["context"]["commit_sha"] == job.commit_sha
    assert [f["location"]["path"] for f in findings["findings"]] == ["app/config.py"]
    with control_plane.admin() as connection:
        leaked = connection.execute(
            "SELECT count(*) FROM evidence.objects WHERE position(%s IN content) > 0",
            (TOKEN.encode(),),
        ).fetchone()[0]
        control_plane.supervise()
        decision = connection.execute(
            "SELECT execution_status, security_decision, decision_reason FROM scans WHERE id = %s",
            (job.scan_id,),
        ).fetchone()
    assert leaked == 0
    # Execution finished; the decision is the control plane's evaluation (Java supervisor,
    # covered end to end), which records INCOMPLETE until policies exist (M4). Never PASS.
    assert tuple(decision) == ("EVALUATING", "PENDING", None)
    assert containers(gitleaks_cli, job) == []


def test_two_tenants_scanning_identical_content_get_separate_evidence(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    files = {"secret.env": f"GITHUB_TOKEN={TOKEN}\n"}
    first, second = seed(control_plane, tmp_path, files), seed(control_plane, tmp_path, files)
    scanner = executor(gitleaks_cli, tmp_path)

    for job in (first, second):
        assert run_one(control_plane, scanner, claim(control_plane, job)) is RunOutcome.REPORTED

    (doc_a, org_a), (doc_b, org_b) = (
        stored_findings(control_plane, first),
        stored_findings(control_plane, second),
    )
    assert (org_a, org_b) == (first.organization_id, second.organization_id)
    assert doc_a["context"]["organization_id"] != doc_b["context"]["organization_id"]
    # Same content, same fingerprints; separate, tenant-scoped evidence objects.
    assert [f["fingerprint"] for f in doc_a["findings"]] == [
        f["fingerprint"] for f in doc_b["findings"]
    ]
    assert doc_a["input"]["content_sha256"] == doc_b["input"]["content_sha256"]


def test_a_crashed_attempt_is_retried_and_only_the_new_lease_is_accepted(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"a.txt": f"{TOKEN}\n"})
    crashed = claim(control_plane, job, "crashed")
    # The first worker dies without reporting; the supervisor reclaims the job.
    control_plane.expire_lease(job.job_id)
    control_plane.supervise()
    assert control_plane.job_state(job.job_id)["status"] == "QUEUED"
    control_plane.make_retry_due(job.job_id)
    scanner = executor(gitleaks_cli, tmp_path)

    retried = claim(control_plane, job, "retry")
    assert run_one(control_plane, scanner, retried) is RunOutcome.REPORTED
    # The crashed worker's lease is fenced even if it comes back with a result.
    assert run_one(control_plane, scanner, crashed) is RunOutcome.REJECTED

    state = control_plane.job_state(job.job_id)
    assert (state["status"], state["attempts"], state["epoch"]) == (
        "COMPLETED",
        2,
        retried.epoch,
    )
    assert report_count(control_plane, job) == 1


def test_a_lost_lease_never_gets_findings_accepted(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"a.txt": f"{TOKEN}\n"})
    lease = claim(control_plane, job)
    control_plane.expire_lease(job.job_id)
    control_plane.supervise()

    outcome = run_one(control_plane, executor(gitleaks_cli, tmp_path), lease)

    assert outcome is RunOutcome.REJECTED
    assert report_count(control_plane, job) == 0
    assert control_plane.job_state(job.job_id)["status"] == "QUEUED"


def test_a_cancelled_scan_never_gets_findings_accepted(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    job = seed(control_plane, tmp_path, {"a.txt": f"{TOKEN}\n"})
    lease = claim(control_plane, job)
    assert control_plane.cancel(job.scan_id) == "CANCELLED"

    outcome = run_one(control_plane, executor(gitleaks_cli, tmp_path), lease)

    assert outcome is RunOutcome.REJECTED
    assert report_count(control_plane, job) == 0
    assert control_plane.job_state(job.job_id)["status"] == "CANCELLED"
    assert containers(gitleaks_cli, job) == []


def test_a_missing_repository_fails_closed_and_is_retried(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    job = control_plane.seed_fixture_job(scanner_type="GITLEAKS", repository_name="absent")

    outcome = run_one(control_plane, executor(gitleaks_cli, tmp_path), claim(control_plane, job))

    assert outcome is RunOutcome.REPORTED
    state = control_plane.job_state(job.job_id)
    assert (state["status"], state["failure_reason"]) == ("QUEUED", "SCANNER_ERROR")


def test_secrets_in_file_names_are_never_stored(
    control_plane: ControlPlane, gitleaks_cli: DockerCli, tmp_path: Path
) -> None:
    """Regression (security review D2): a credential committed as a file name is reported
    as a FILE_PATH finding with a redacted path; the raw name is in no stored evidence."""
    name_secret = synthetic_github_token(22)
    job = seed(control_plane, tmp_path, {f"keys/{name_secret}.txt": "harmless\n"})

    outcome = run_one(control_plane, executor(gitleaks_cli, tmp_path), claim(control_plane, job))

    assert outcome is RunOutcome.REPORTED
    findings, _ = stored_findings(control_plane, job)
    (finding,) = findings["findings"]
    assert finding["location"]["target"] == "FILE_PATH"
    assert finding["location"]["path"] == "keys/[redacted-1]"
    with control_plane.admin() as connection:
        leaked = connection.execute(
            "SELECT (SELECT count(*) FROM evidence.objects WHERE position(%s IN content) > 0)"
            " + (SELECT count(*) FROM lifecycle.job_reports WHERE position(%s IN result::text) > 0)"
            " + (SELECT count(*) FROM lifecycle.execution_events WHERE position(%s IN row_to_json("
            "execution_events)::text) > 0)",
            (name_secret.encode(), name_secret, name_secret),
        ).fetchone()[0]
    assert leaked == 0

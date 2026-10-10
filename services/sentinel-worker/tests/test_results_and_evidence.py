"""Unit tests of job-result.v1 documents, evidence handling and execution metrics."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from prometheus_client import generate_latest

from sentinel_worker.execution import results
from sentinel_worker.execution.evidence import (
    Artifact,
    DatabaseEvidenceStore,
    EvidenceError,
    EvidenceRef,
)
from sentinel_worker.execution.fixture import FixtureExecutor
from sentinel_worker.execution.leases import FailureReason, JobOutcome, LeaseStoreError
from sentinel_worker.execution.runner import ExecutionLoop, ExecutionResult, RunOutcome
from sentinel_worker.messaging import contracts
from sentinel_worker.metrics import ExecutionMetrics
from test_execution import T0, TOKEN, FakeClient, ScriptedExecutor, lease

SECRET_LOOKING = b'{"aws_key":"AKIAFAKEFAKEFAKE0000"}'


def ref(name: str = "fixture-result.json", content: bytes = b"{}") -> EvidenceRef:
    return EvidenceRef(name, "application/json", hashlib.sha256(content).hexdigest(), len(content))


# --- job-result.v1 -------------------------------------------------------------------


def test_results_are_canonical_and_reproducible() -> None:
    claimed = lease()
    finished = T0 + timedelta(seconds=2)

    first = results.build(
        claimed, JobOutcome.COMPLETED, None, T0, finished, [ref("b.json"), ref("a.json")]
    )
    second = results.build(
        claimed, JobOutcome.COMPLETED, None, T0, finished, [ref("a.json"), ref("b.json")]
    )

    assert first == second
    document = json.loads(first)
    assert first == json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert [a["name"] for a in document["artifacts"]] == ["a.json", "b.json"]
    assert b" " not in first
    assert document["started_at"] == "2026-10-10T12:00:00.000000Z"
    validator = contracts.validator(contracts.JOB_RESULT_SCHEMA)
    assert list(validator.iter_errors(document)) == []


def test_results_carry_the_leases_authoritative_context_but_never_its_token() -> None:
    claimed = lease()

    document = json.loads(
        results.build(claimed, JobOutcome.FAILED, FailureReason.SCANNER_ERROR, T0, T0)
    )

    assert document["job_id"] == str(claimed.job_id)
    assert document["organization_id"] == str(claimed.organization_id)
    assert document["commit_sha"] == claimed.commit_sha
    assert document["lease_epoch"] == claimed.epoch
    assert document["schema_version"] == 1
    assert TOKEN not in json.dumps(document)


def test_timestamps_are_utc_and_never_go_backwards() -> None:
    local = T0.astimezone(timezone(timedelta(hours=-3)))

    document = json.loads(
        results.build(lease(), JobOutcome.COMPLETED, None, local, local - timedelta(1))
    )

    assert document["started_at"].endswith("Z")
    assert document["finished_at"] == document["started_at"]


def test_invalid_results_are_never_built() -> None:
    with pytest.raises(results.InvalidResultError):
        results.build(lease(), JobOutcome.COMPLETED, None, T0, T0, [ref(), ref()])
    with pytest.raises(results.InvalidResultError):
        results.build(
            lease(), JobOutcome.COMPLETED, None, T0, T0, [ref(f"a{i}.json") for i in range(17)]
        )


def test_the_contract_rejects_other_versions_and_unknown_fields() -> None:
    document = json.loads(results.build(lease(), JobOutcome.COMPLETED, None, T0, T0))
    validator = contracts.validator(contracts.JOB_RESULT_SCHEMA)

    assert list(validator.iter_errors(document | {"schema_version": 2}))
    assert list(validator.iter_errors(document | {"lease_token": TOKEN}))
    assert list(validator.iter_errors(document | {"attempt": 1.5}))
    path_reference = {
        "name": "../etc/passwd",
        "media_type": "text/plain",
        "sha256": "a" * 64,
        "size_bytes": 1,
    }
    assert list(validator.iter_errors(document | {"artifacts": [path_reference]}))


# --- Artifacts and the evidence store ------------------------------------------------


@pytest.mark.parametrize(
    "name", ["../x", "a/b", "https://evil.example/x", "UPPER.json", "", ".hidden", "a..b", "x" * 65]
)
def test_artifact_names_are_identifiers_never_paths(name: str) -> None:
    with pytest.raises(ValueError, match="identifiers"):
        Artifact(name, "application/json", b"{}")


def test_artifact_limits_and_repr() -> None:
    with pytest.raises(ValueError, match="media type"):
        Artifact("x.html", "text/html", b"")
    with pytest.raises(ValueError, match="limited"):
        Artifact("big.txt", "text/plain", b"x" * (1024 * 1024 + 1))
    assert "AKIA" not in repr(Artifact("a.json", "application/json", SECRET_LOOKING))


def test_the_store_returns_the_databases_digest() -> None:
    artifact = Artifact("a.json", "application/json", SECRET_LOOKING)

    stored = DatabaseEvidenceStore(FakeClient()).put(lease(), artifact)  # type: ignore[arg-type]

    assert stored == EvidenceRef("a.json", "application/json", artifact.sha256, len(SECRET_LOOKING))


@pytest.mark.parametrize(
    ("answer", "transient"),
    [
        (("STORED", "0" * 64, 2), False),  # the stored bytes are not the produced bytes
        (("CONFLICT", None, None), False),
        (("REJECTED_STALE_EPOCH", None, None), False),
        (LeaseStoreError("down"), True),
    ],
)
def test_unverifiable_evidence_is_never_referenced(answer: Any, transient: bool) -> None:
    store = DatabaseEvidenceStore(FakeClient(uploads=[answer]))  # type: ignore[arg-type]

    with pytest.raises(EvidenceError) as raised:
        store.put(lease(), Artifact("a.json", "application/json", SECRET_LOOKING))

    assert raised.value.transient is transient
    assert "AKIA" not in str(raised.value)


# --- Execution loop with evidence ----------------------------------------------------


def run(
    client: FakeClient, result: ExecutionResult, metrics: ExecutionMetrics | None = None
) -> RunOutcome:
    loop = ExecutionLoop(
        client,  # type: ignore[arg-type]
        FakeClient(),  # type: ignore[arg-type]
        ScriptedExecutor(result),
        report_backoff=0.0,
        clock=lambda: T0,
        metrics=metrics,
    )
    return loop.run_one(lease())


def test_evidence_is_uploaded_and_referenced_with_the_stored_digest() -> None:
    client = FakeClient()
    artifact = Artifact("fixture-result.json", "application/json", b'{"ok":true}')

    assert run(client, ExecutionResult.completed((artifact,))) is RunOutcome.REPORTED

    assert client.uploaded == ["fixture-result.json"]
    (document,) = [json.loads(d) for d in client.documents]
    assert document["artifacts"] == [
        {
            "media_type": "application/json",
            "name": "fixture-result.json",
            "sha256": artifact.sha256,
            "size_bytes": len(artifact.content),
        }
    ]


def test_a_storage_outage_is_retried() -> None:
    client = FakeClient(uploads=[LeaseStoreError("down"), LeaseStoreError("down")])
    artifact = Artifact("fixture-result.json", "application/json", b"{}")

    run(client, ExecutionResult.completed((artifact,)))

    assert len(client.uploaded) == 3
    assert client.reported == [(JobOutcome.COMPLETED, None)]


@pytest.mark.parametrize(
    "failure",
    [LeaseStoreError("down")] * 1 + [("STORED", "f" * 64, 2), ("CONFLICT", None, None)],
)
def test_evidence_that_cannot_be_stored_or_verified_fails_the_attempt_for_retry(
    failure: Any,
) -> None:
    client = FakeClient(uploads=[failure] * 10)
    artifact = Artifact("fixture-result.json", "application/json", b"{}")

    assert run(client, ExecutionResult.completed((artifact,))) is RunOutcome.REPORTED

    assert client.reported == [(JobOutcome.FAILED, FailureReason.EVIDENCE_UNAVAILABLE)]
    assert json.loads(client.documents[0])["artifacts"] == []


def test_the_fixture_produces_verifiable_evidence_end_to_end_with_fakes() -> None:
    client = FakeClient()
    loop = ExecutionLoop(
        client,  # type: ignore[arg-type]
        FakeClient(),  # type: ignore[arg-type]
        FixtureExecutor(0),
        clock=lambda: T0,
    )

    assert loop.run_one(lease()) is RunOutcome.REPORTED
    assert client.uploaded == ["fixture-result.json"]


# --- Metrics and logs ----------------------------------------------------------------


def test_metrics_cover_the_execution_and_contain_no_identifiers_or_secrets() -> None:
    metrics = ExecutionMetrics()
    client = FakeClient(claims=[lease(), None])
    artifact = Artifact("fixture-result.json", "application/json", SECRET_LOOKING)
    loop = ExecutionLoop(
        client,  # type: ignore[arg-type]
        FakeClient(),  # type: ignore[arg-type]
        ScriptedExecutor(ExecutionResult.completed((artifact,))),
        poll_interval=0.01,
        clock=lambda: T0,
        metrics=metrics,
    )

    loop.run(max_jobs=1)

    def value(name: str, **labels: str) -> float:
        sample = metrics.registry.get_sample_value(name, labels)
        return sample if sample is not None else 0.0

    assert value("sentinel_worker_job_claims_total", outcome="claimed") == 1
    assert value("sentinel_worker_job_results_total", outcome="accepted") == 1
    assert value("sentinel_worker_job_runs_total", outcome="reported") == 1
    assert value("sentinel_worker_evidence_uploads_total", outcome="stored") == 1
    assert value("sentinel_worker_job_execution_seconds_count", scanner_type="FIXTURE") == 1
    exposition = generate_latest(metrics.registry).decode()
    assert TOKEN not in exposition
    assert "AKIA" not in exposition
    assert "job_id" not in exposition


def test_metric_labels_are_a_closed_set() -> None:
    metrics = ExecutionMetrics()

    with pytest.raises(ValueError, match="label"):
        metrics.result("REJECTED_SOMETHING_NEW")
    with pytest.raises(ValueError, match="label"):
        metrics.executed("../../etc", 1.0)
    metrics.heartbeat("RENEWED")
    metrics.result("REJECTED_ARTIFACT_MISMATCH")


def test_logs_never_contain_tokens_or_evidence(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    client = FakeClient(uploads=[("STORED", "0" * 64, 1)], reports=[LeaseStoreError("down")])
    artifact = Artifact("fixture-result.json", "application/json", SECRET_LOOKING)

    run(client, ExecutionResult.completed((artifact,)))

    assert caplog.records
    assert TOKEN not in caplog.text
    assert "AKIA" not in caplog.text


def test_heartbeats_are_counted() -> None:
    metrics = ExecutionMetrics()
    stop = threading.Event()
    from sentinel_worker.execution.runner import LeaseKeeper

    keeper = LeaseKeeper(
        FakeClient(heartbeats=[LeaseStoreError("down")]),  # type: ignore[arg-type]
        lease(),
        stop,
        clock=lambda: datetime(2026, 10, 10, 12, 0, 10, tzinfo=UTC),
        metrics=metrics,
    )
    keeper.beat()
    keeper.beat()

    assert (
        metrics.registry.get_sample_value("sentinel_worker_heartbeats_total", {"status": "error"})
        == 1
    )
    assert (
        metrics.registry.get_sample_value("sentinel_worker_heartbeats_total", {"status": "renewed"})
        == 1
    )

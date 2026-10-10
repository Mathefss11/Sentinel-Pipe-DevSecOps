"""Unit tests of the execution client, lease keeper and loop (no database)."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from sentinel_worker import cli
from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.execution import results
from sentinel_worker.execution.fixture import FixtureExecutor
from sentinel_worker.execution.leases import (
    FailureReason,
    HeartbeatStatus,
    JobLease,
    JobLeaseClient,
    JobOutcome,
    LeaseStoreError,
    ReportOutcome,
    Repository,
)
from sentinel_worker.execution.runner import (
    ExecutionLoop,
    ExecutionResult,
    LeaseKeeper,
    RunOutcome,
    StopReason,
)
from sentinel_worker.execution.settings import ExecutionSettings
from sentinel_worker.messaging.receipts import DatabaseSettings

T0 = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
TOKEN = "ab" * 32


def lease(lease_seconds: int = 60, scanner_type: str = "FIXTURE") -> JobLease:
    return JobLease(
        job_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        commit_sha="a" * 40,
        branch="main",
        repository=Repository("GITHUB", "acme", "repo"),
        scanner_type=scanner_type,
        attempt=1,
        max_attempts=3,
        epoch=1,
        token=TOKEN,
        expires_at=T0 + timedelta(seconds=lease_seconds),
        lease_duration_seconds=lease_seconds,
        deadline_at=T0 + timedelta(minutes=15),
    )


class FakeClient:
    """Scripted stand-in for JobLeaseClient. Script entries may be exceptions."""

    def __init__(
        self,
        claims: Iterable[Any] = (),
        heartbeats: Iterable[Any] = (),
        reports: Iterable[Any] = (),
        uploads: Iterable[Any] = (),
    ) -> None:
        self.claims = list(claims)
        self.heartbeats = list(heartbeats)
        self.reports = list(reports)
        self.uploads = list(uploads)
        self.reported: list[tuple[JobOutcome, FailureReason | None]] = []
        self.documents: list[bytes] = []
        self.uploaded: list[str] = []
        self.heartbeat_calls = 0

    @staticmethod
    def _next(script: list[Any], default: Any) -> Any:
        value = script.pop(0) if script else default
        if isinstance(value, Exception):
            raise value
        return value

    def claim(self, scanner_types: Iterable[str], scan_id: uuid.UUID | None = None) -> Any:
        return self._next(self.claims, None)

    def heartbeat(self, lease: JobLease) -> Any:
        self.heartbeat_calls += 1
        return self._next(self.heartbeats, (HeartbeatStatus.RENEWED, T0 + timedelta(minutes=1)))

    def submit_result(self, lease: JobLease, document: bytes) -> Any:
        parsed = json.loads(document)
        reason = parsed["failure_reason"]
        self.reported.append(
            (JobOutcome(parsed["outcome"]), FailureReason(reason) if reason else None)
        )
        self.documents.append(document)
        return self._next(self.reports, ReportOutcome.ACCEPTED)

    def put_evidence(self, lease: JobLease, name: str, media_type: str, content: bytes) -> Any:
        self.uploaded.append(name)
        default = ("STORED", hashlib.sha256(content).hexdigest(), len(content))
        return self._next(self.uploads, default)


class ScriptedExecutor:
    scanner_types = frozenset({"FIXTURE"})

    def __init__(self, result: ExecutionResult | Exception, wait: float = 0.0) -> None:
        self.result = result
        self.wait = wait
        self.stopped = False

    def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
        self.stopped = stop.wait(self.wait)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def loop(client: FakeClient, executor: Any, heartbeats: FakeClient | None = None) -> ExecutionLoop:
    return ExecutionLoop(
        client,  # type: ignore[arg-type]
        heartbeats or FakeClient(),  # type: ignore[arg-type]
        executor,
        poll_interval=0.01,
        report_backoff=0.0,
        clock=lambda: T0,
    )


# --- Lease ---------------------------------------------------------------------------


def test_the_lease_token_never_appears_in_reprs_or_logs() -> None:
    claimed = lease()

    assert TOKEN not in repr(claimed)
    assert TOKEN not in str(claimed.log_fields())


def test_heartbeats_run_every_quarter_of_the_lease() -> None:
    assert lease(60).heartbeat_interval == timedelta(seconds=15)


# --- LeaseKeeper ---------------------------------------------------------------------


def keeper(client: FakeClient, now: list[datetime]) -> tuple[LeaseKeeper, threading.Event]:
    stop = threading.Event()
    return LeaseKeeper(client, lease(), stop, clock=lambda: now[0]), stop  # type: ignore[arg-type]


def test_a_renewed_lease_extends_the_known_expiry() -> None:
    renewed = T0 + timedelta(minutes=2)
    lease_keeper, stop = keeper(FakeClient(heartbeats=[(HeartbeatStatus.RENEWED, renewed)]), [T0])

    lease_keeper.beat()

    assert lease_keeper.expires_at == renewed
    assert lease_keeper.reason is None
    assert not stop.is_set()


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (HeartbeatStatus.CANCELLED, StopReason.CANCELLED),
        (HeartbeatStatus.DEADLINE_EXCEEDED, StopReason.DEADLINE_EXCEEDED),
        (HeartbeatStatus.LEASE_LOST, StopReason.LEASE_LOST),
    ],
)
def test_the_executor_is_stopped_when_the_lease_must_not_be_used(
    status: HeartbeatStatus, reason: StopReason
) -> None:
    lease_keeper, stop = keeper(FakeClient(heartbeats=[(status, None)]), [T0])

    lease_keeper.beat()

    assert stop.is_set()
    assert lease_keeper.reason is reason


def test_a_database_outage_is_tolerated_while_the_lease_is_certainly_valid() -> None:
    now = [T0 + timedelta(seconds=10)]
    lease_keeper, stop = keeper(FakeClient(heartbeats=[LeaseStoreError("down")] * 2), now)

    lease_keeper.beat()
    assert not stop.is_set()

    # Half an interval (7.5 s) before the 60 s lease expires, execution stops.
    now[0] = T0 + timedelta(seconds=53)
    lease_keeper.beat()
    assert stop.is_set()
    assert lease_keeper.reason is StopReason.LEASE_UNCERTAIN


# --- ExecutionLoop -------------------------------------------------------------------


def test_a_completed_job_is_reported_once() -> None:
    client = FakeClient()

    outcome = loop(client, ScriptedExecutor(ExecutionResult.completed())).run_one(lease())

    assert outcome is RunOutcome.REPORTED
    assert client.reported == [(JobOutcome.COMPLETED, None)]


def test_a_cancelled_job_is_stopped_and_never_reported() -> None:
    client = FakeClient()
    heartbeats = FakeClient(heartbeats=[(HeartbeatStatus.CANCELLED, None)])
    executor = ScriptedExecutor(ExecutionResult.completed(), wait=10.0)
    fast = lease(lease_seconds=1)  # heartbeat every 0.25 s

    outcome = loop(client, executor, heartbeats).run_one(fast)

    assert outcome is RunOutcome.ABANDONED
    assert executor.stopped
    assert client.reported == []


def test_reports_are_retried_through_a_database_outage() -> None:
    client = FakeClient(reports=[LeaseStoreError("down"), LeaseStoreError("down")])

    outcome = loop(client, ScriptedExecutor(ExecutionResult.completed())).run_one(lease())

    assert outcome is RunOutcome.REPORTED
    assert len(client.reported) == 3


def test_an_undeliverable_report_is_left_to_lease_expiry() -> None:
    client = FakeClient(reports=[LeaseStoreError("down")] * 10)

    outcome = loop(client, ScriptedExecutor(ExecutionResult.completed())).run_one(lease())

    assert outcome is RunOutcome.UNREPORTED
    assert len(client.reported) == 5


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (ReportOutcome.DUPLICATE, RunOutcome.REPORTED),
        (ReportOutcome.REJECTED_STALE_EPOCH, RunOutcome.REJECTED),
        (ReportOutcome.REJECTED_JOB_NOT_RUNNING, RunOutcome.REJECTED),
        (ReportOutcome.CONFLICT, RunOutcome.REJECTED),
    ],
)
def test_report_answers_are_interpreted_without_retrying(
    answer: ReportOutcome, expected: RunOutcome
) -> None:
    client = FakeClient(reports=[answer])

    outcome = loop(client, ScriptedExecutor(ExecutionResult.completed())).run_one(lease())

    assert outcome is expected
    assert len(client.reported) == 1


def test_an_executor_crash_is_reported_as_a_retryable_sandbox_error() -> None:
    client = FakeClient()

    loop(client, ScriptedExecutor(RuntimeError("boom"))).run_one(lease())

    assert client.reported == [(JobOutcome.FAILED, FailureReason.SANDBOX_ERROR)]


def test_shutdown_interrupts_the_executor_and_releases_the_job_for_retry() -> None:
    client = FakeClient()
    executor = ScriptedExecutor(ExecutionResult.failed(FailureReason.SCANNER_ERROR), wait=10.0)
    execution = loop(client, executor)
    threading.Timer(0.05, execution.request_shutdown).start()

    outcome = execution.run_one(lease())

    assert outcome is RunOutcome.REPORTED
    assert executor.stopped
    assert client.reported == [(JobOutcome.FAILED, FailureReason.WORKER_SHUTDOWN)]


def test_run_stops_after_max_jobs_and_survives_claim_failures() -> None:
    client = FakeClient(claims=[LeaseStoreError("down"), lease(), None, lease(), lease()])

    summary = loop(client, ScriptedExecutor(ExecutionResult.completed())).run(max_jobs=2)

    assert summary.claimed == 2
    assert summary.reported == 2


def test_run_stops_when_idle() -> None:
    summary = loop(FakeClient(), ScriptedExecutor(ExecutionResult.completed())).run(idle_timeout=0)

    assert summary.claimed == 0


# --- FixtureExecutor -----------------------------------------------------------------


def test_the_fixture_completes_without_touching_any_repository() -> None:
    claimed = lease()

    result = FixtureExecutor(0).execute(claimed, threading.Event())

    assert result.outcome is JobOutcome.COMPLETED
    (artifact,) = result.artifacts
    assert artifact.name == "fixture-result.json"
    evidence = json.loads(artifact.content)
    assert evidence["fixture"] == "harmless"
    assert evidence["repository_content_read"] is False
    assert evidence["job_id"] == str(claimed.job_id)
    assert TOKEN not in artifact.content.decode()


def test_the_fixture_refuses_other_scanner_types() -> None:
    result = FixtureExecutor(0).execute(lease(scanner_type="SEMGREP"), threading.Event())

    assert result == ExecutionResult.failed(FailureReason.UNSUPPORTED_SCANNER)


def test_the_fixture_stops_promptly() -> None:
    stop = threading.Event()
    stop.set()

    result = FixtureExecutor(600).execute(lease(), stop)

    assert result.outcome is JobOutcome.FAILED


# --- JobLeaseClient ------------------------------------------------------------------


class FakeConnection:
    def __init__(self, rows: list[Any] | Exception) -> None:
        self.rows = rows
        self.closed = False
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    def transaction(self) -> Any:
        import contextlib

        return contextlib.nullcontext()

    def execute(self, sql: str, parameters: tuple[Any, ...]) -> Any:
        self.executed.append((sql, parameters))
        if isinstance(self.rows, Exception):
            raise self.rows
        rows = self.rows

        class Cursor:
            def fetchall(self) -> list[Any]:
                return rows

        return Cursor()

    def close(self) -> None:
        self.closed = True


SETTINGS = DatabaseSettings(host="db", port=5432, dbname="sentinelpipe", user="w", password="pw")


def claim_row(token: str = TOKEN) -> tuple[Any, ...]:
    return (
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        "a" * 40,
        "main",
        "GITHUB",
        "acme",
        "repo",
        "FIXTURE",
        1,
        3,
        1,
        token,
        T0,
        60,
        T0 + timedelta(minutes=15),
    )


def client_with(*connections: FakeConnection) -> JobLeaseClient:
    pending = list(connections)
    return JobLeaseClient(SETTINGS, "test", connect=lambda **_: pending.pop(0))


def test_a_claim_returns_the_databases_context() -> None:
    connection = FakeConnection([claim_row()])

    claimed = client_with(connection).claim(["FIXTURE", "FIXTURE"])

    assert claimed is not None
    assert claimed.token == TOKEN
    assert claimed.repository == Repository("GITHUB", "acme", "repo")
    assert connection.executed[0][1] == (["FIXTURE"], None)


def test_no_claimable_job_is_none() -> None:
    assert client_with(FakeConnection([])).claim(["FIXTURE"]) is None


def test_a_malformed_claim_response_fails_closed() -> None:
    with pytest.raises(LeaseStoreError):
        client_with(FakeConnection([claim_row(token="not-a-token")])).claim(["FIXTURE"])


def test_database_errors_are_transient_and_the_connection_is_replaced() -> None:
    broken = FakeConnection(psycopg.OperationalError("connection to host db failed for user w"))
    healthy = FakeConnection([(ReportOutcome.DUPLICATE.value,)])
    client = client_with(broken, healthy)

    with pytest.raises(LeaseStoreError) as raised:
        client.submit_result(lease(), b"{}")
    # The driver message (host and user names) is not propagated.
    assert "db" not in str(raised.value)
    assert broken.closed
    assert client.submit_result(lease(), b"{}") is ReportOutcome.DUPLICATE


def test_an_unknown_answer_fails_closed() -> None:
    with pytest.raises(LeaseStoreError):
        client_with(FakeConnection([("PASS",)])).submit_result(lease(), b"{}")
    with pytest.raises(LeaseStoreError):
        client_with(FakeConnection([("SOMETHING", None)])).heartbeat(lease())


def test_inconsistent_results_are_refused_locally() -> None:
    with pytest.raises(results.InvalidResultError):
        results.build(lease(), JobOutcome.COMPLETED, FailureReason.SCANNER_ERROR, T0, T0)
    with pytest.raises(results.InvalidResultError):
        results.build(lease(), JobOutcome.FAILED, None, T0, T0)
    with pytest.raises(ValueError, match="scanner type"):
        client_with().claim([])


# --- Settings and CLI ----------------------------------------------------------------

DB_ENV = {"SENTINEL_WORKER_DB_USERNAME": "w", "SENTINEL_WORKER_DB_PASSWORD": "pw"}


def test_execution_requires_an_executable_scanner() -> None:
    with pytest.raises(ConfigurationError, match="no executable scanner"):
        ExecutionSettings.from_env(Environment.DEVELOPMENT, DB_ENV)


def test_the_fixture_is_refused_in_production() -> None:
    env = DB_ENV | {"SENTINEL_WORKER_FIXTURE_ENABLED": "true"}

    with pytest.raises(ConfigurationError, match="not permitted in production"):
        ExecutionSettings.from_env(Environment.PRODUCTION, env)


def test_execution_settings_are_bounded() -> None:
    env = DB_ENV | {"SENTINEL_WORKER_FIXTURE_ENABLED": "true"}

    settings = ExecutionSettings.from_env(Environment.CI, env)
    assert settings.poll_interval_seconds == 5.0
    assert settings.fixture_seconds == 2.0
    for name, value in [
        ("SENTINEL_WORKER_EXECUTION_POLL_SECONDS", "0"),
        ("SENTINEL_WORKER_FIXTURE_SECONDS", "601"),
        ("SENTINEL_WORKER_FIXTURE_SECONDS", "x"),
        ("SENTINEL_WORKER_FIXTURE_ENABLED", "yes"),
    ]:
        with pytest.raises(ConfigurationError):
            ExecutionSettings.from_env(Environment.CI, env | {name: value})


def test_the_execute_command_fails_fast_on_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SENTINEL_WORKER_FIXTURE_ENABLED", raising=False)
    monkeypatch.setenv("SENTINEL_WORKER_DB_PASSWORD", "super-secret-value")

    assert cli.main(["execute", "--max-jobs", "1"]) == cli.EXIT_CONFIGURATION
    assert "super-secret-value" not in capsys.readouterr().err

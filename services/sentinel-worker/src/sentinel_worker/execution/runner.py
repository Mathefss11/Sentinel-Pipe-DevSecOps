"""Execution loop: claim a job, keep its lease alive, execute it, report the outcome.

Guarantees, together with the database protocol (ADR-0007):

* **One holder per job.** Claims are atomic; a lease belongs to one worker login and one
  token. Stale holders are fenced by the epoch.
* **Heartbeats.** A separate thread with its own connection renews the lease every
  quarter of its duration (15 s by default). If the job is cancelled, the scan passes its
  deadline or the lease is lost, the executor is told to stop and nothing is reported.
* **Database outages.** Failed heartbeats are retried. If the lease cannot be renewed
  before it would expire, the executor is stopped: the job will be reclaimed by the
  supervisor and retried, so continuing would only duplicate work.
* **Crashes.** A crashed worker stops heartbeating; the supervisor reclaims the job when
  the lease expires (within 60 s by default) and retries it while attempts remain.
* **Evidence** produced by the executor is uploaded under the lease first. The database
  computes each digest; evidence whose stored digest differs from the produced bytes is
  never referenced. If evidence cannot be stored, the job is reported FAILED with the
  retryable EVIDENCE_UNAVAILABLE.
* **Results** are submitted as one canonical job-result.v1 document, retried a bounded
  number of times while the lease is valid. The same bytes are resubmitted on every
  retry, so a retry after an ambiguous commit is a DUPLICATE. If every attempt fails, the
  lease expires and the job is retried.
* **Shutdown** stops the executor and reports WORKER_SHUTDOWN, which the control plane
  retries on another worker.

Nothing here decides security outcomes: COMPLETED only means the scanner ran.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from sentinel_worker.execution import results
from sentinel_worker.execution.evidence import (
    Artifact,
    DatabaseEvidenceStore,
    EvidenceError,
    EvidenceRef,
    EvidenceStore,
)
from sentinel_worker.execution.leases import (
    FailureReason,
    HeartbeatStatus,
    JobLease,
    JobLeaseClient,
    JobOutcome,
    LeaseStoreError,
    ReportOutcome,
)
from sentinel_worker.metrics import ExecutionMetrics

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _log(level: int, event: str, **fields: Any) -> None:
    logger.log(level, json.dumps({"event": event, **fields}, sort_keys=True, default=str))


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    outcome: JobOutcome
    failure_reason: FailureReason | None = None
    artifacts: tuple[Artifact, ...] = ()
    """Evidence to upload and reference in the result (content never logged)."""

    @classmethod
    def completed(cls, artifacts: tuple[Artifact, ...] = ()) -> ExecutionResult:
        return cls(JobOutcome.COMPLETED, None, artifacts)

    @classmethod
    def failed(cls, reason: FailureReason) -> ExecutionResult:
        return cls(JobOutcome.FAILED, reason)


class JobExecutor(Protocol):
    """Runs one claimed job. Must return promptly once ``stop`` is set."""

    @property
    def scanner_types(self) -> frozenset[str]: ...  # pragma: no cover

    def execute(
        self, lease: JobLease, stop: threading.Event
    ) -> ExecutionResult: ...  # pragma: no cover


class StopReason(StrEnum):
    CANCELLED = "CANCELLED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    LEASE_LOST = "LEASE_LOST"
    LEASE_UNCERTAIN = "LEASE_UNCERTAIN"
    """The database stayed unreachable until the lease was about to expire."""


_STOP_REASONS = {
    HeartbeatStatus.CANCELLED: StopReason.CANCELLED,
    HeartbeatStatus.DEADLINE_EXCEEDED: StopReason.DEADLINE_EXCEEDED,
    HeartbeatStatus.LEASE_LOST: StopReason.LEASE_LOST,
}


class LeaseKeeper:
    """Renews one lease from a background thread and stops the executor when the lease
    must no longer be used. :meth:`beat` is the unit of work (also used by tests)."""

    def __init__(
        self,
        client: JobLeaseClient,
        lease: JobLease,
        stop: threading.Event,
        clock: Callable[[], datetime] = _utc_now,
        metrics: ExecutionMetrics | None = None,
    ) -> None:
        self._client = client
        self._metrics = metrics
        self._lease = lease
        self._stop = stop
        self._clock = clock
        self._finished = threading.Event()
        self._expires_at = lease.expires_at
        self._reason: StopReason | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def reason(self) -> StopReason | None:
        """Why the lease must no longer be used, or ``None`` while it is valid."""
        with self._lock:
            return self._reason

    @property
    def expires_at(self) -> datetime:
        with self._lock:
            return self._expires_at

    def _lose(self, reason: StopReason) -> None:
        with self._lock:
            if self._reason is None:
                self._reason = reason
        self._stop.set()
        _log(
            logging.WARNING,
            "execution.lease_stopped",
            reason=reason.value,
            **self._lease.log_fields(),
        )

    def beat(self) -> None:
        try:
            status, expires_at = self._client.heartbeat(self._lease)
        except LeaseStoreError as exc:
            if self._metrics is not None:
                self._metrics.heartbeat("error")
            # Keep executing while the lease is certainly valid; stop half an interval
            # before it would expire, because the job will then be reclaimed.
            margin = self._lease.heartbeat_interval / 2
            if self._clock() >= self.expires_at - margin:
                self._lose(StopReason.LEASE_UNCERTAIN)
            else:
                _log(
                    logging.WARNING,
                    "execution.heartbeat_failed",
                    error=str(exc),
                    **self._lease.log_fields(),
                )
            return
        if self._metrics is not None:
            self._metrics.heartbeat(status.value)
        if status is HeartbeatStatus.RENEWED and expires_at is not None:
            with self._lock:
                self._expires_at = expires_at
            return
        self._lose(_STOP_REASONS.get(status, StopReason.LEASE_LOST))

    def _run(self) -> None:
        interval = self._lease.heartbeat_interval.total_seconds()
        while not self._finished.wait(interval):
            self.beat()
            if self.reason is not None:
                return

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="sentinel-lease-keeper", daemon=True)
        self._thread.start()

    def finish(self) -> None:
        self._finished.set()
        if self._thread is not None:
            self._thread.join(timeout=30)


class RunOutcome(StrEnum):
    REPORTED = "reported"
    """The control plane holds the report (ACCEPTED or DUPLICATE)."""

    ABANDONED = "abandoned"
    """Cancelled, past the deadline or lease lost: the work was discarded unreported."""

    REJECTED = "rejected"
    """The control plane refused the report (lease lost meanwhile, or a conflict)."""

    UNREPORTED = "unreported"
    """The report could not be delivered; the lease will expire and the job be retried."""


@dataclass
class RunSummary:
    claimed: int = 0
    reported: int = 0
    abandoned: int = 0
    rejected: int = 0
    unreported: int = 0

    def count(self, outcome: RunOutcome) -> None:
        setattr(self, outcome.value, getattr(self, outcome.value) + 1)

    def to_dict(self) -> dict[str, int]:
        return {
            "claimed": self.claimed,
            "reported": self.reported,
            "abandoned": self.abandoned,
            "rejected": self.rejected,
            "unreported": self.unreported,
        }


class ExecutionLoop:
    def __init__(
        self,
        client: JobLeaseClient,
        heartbeat_client: JobLeaseClient,
        executor: JobExecutor,
        poll_interval: float = 5.0,
        report_attempts: int = 5,
        report_backoff: float = 1.0,
        clock: Callable[[], datetime] = _utc_now,
        evidence_store: EvidenceStore | None = None,
        metrics: ExecutionMetrics | None = None,
    ) -> None:
        if not executor.scanner_types:
            raise ValueError("the executor supports no scanner type")
        self._client = client
        self._evidence = (
            evidence_store if evidence_store is not None else DatabaseEvidenceStore(client)
        )
        self._metrics = metrics if metrics is not None else ExecutionMetrics()
        self._heartbeat_client = heartbeat_client
        self._executor = executor
        self._poll_interval = poll_interval
        self._report_attempts = report_attempts
        self._report_backoff = report_backoff
        self._clock = clock
        self._shutdown = threading.Event()
        self._current_stop: threading.Event | None = None

    def request_shutdown(self) -> None:
        """Stops claiming, stops the running executor and reports WORKER_SHUTDOWN."""
        self._shutdown.set()
        current = self._current_stop
        if current is not None:
            current.set()

    def run(self, max_jobs: int | None = None, idle_timeout: float | None = None) -> RunSummary:
        summary = RunSummary()
        idle_since = self._clock()
        while not self._shutdown.is_set():
            if max_jobs is not None and summary.claimed >= max_jobs:
                break
            try:
                lease = self._client.claim(self._executor.scanner_types)
            except LeaseStoreError as exc:
                _log(logging.WARNING, "execution.claim_failed", error=str(exc))
                self._metrics.claim("error")
                lease = None
            else:
                self._metrics.claim("claimed" if lease is not None else "empty")
            if lease is None:
                if (
                    idle_timeout is not None
                    and (self._clock() - idle_since).total_seconds() >= idle_timeout
                ):
                    break
                self._shutdown.wait(self._poll_interval)
                continue
            summary.claimed += 1
            outcome = self.run_one(lease)
            summary.count(outcome)
            self._metrics.run(outcome.value)
            idle_since = self._clock()
        _log(logging.INFO, "execution.stopped", **summary.to_dict())
        return summary

    def run_one(self, lease: JobLease) -> RunOutcome:
        _log(logging.INFO, "execution.claimed", **lease.log_fields())
        stop = threading.Event()
        self._current_stop = stop
        if self._shutdown.is_set():
            stop.set()
        keeper = LeaseKeeper(self._heartbeat_client, lease, stop, self._clock, self._metrics)
        keeper.start()
        started_at = self._clock()
        started = time.monotonic()
        references: tuple[EvidenceRef, ...] = ()
        try:
            try:
                result = self._executor.execute(lease, stop)
            except Exception as exc:  # an executor failure must never crash the worker
                _log(
                    logging.ERROR,
                    "execution.executor_error",
                    error_type=type(exc).__name__,
                    **lease.log_fields(),
                )
                result = ExecutionResult.failed(FailureReason.SANDBOX_ERROR)
            finally:
                self._metrics.executed(lease.scanner_type, time.monotonic() - started)
            finished_at = self._clock()
            if keeper.reason is None:
                # Evidence is uploaded while the lease keeper still renews the lease.
                references, result = self._upload(lease, result, keeper)
        finally:
            keeper.finish()
            self._current_stop = None

        if keeper.reason is not None:
            _log(
                logging.WARNING,
                "execution.abandoned",
                reason=keeper.reason.value,
                **lease.log_fields(),
            )
            return RunOutcome.ABANDONED
        if self._shutdown.is_set() and result.outcome is not JobOutcome.COMPLETED:
            result = ExecutionResult.failed(FailureReason.WORKER_SHUTDOWN)
            references = ()
        try:
            document = results.build(
                lease, result.outcome, result.failure_reason, started_at, finished_at, references
            )
        except results.InvalidResultError:
            # A bug in an executor's output (e.g. duplicate artifact names): report a
            # retryable failure without evidence rather than an invalid result.
            _log(logging.ERROR, "execution.invalid_result", **lease.log_fields())
            result = ExecutionResult.failed(FailureReason.SANDBOX_ERROR)
            document = results.build(
                lease, result.outcome, result.failure_reason, started_at, finished_at
            )
        return self._submit(lease, result, document, keeper.expires_at)

    def _upload(
        self, lease: JobLease, result: ExecutionResult, keeper: LeaseKeeper
    ) -> tuple[tuple[EvidenceRef, ...], ExecutionResult]:
        """Stores the result's evidence; on failure the result becomes a retryable
        EVIDENCE_UNAVAILABLE without references."""
        references: list[EvidenceRef] = []
        for artifact in result.artifacts:
            for attempt in range(1, self._report_attempts + 1):
                try:
                    references.append(self._evidence.put(lease, artifact))
                    self._metrics.upload("stored")
                    break
                except EvidenceError as exc:
                    self._metrics.upload("error" if exc.transient else "refused")
                    _log(
                        logging.WARNING,
                        "execution.evidence_failed",
                        artifact=artifact.name,
                        error=str(exc),
                        **lease.log_fields(),
                    )
                    if (
                        not exc.transient
                        or attempt == self._report_attempts
                        or keeper.reason is not None
                        or self._clock() >= keeper.expires_at
                    ):
                        return (), ExecutionResult.failed(FailureReason.EVIDENCE_UNAVAILABLE)
                    time.sleep(self._report_backoff * 2 ** (attempt - 1))
        return tuple(references), result

    def _submit(
        self, lease: JobLease, result: ExecutionResult, document: bytes, expires_at: datetime
    ) -> RunOutcome:
        for attempt in range(1, self._report_attempts + 1):
            try:
                outcome = self._client.submit_result(lease, document)
            except LeaseStoreError as exc:
                self._metrics.result("error")
                _log(
                    logging.WARNING,
                    "execution.report_failed",
                    report_attempt=attempt,
                    error=str(exc),
                    **lease.log_fields(),
                )
                if attempt == self._report_attempts or self._clock() >= expires_at:
                    break
                # Not interrupted by shutdown: delivering the report is the point of stopping.
                time.sleep(self._report_backoff * 2 ** (attempt - 1))
                continue
            self._metrics.result(outcome.value)
            fields = {
                "outcome": result.outcome.value,
                "failure_reason": result.failure_reason.value if result.failure_reason else None,
                "report": outcome.value,
                **lease.log_fields(),
            }
            if outcome.settled:
                _log(logging.INFO, "execution.reported", **fields)
                return RunOutcome.REPORTED
            level = logging.ERROR if outcome is ReportOutcome.CONFLICT else logging.WARNING
            _log(level, "execution.report_rejected", **fields)
            return RunOutcome.REJECTED
        _log(logging.ERROR, "execution.unreported", **lease.log_fields())
        return RunOutcome.UNREPORTED

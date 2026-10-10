"""Runs a scanner adapter in an isolated sandbox for one leased job (ADR-0009, ADR-0010).

Per attempt:

1. the repository snapshot is built from the job's authoritative repository (the lease),
   never from a message; input problems are reported without content;
2. the adapter's fixed command runs in a fresh sandbox, with the snapshot on stdin; the
   attempt's time limit is the policy timeout capped by the scan's hard deadline;
3. sandbox outcomes other than a normal exit (timeout, resource limits, cancellation,
   runtime failures) map exactly as for the FIXTURE (:func:`outcome_for`);
4. a normal exit is interpreted by the adapter (exit-code semantics, strict parsing,
   normalization, redaction) into evidence, or a sanitized failure.

Repository input errors map onto existing job-result.v1 reasons: input over the size
limits is ``RESOURCE_LIMIT_EXCEEDED`` (final); anything else ``SCANNER_ERROR`` (retried).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from sentinel_worker.execution.leases import FailureReason, JobLease
from sentinel_worker.execution.runner import ExecutionResult, JobExecutor
from sentinel_worker.execution.sandboxed import (
    DEADLINE_MARGIN_SECONDS,
    REAP_INTERVAL_SECONDS,
    outcome_for,
)
from sentinel_worker.repository.snapshot import InputError, InputErrorCode, RepositorySource
from sentinel_worker.sandbox.docker import DockerSandbox, SandboxError, SandboxStatus
from sentinel_worker.scanners.adapter import ScannerAdapter, ScannerError

logger = logging.getLogger(__name__)


def _log(level: int, event: str, **fields: object) -> None:
    logger.log(level, json.dumps({"event": event, **fields}, sort_keys=True))


class ScannerExecutor:
    def __init__(
        self,
        sandbox: DockerSandbox,
        adapter: ScannerAdapter,
        source: RepositorySource,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if sandbox.policy.image != adapter.identity.image:
            raise ValueError("the sandbox policy does not use the adapter's image")
        self._sandbox = sandbox
        self._adapter = adapter
        self._source = source
        self._clock = clock
        self._last_reap = float("-inf")
        if sandbox.policy.runtime is None:
            # ADR-0009 trust policy: runc shares the host kernel. Acceptable for reviewed
            # scanners on synthetic or trusted content, not for hostile repositories.
            _log(
                logging.WARNING,
                "scanner.runc_boundary",
                scanner=adapter.identity.name,
                note="default runc runtime; not an isolation boundary for hostile content",
            )

    @property
    def scanner_types(self) -> frozenset[str]:
        return frozenset({self._adapter.scanner_type})

    def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
        scanner = self._adapter.identity.name
        if lease.scanner_type != self._adapter.scanner_type:
            return ExecutionResult.failed(FailureReason.UNSUPPORTED_SCANNER)
        self._reap_expired()
        remaining = (lease.deadline_at - self._clock()).total_seconds() - DEADLINE_MARGIN_SECONDS
        if remaining <= 0:
            return ExecutionResult.failed(FailureReason.EXECUTION_TIMEOUT)
        if stop.is_set():
            return ExecutionResult.failed(FailureReason.WORKER_SHUTDOWN)
        try:
            snapshot = self._source.snapshot(lease)
            stdin = self._adapter.stdin(snapshot)
        except InputError as exc:
            _log(logging.WARNING, "scanner.input_rejected", scanner=scanner, code=exc.code.value)
            reason = (
                FailureReason.RESOURCE_LIMIT_EXCEEDED
                if exc.code is InputErrorCode.INPUT_TOO_LARGE
                else FailureReason.SCANNER_ERROR
            )
            return ExecutionResult.failed(reason)
        if len(stdin) > self._sandbox.policy.max_stdin_bytes:
            _log(logging.WARNING, "scanner.input_rejected", scanner=scanner, code="INPUT_TOO_LARGE")
            return ExecutionResult.failed(FailureReason.RESOURCE_LIMIT_EXCEEDED)
        try:
            run = self._sandbox.run(
                self._adapter.command(snapshot),
                stop,
                timeout_seconds=min(self._sandbox.policy.timeout_seconds, remaining),
                job_id=str(lease.job_id),
                stdin=stdin,
            )
        except SandboxError:
            return ExecutionResult.failed(FailureReason.SANDBOX_ERROR)
        if run.status is not SandboxStatus.EXITED:
            return outcome_for(run)
        try:
            artifacts = self._adapter.interpret(run, snapshot, lease)
        except ScannerError as exc:
            _log(
                logging.WARNING,
                "scanner.failed",
                scanner=scanner,
                code=exc.code,
                reason=exc.reason.value,
                exit_code=run.exit_code,
            )
            return ExecutionResult.failed(exc.reason)
        _log(
            logging.INFO,
            "scanner.completed",
            scanner=scanner,
            exit_code=run.exit_code,
            files_scanned=len(snapshot.files),
            coverage_complete=snapshot.complete,
        )
        return ExecutionResult.completed(artifacts)

    def _reap_expired(self) -> None:
        now = time.monotonic()
        if now - self._last_reap >= REAP_INTERVAL_SECONDS:
            self._last_reap = now
            self._sandbox.reap_expired()


class DispatchingExecutor:
    """Routes each job to the executor for its scanner type (one worker, several
    scanners)."""

    def __init__(self, executors: Sequence[JobExecutor]) -> None:
        routes: dict[str, JobExecutor] = {}
        for executor in executors:
            for scanner_type in executor.scanner_types:
                if scanner_type in routes:
                    raise ValueError("two executors for one scanner type")
                routes[scanner_type] = executor
        if not routes:
            raise ValueError("no executor")
        self._routes = routes

    @property
    def scanner_types(self) -> frozenset[str]:
        return frozenset(self._routes)

    def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
        executor = self._routes.get(lease.scanner_type)
        if executor is None:
            return ExecutionResult.failed(FailureReason.UNSUPPORTED_SCANNER)
        return executor.execute(lease, stop)

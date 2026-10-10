"""The FIXTURE scanner executed in an isolated, ephemeral sandbox (ADR-0009).

Sandbox outcomes map onto the existing job-result.v1 failure reasons, unchanged:

=====================================  ===================================
sandbox outcome                        job result
=====================================  ===================================
exit 0 with valid sandbox-output.v1    COMPLETED with the artifacts
exit 0 with invalid output             FAILED SCANNER_ERROR (retried)
exit 1-127                             FAILED SCANNER_ERROR (retried)
exit >= 128 (killed by a signal)       FAILED SANDBOX_ERROR (retried)
runtime CLI lost, container running    FAILED SANDBOX_ERROR (retried)
time limit                             FAILED EXECUTION_TIMEOUT (final)
memory, PID or output limit            FAILED RESOURCE_LIMIT_EXCEEDED (final)
runtime could not start the sandbox    FAILED SANDBOX_ERROR (retried)
cancelled / lease lost / shutdown      not reported (lease lost) or WORKER_SHUTDOWN
=====================================  ===================================

The per-attempt time limit is the policy's timeout, capped by the scan's hard deadline.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

from sentinel_worker.execution.leases import FailureReason, JobLease
from sentinel_worker.execution.runner import ExecutionResult
from sentinel_worker.sandbox import fixture
from sentinel_worker.sandbox.docker import DockerSandbox, SandboxError, SandboxRun, SandboxStatus
from sentinel_worker.sandbox.protocol import InvalidOutputError, parse

logger = logging.getLogger(__name__)

FIXTURE = "FIXTURE"
#: Stop this long before the scan's hard deadline, so the result can still be reported.
DEADLINE_MARGIN_SECONDS = 5.0
REAP_INTERVAL_SECONDS = 60.0

_RESOURCE_LIMITS = {
    SandboxStatus.OOM_KILLED,
    SandboxStatus.PIDS_EXHAUSTED,
    SandboxStatus.OUTPUT_LIMIT,
}


def outcome_for(run: SandboxRun) -> ExecutionResult:
    if run.status is SandboxStatus.EXITED and run.exit_code == 0:
        try:
            return ExecutionResult.completed(parse(run.stdout))
        except InvalidOutputError as exc:
            logger.warning(json.dumps({"event": "sandbox.invalid_output", "code": exc.code}))
            return ExecutionResult.failed(FailureReason.SCANNER_ERROR)
    if run.status is SandboxStatus.EXITED:
        if run.exit_code is not None and 0 < run.exit_code < 128:
            return ExecutionResult.failed(FailureReason.SCANNER_ERROR)
        return ExecutionResult.failed(FailureReason.SANDBOX_ERROR)
    if run.status is SandboxStatus.TIMED_OUT:
        return ExecutionResult.failed(FailureReason.EXECUTION_TIMEOUT)
    if run.status in _RESOURCE_LIMITS:
        return ExecutionResult.failed(FailureReason.RESOURCE_LIMIT_EXCEEDED)
    if run.status is SandboxStatus.CANCELLED:
        # The loop discards this when the lease was lost; on shutdown it is reported.
        return ExecutionResult.failed(FailureReason.WORKER_SHUTDOWN)
    return ExecutionResult.failed(FailureReason.SANDBOX_ERROR)


class SandboxedFixtureExecutor:
    def __init__(
        self,
        sandbox: DockerSandbox,
        mode: fixture.FixtureMode = fixture.FixtureMode.SUCCESS,
        duration_seconds: float = 2.0,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._sandbox = sandbox
        self._mode = mode
        self._duration = duration_seconds
        self._clock = clock
        self._last_reap = float("-inf")

    @property
    def scanner_types(self) -> frozenset[str]:
        return frozenset({FIXTURE})

    def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
        if lease.scanner_type != FIXTURE:
            return ExecutionResult.failed(FailureReason.UNSUPPORTED_SCANNER)
        self._reap_expired()
        remaining = (lease.deadline_at - self._clock()).total_seconds() - DEADLINE_MARGIN_SECONDS
        if remaining <= 0:
            return ExecutionResult.failed(FailureReason.EXECUTION_TIMEOUT)
        try:
            run = self._sandbox.run(
                fixture.command(self._mode, lease, self._duration),
                stop,
                timeout_seconds=min(self._sandbox.policy.timeout_seconds, remaining),
                job_id=str(lease.job_id),
            )
        except SandboxError:
            return ExecutionResult.failed(FailureReason.SANDBOX_ERROR)
        return outcome_for(run)

    def _reap_expired(self) -> None:
        now = time.monotonic()
        if now - self._last_reap >= REAP_INTERVAL_SECONDS:
            self._last_reap = now
            self._sandbox.reap_expired()

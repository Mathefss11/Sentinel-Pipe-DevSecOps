"""The harmless FIXTURE executor.

It exercises the execution lifecycle (claim, heartbeats, cancellation, evidence upload,
result submission) without running any scanner and without reading, fetching or
executing repository content: it waits for a configured time, interruptibly, and
produces one small JSON evidence artifact describing the fixture run itself. It is enabled only by
``SENTINEL_WORKER_FIXTURE_ENABLED=true`` and refused in production. Isolated execution
of untrusted content (sandbox limits, filesystem, network) is a later slice.
"""

from __future__ import annotations

import threading

from sentinel_worker.execution.evidence import Artifact
from sentinel_worker.execution.leases import FailureReason, JobLease
from sentinel_worker.execution.results import canonical_json
from sentinel_worker.execution.runner import ExecutionResult

FIXTURE = "FIXTURE"
EVIDENCE_NAME = "fixture-result.json"


class FixtureExecutor:
    def __init__(self, duration_seconds: float = 2.0) -> None:
        if duration_seconds < 0:
            raise ValueError("duration_seconds must not be negative")
        self._duration = duration_seconds

    @property
    def scanner_types(self) -> frozenset[str]:
        return frozenset({FIXTURE})

    def execute(self, lease: JobLease, stop: threading.Event) -> ExecutionResult:
        if lease.scanner_type != FIXTURE:
            return ExecutionResult.failed(FailureReason.UNSUPPORTED_SCANNER)
        if stop.wait(self._duration):
            # Interrupted (cancellation, lost lease or shutdown): the loop decides whether
            # anything is reported.
            return ExecutionResult.failed(FailureReason.WORKER_SHUTDOWN)
        # Evidence describing the fixture run itself; it contains no repository content.
        evidence = {
            "fixture": "harmless",
            "job_id": str(lease.job_id),
            "scan_id": str(lease.scan_id),
            "attempt": lease.attempt,
            "lease_epoch": lease.epoch,
            "repository_content_read": False,
        }
        return ExecutionResult.completed(
            (Artifact(EVIDENCE_NAME, "application/json", canonical_json(evidence)),)
        )

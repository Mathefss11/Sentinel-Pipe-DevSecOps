"""The scanner adapter contract (ADR-0010).

An adapter describes one reviewed scanner and owns everything scanner-specific:

* **identity**: name, version and the digest-pinned image (:class:`~.findings.Scanner`);
* **sandbox policy**: the image plus resource limits (:meth:`ScannerAdapter.policy`);
* **input**: how a repository snapshot is presented (:meth:`ScannerAdapter.stdin`);
* **command**: a fixed, allowlisted argument vector with validated arguments only;
* **exit-code semantics, output parsing, normalization and evidence**
  (:meth:`ScannerAdapter.interpret`), which turns one *exited* sandbox run into evidence
  artifacts or raises :class:`ScannerError` with a sanitized code and a failure reason.

Whatever the scanner prints is untrusted. A scanner that found problems has *succeeded*;
only an unusable run is a failure. Neither outcome is a security decision.
"""

from __future__ import annotations

from typing import Protocol

from sentinel_worker.execution.evidence import Artifact
from sentinel_worker.execution.leases import FailureReason, JobLease
from sentinel_worker.repository.snapshot import RepositorySnapshot
from sentinel_worker.sandbox.docker import SandboxRun
from sentinel_worker.sandbox.policy import SandboxPolicy
from sentinel_worker.scanners.findings import Scanner


class ScannerError(Exception):
    """The scanner run cannot be used. ``code`` is a sanitized, closed-set identifier;
    neither it nor the message ever contains scanner output or repository content."""

    def __init__(self, code: str, reason: FailureReason) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason


class ScannerAdapter(Protocol):
    @property
    def scanner_type(self) -> str: ...  # pragma: no cover

    @property
    def identity(self) -> Scanner: ...  # pragma: no cover

    def policy(
        self, timeout_seconds: float, cpus: float, runtime: str | None
    ) -> SandboxPolicy: ...  # pragma: no cover

    def stdin(self, snapshot: RepositorySnapshot) -> bytes: ...  # pragma: no cover

    def command(self, snapshot: RepositorySnapshot) -> list[str]: ...  # pragma: no cover

    def interpret(
        self, run: SandboxRun, snapshot: RepositorySnapshot, lease: JobLease
    ) -> tuple[Artifact, ...]: ...  # pragma: no cover

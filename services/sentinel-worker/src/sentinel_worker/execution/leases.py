"""Client for the PostgreSQL execution protocol (Flyway V007, ADR-0007).

The worker changes execution state only through three ``SECURITY DEFINER`` functions,
with its own database login:

* ``worker.claim_job`` claims a job and returns a **lease**: a random token (returned
  once; the database stores only its SHA-256), a fencing **epoch** that increases with
  every claim, an expiry, and the authoritative scan, project, organization, commit and
  repository. Workers use these values, never identifiers from queue messages;
* ``worker.heartbeat_job`` renews the lease, or reports that the job was cancelled, the
  scan passed its hard deadline, or the lease was lost;
* ``worker.put_evidence`` uploads evidence bytes under the lease; the database computes
  their SHA-256 (ADR-0008);
* ``worker.submit_result`` submits one canonical ``job-result.v1`` document. The database
  checks it against the authoritative job, scan, project, organization and commit, and
  every artifact reference against the digests it computed. Retry decisions belong to the
  control plane. Duplicate submissions are idempotent; stale, forged or contradictory
  ones change nothing.

The database authenticates every call by ``session_user`` (the lease owner), the token
and the epoch, so a stale or compromised worker cannot change a job it does not hold.
Lease tokens are secrets: they are excluded from ``repr`` and never logged.
"""

from __future__ import annotations

import contextlib
import re
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sentinel_worker.messaging.receipts import DatabaseSettings

_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class HeartbeatStatus(StrEnum):
    RENEWED = "RENEWED"
    """The lease was extended."""

    CANCELLED = "CANCELLED"
    """The job was cancelled: stop and discard all work."""

    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    """The scan passed its hard execution deadline: stop."""

    LEASE_LOST = "LEASE_LOST"
    """The lease expired or belongs to someone else now: stop; reports will be rejected."""


class ReportOutcome(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    CONFLICT = "CONFLICT"
    REJECTED_UNKNOWN_JOB = "REJECTED_UNKNOWN_JOB"
    REJECTED_SCAN_MISMATCH = "REJECTED_SCAN_MISMATCH"
    REJECTED_STALE_EPOCH = "REJECTED_STALE_EPOCH"
    REJECTED_UNKNOWN_EPOCH = "REJECTED_UNKNOWN_EPOCH"
    REJECTED_NOT_LEASE_OWNER = "REJECTED_NOT_LEASE_OWNER"
    REJECTED_TOKEN_MISMATCH = "REJECTED_TOKEN_MISMATCH"  # noqa: S105 - outcome name, not a secret
    REJECTED_JOB_NOT_RUNNING = "REJECTED_JOB_NOT_RUNNING"
    REJECTED_LEASE_EXPIRED = "REJECTED_LEASE_EXPIRED"
    REJECTED_DEADLINE_EXCEEDED = "REJECTED_DEADLINE_EXCEEDED"
    REJECTED_CONTEXT_MISMATCH = "REJECTED_CONTEXT_MISMATCH"
    REJECTED_MISSING_ARTIFACT = "REJECTED_MISSING_ARTIFACT"
    REJECTED_ARTIFACT_MISMATCH = "REJECTED_ARTIFACT_MISMATCH"
    REJECTED_UNSUPPORTED_SCHEMA_VERSION = "REJECTED_UNSUPPORTED_SCHEMA_VERSION"

    @property
    def settled(self) -> bool:
        """The control plane holds this lease's report (now or from an earlier call)."""
        return self in (ReportOutcome.ACCEPTED, ReportOutcome.DUPLICATE)


class JobOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    """The scanner ran and produced its output. Says nothing about findings."""

    FAILED = "FAILED"


class FailureReason(StrEnum):
    """Failure reasons a worker may report. Whether one is retried is decided by the
    control plane: SCANNER_ERROR, SANDBOX_ERROR, WORKER_SHUTDOWN and EVIDENCE_UNAVAILABLE
    are retried while attempts remain; the others are final."""

    SCANNER_ERROR = "SCANNER_ERROR"
    SANDBOX_ERROR = "SANDBOX_ERROR"
    WORKER_SHUTDOWN = "WORKER_SHUTDOWN"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    UNSUPPORTED_SCANNER = "UNSUPPORTED_SCANNER"


class LeaseStoreError(Exception):
    """The database could not be reached or answered unexpectedly. Transient: the outcome
    of the call is unknown; retrying is safe because every operation is idempotent or
    fenced."""


@dataclass(frozen=True, slots=True)
class Repository:
    provider: str
    owner: str
    name: str


@dataclass(frozen=True, slots=True)
class JobLease:
    """A claimed job with its authoritative context. Only the database's values are used."""

    job_id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    organization_id: uuid.UUID
    commit_sha: str
    branch: str
    repository: Repository
    scanner_type: str
    attempt: int
    max_attempts: int
    epoch: int
    token: str = field(repr=False)
    expires_at: datetime
    lease_duration_seconds: int
    deadline_at: datetime

    @property
    def heartbeat_interval(self) -> timedelta:
        """A quarter of the lease (15 s for the default 60 s lease): three heartbeats can
        fail before the lease expires."""
        return timedelta(seconds=self.lease_duration_seconds / 4)

    def log_fields(self) -> dict[str, Any]:
        """Identifiers safe to log (never the token)."""
        return {
            "job_id": str(self.job_id),
            "scan_id": str(self.scan_id),
            "organization_id": str(self.organization_id),
            "scanner_type": self.scanner_type,
            "attempt": self.attempt,
            "lease_epoch": self.epoch,
        }


def _lease(row: Any) -> JobLease:
    (
        job_id,
        scan_id,
        project_id,
        organization_id,
        commit_sha,
        branch,
        provider,
        owner,
        name,
        scanner_type,
        attempt,
        max_attempts,
        epoch,
        token,
        expires_at,
        lease_seconds,
        deadline_at,
    ) = row
    if not isinstance(token, str) or not _TOKEN.match(token):
        raise LeaseStoreError("unexpected claim response")
    return JobLease(
        job_id=_uuid(job_id),
        scan_id=_uuid(scan_id),
        project_id=_uuid(project_id),
        organization_id=_uuid(organization_id),
        commit_sha=str(commit_sha),
        branch=str(branch),
        repository=Repository(str(provider), str(owner), str(name)),
        scanner_type=str(scanner_type),
        attempt=int(attempt),
        max_attempts=int(max_attempts),
        epoch=int(epoch),
        token=token,
        expires_at=expires_at,
        lease_duration_seconds=int(lease_seconds),
        deadline_at=deadline_at,
    )


def _uuid(value: Any) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class JobLeaseClient:
    """One database connection for the execution protocol. Not thread-safe: the
    heartbeat thread uses its own client.

    Each call is one explicit transaction and returns only after ``COMMIT``. Any database
    error (including an ambiguous commit after a lost connection) raises
    :class:`LeaseStoreError`; the connection is discarded and re-opened on the next call.
    """

    def __init__(
        self,
        settings: DatabaseSettings,
        application_name: str,
        connect: Callable[..., Any] | None = None,
    ) -> None:
        self._settings = settings
        self._application_name = application_name
        self._connect = connect
        self._connection: Any = None

    def _open(self) -> Any:
        if self._connection is None or self._connection.closed:
            connect = self._connect
            if connect is None:
                import psycopg

                connect = psycopg.connect
            self._connection = connect(**self._settings.connection_kwargs(self._application_name))
        return self._connection

    def _discard(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            with contextlib.suppress(Exception):  # best effort on a broken connection
                connection.close()

    def _call(self, sql: str, parameters: tuple[Any, ...]) -> list[Any]:
        import psycopg

        try:
            connection = self._open()
            with connection.transaction():
                return list(connection.execute(sql, parameters).fetchall())
        except psycopg.Error as exc:
            self._discard()
            # Type only: driver messages can contain host or user names.
            raise LeaseStoreError(f"execution store unavailable: {type(exc).__name__}") from exc

    def claim(
        self, scanner_types: Iterable[str], scan_id: uuid.UUID | None = None
    ) -> JobLease | None:
        """Claims the oldest claimable job of these scanner types, or returns ``None``."""
        types = sorted(set(scanner_types))
        if not types:
            raise ValueError("at least one scanner type is required")
        rows = self._call(
            "SELECT job_id, scan_id, project_id, organization_id, commit_sha, branch,"
            " repository_provider, repository_owner, repository_name, scanner_type, attempt,"
            " max_attempts, lease_epoch, lease_token, lease_expires_at, lease_duration_seconds,"
            " deadline_at FROM worker.claim_job(%s::text[], %s::uuid)",
            (types, str(scan_id) if scan_id is not None else None),
        )
        if not rows:
            return None
        try:
            return _lease(rows[0])
        except (TypeError, ValueError) as exc:
            # Unexpected shape: fail closed. The lease expires and the job is reclaimed.
            raise LeaseStoreError("unexpected claim response") from exc

    def heartbeat(self, lease: JobLease) -> tuple[HeartbeatStatus, datetime | None]:
        rows = self._call(
            "SELECT status, lease_expires_at FROM worker.heartbeat_job(%s, %s, %s)",
            (lease.job_id, lease.epoch, lease.token),
        )
        try:
            status, expires_at = rows[0]
            return HeartbeatStatus(status), expires_at
        except (IndexError, TypeError, ValueError) as exc:
            raise LeaseStoreError("unexpected heartbeat response") from exc

    def put_evidence(
        self, lease: JobLease, name: str, media_type: str, content: bytes
    ) -> tuple[str, str | None, int | None]:
        """Uploads evidence; returns (status, database-computed sha256, size)."""
        rows = self._call(
            "SELECT status, sha256, size_bytes FROM worker.put_evidence(%s, %s, %s, %s, %s, %s)",
            (lease.job_id, lease.epoch, lease.token, name, media_type, content),
        )
        try:
            status, sha256, size = rows[0]
            return str(status), sha256, size
        except (IndexError, TypeError, ValueError) as exc:
            raise LeaseStoreError("unexpected evidence response") from exc

    def submit_result(self, lease: JobLease, result: bytes) -> ReportOutcome:
        """Submits canonical job-result.v1 bytes (see :mod:`sentinel_worker.execution.results`)."""
        rows = self._call(
            "SELECT worker.submit_result(%s, %s)", (lease.token, result.decode("ascii"))
        )
        try:
            return ReportOutcome(rows[0][0])
        except (IndexError, TypeError, ValueError) as exc:
            raise LeaseStoreError("unexpected result response") from exc

    def close(self) -> None:
        self._discard()

    def __enter__(self) -> JobLeaseClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

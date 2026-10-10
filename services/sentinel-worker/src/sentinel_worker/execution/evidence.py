"""Evidence produced by a job, and the storage it is uploaded to (ADR-0008).

Evidence is uploaded under the job's lease **before** the result is submitted. The
storage computes the SHA-256 of the bytes it received and returns it. The worker compares
it with its own computation and references only evidence whose digests agree. The control
plane then accepts a result only if every reference matches a digest the database computed
itself under the same lease and tenant.

Artifact names are restricted identifiers (``^[a-z0-9][a-z0-9._-]{0,63}$``, no ``..``),
never paths or URLs. Evidence content is never logged.

:class:`DatabaseEvidenceStore` stores evidence in PostgreSQL (development and CI; small
artifacts, at most 1 MiB each and 8 MiB per lease). An S3-compatible store can implement
the same :class:`EvidenceStore` protocol later. It must preserve the same guarantees:
the control plane, not the worker, establishes the digest of the stored bytes.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from sentinel_worker.execution.leases import JobLease, JobLeaseClient, LeaseStoreError

MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_ARTIFACTS = 16
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MEDIA_TYPES = frozenset({"application/json", "application/sarif+json", "text/plain"})
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class UploadStatus(StrEnum):
    STORED = "STORED"
    DUPLICATE = "DUPLICATE"
    CONFLICT = "CONFLICT"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class Artifact:
    """Evidence bytes produced by an executor. ``repr`` omits the content."""

    name: str
    media_type: str
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _NAME.match(self.name) or ".." in self.name:
            raise ValueError("artifact names must be restricted identifiers, not paths")
        if self.media_type not in MEDIA_TYPES:
            raise ValueError("unsupported artifact media type")
        if len(self.content) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifacts are limited to {MAX_ARTIFACT_BYTES} bytes")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A stored artifact as established by the storage (its digest and size)."""

    name: str
    media_type: str
    sha256: str
    size_bytes: int


class EvidenceError(Exception):
    """The evidence could not be stored or verified. The message never contains content."""

    def __init__(self, message: str, transient: bool) -> None:
        super().__init__(message)
        self.transient = transient


class EvidenceStore(Protocol):
    def put(self, lease: JobLease, artifact: Artifact) -> EvidenceRef:
        """Stores the artifact under the lease. Raises :class:`EvidenceError`."""
        ...  # pragma: no cover


class DatabaseEvidenceStore:
    """Evidence in PostgreSQL through ``worker.put_evidence`` (the worker's own login)."""

    def __init__(self, client: JobLeaseClient) -> None:
        self._client = client

    def put(self, lease: JobLease, artifact: Artifact) -> EvidenceRef:
        try:
            status, sha256, size = self._client.put_evidence(
                lease, artifact.name, artifact.media_type, artifact.content
            )
        except LeaseStoreError as exc:
            raise EvidenceError("evidence store unavailable", transient=True) from exc
        if status not in (UploadStatus.STORED.value, UploadStatus.DUPLICATE.value):
            # CONFLICT or REJECTED_<reason>: the code is sanitized, no content.
            raise EvidenceError(f"evidence refused: {status}", transient=False)
        if sha256 != artifact.sha256 or size != len(artifact.content):
            # The bytes stored are not the bytes produced: never reference them.
            raise EvidenceError(
                "stored evidence digest differs from the produced bytes", transient=False
            )
        return EvidenceRef(artifact.name, artifact.media_type, sha256, size)

"""``job-result.v1`` documents (packages/contracts/messages/v1/job-result.v1.schema.json).

Canonical serialization, shared with the control plane's expectations: UTF-8, ASCII only,
object keys sorted by code point, no insignificant whitespace, no duplicate keys,
integers only, artifacts sorted by name, at most :data:`MAX_RESULT_BYTES`. The database
identifies a result by the SHA-256 of these exact bytes. Building the same result twice
yields the same bytes, so a retried submission is recognized as a duplicate.

Identifiers and the commit come from the lease (the database's values), never from queue
messages. The lease token is not part of the document.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sentinel_worker.execution.evidence import MAX_ARTIFACTS, EvidenceRef
from sentinel_worker.execution.leases import FailureReason, JobLease, JobOutcome
from sentinel_worker.messaging import contracts

SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 16 * 1024


class InvalidResultError(ValueError):
    """The document would violate job-result.v1 (a bug: never submitted)."""


def timestamp(moment: datetime) -> str:
    """UTC, microsecond precision, ``Z`` suffix, as the contract requires."""
    return moment.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def build(
    lease: JobLease,
    outcome: JobOutcome,
    failure_reason: FailureReason | None,
    started_at: datetime,
    finished_at: datetime,
    artifacts: Iterable[EvidenceRef] = (),
) -> bytes:
    """The canonical job-result.v1 bytes for ``lease``, validated against the contract."""
    references = sorted(artifacts, key=lambda ref: ref.name)
    names = [ref.name for ref in references]
    if len(names) != len(set(names)) or len(names) > MAX_ARTIFACTS:
        raise InvalidResultError("artifact names must be unique and at most 16")
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "job_id": str(lease.job_id),
        "scan_id": str(lease.scan_id),
        "project_id": str(lease.project_id),
        "organization_id": str(lease.organization_id),
        "commit_sha": lease.commit_sha,
        "scanner_type": lease.scanner_type,
        "attempt": lease.attempt,
        "lease_epoch": lease.epoch,
        "outcome": outcome.value,
        "failure_reason": failure_reason.value if failure_reason is not None else None,
        "started_at": timestamp(started_at),
        "finished_at": timestamp(max(finished_at, started_at)),
        "artifacts": [
            {
                "name": ref.name,
                "media_type": ref.media_type,
                "sha256": ref.sha256,
                "size_bytes": ref.size_bytes,
            }
            for ref in references
        ],
    }
    validator = contracts.validator(contracts.JOB_RESULT_SCHEMA)
    if next(validator.iter_errors(document), None) is not None:
        raise InvalidResultError("result does not conform to job-result.v1")
    encoded = canonical_json(document)
    if len(encoded) > MAX_RESULT_BYTES:
        raise InvalidResultError(f"result exceeds {MAX_RESULT_BYTES} bytes")
    return encoded

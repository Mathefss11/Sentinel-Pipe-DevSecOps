"""Decides what happens to one delivered message.

Pure decision logic (no broker I/O) so every path is unit-testable:

* invalid messages (size, encoding, JSON, schema, AMQP properties) are dead-lettered
  with metadata; they are never acknowledged silently and never requeued forever;
* valid messages get a durable receipt, then an acknowledgment;
* a duplicate delivery of the same message is acknowledged without new effects;
* the same ``event_id`` with a different message (replay with altered tenant or
  commit, i.e. tampering) is dead-lettered and the original receipt is kept;
* a receipt-store failure is transient: the message is retried through the delayed
  retry queue, and dead-lettered once ``max_retries`` retries are exhausted.

Messages are untrusted input and never authorization credentials: nothing in a message
grants access to another organization's data. Error details never contain message
content.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sentinel_worker import __version__
from sentinel_worker.messaging import contracts
from sentinel_worker.messaging.receipts import (
    Receipt,
    ReceiptStoreError,
    RecordOutcome,
    SqliteReceiptStore,
)

MAX_MESSAGE_BYTES = 64 * 1024
EXPECTED_MESSAGE_TYPE = "scan.requested.v1"
EXPECTED_CONTENT_TYPE = "application/json"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?\Z")


class Disposition(StrEnum):
    ACK = "ack"
    DEAD_LETTER = "dead_letter"
    RETRY = "retry"


class FailureCode(StrEnum):
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    INVALID_ENCODING = "INVALID_ENCODING"
    INVALID_JSON = "INVALID_JSON"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    PROPERTIES_MISMATCH = "PROPERTIES_MISMATCH"
    EVENT_ID_CONFLICT = "EVENT_ID_CONFLICT"
    TRANSIENT_RETRIES_EXHAUSTED = "TRANSIENT_RETRIES_EXHAUSTED"


_DETAILS = {
    FailureCode.MESSAGE_TOO_LARGE: f"Message body exceeds {MAX_MESSAGE_BYTES} bytes.",
    FailureCode.INVALID_ENCODING: "Message body is not valid UTF-8.",
    FailureCode.INVALID_JSON: "Message body is not a single JSON object without duplicate keys.",
    FailureCode.SCHEMA_VIOLATION: "Message does not conform to scan.requested v1.",
    FailureCode.PROPERTIES_MISMATCH: (
        "AMQP properties (message-id, type, content-type) do not match the message."
    ),
    FailureCode.EVENT_ID_CONFLICT: (
        "A different message with the same event_id was already processed; possible tampering."
    ),
    FailureCode.TRANSIENT_RETRIES_EXHAUSTED: (
        "The receipt store stayed unavailable for every retry; the message was not processed."
    ),
}

DEFAULT_MAX_RETRIES = int(contracts.topology()["retry"]["max_retries"])


@dataclass(frozen=True, slots=True)
class MessageProperties:
    """The AMQP properties the handler relies on."""

    message_id: str | None
    message_type: str | None
    content_type: str | None
    retry_count: int = 0
    """Transient retries already performed (``x-sentinel-retry-count`` header)."""


@dataclass(frozen=True, slots=True)
class HandlingResult:
    disposition: Disposition
    event_id: str | None = None
    correlation_id: str | None = None
    duplicate: bool = False
    failure_code: FailureCode | None = None
    dead_letter_metadata: dict[str, Any] | None = None


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        # Duplicate keys are parsed inconsistently across JSON implementations and could
        # make the control plane and the worker see different values.
        raise _DuplicateKeyError
    return dict(pairs)


def _reject_constant(_: str) -> None:
    raise ValueError("non-standard JSON constant")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class MessageHandler:
    def __init__(
        self,
        store: SqliteReceiptStore,
        worker_id: str,
        clock: Callable[[], datetime] = _utc_now,
        worker_version: str = __version__,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._store = store
        self._worker_id = worker_id
        self._worker_version = worker_version
        self._clock = clock
        self._max_retries = max_retries

    def handle(self, body: bytes, properties: MessageProperties) -> HandlingResult:
        digest = hashlib.sha256(body).hexdigest()
        if len(body) > MAX_MESSAGE_BYTES:
            return self._dead_letter(FailureCode.MESSAGE_TOO_LARGE, body, digest, None)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return self._dead_letter(FailureCode.INVALID_ENCODING, body, digest, None)
        try:
            message = json.loads(
                text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
            )
        except (ValueError, RecursionError):
            return self._dead_letter(FailureCode.INVALID_JSON, body, digest, None)
        if not isinstance(message, dict):
            return self._dead_letter(FailureCode.INVALID_JSON, body, digest, None)

        validator = contracts.validator(contracts.SCAN_REQUESTED_SCHEMA)
        if next(validator.iter_errors(message), None) is not None:
            return self._dead_letter(FailureCode.SCHEMA_VIOLATION, body, digest, message)
        if (
            properties.message_id != message["event_id"]
            or properties.message_type != EXPECTED_MESSAGE_TYPE
            or properties.content_type != EXPECTED_CONTENT_TYPE
        ):
            return self._dead_letter(FailureCode.PROPERTIES_MISMATCH, body, digest, message)

        receipt = Receipt(
            {
                "schema_version": 1,
                "event_id": message["event_id"],
                "event_type": message["event_type"],
                "event_schema_version": message["schema_version"],
                "scan_id": message["scan_id"],
                "project_id": message["project_id"],
                "organization_id": message["organization_id"],
                "commit_sha": message["commit_sha"],
                "correlation_id": message["correlation_id"],
                "occurred_at": message["occurred_at"],
                "message_sha256": digest,
                "outcome": "ACCEPTED",
                "received_at": _iso(self._clock()),
                "worker_id": self._worker_id,
                "worker_version": self._worker_version,
            }
        )
        try:
            outcome = self._store.record(receipt)
        except ReceiptStoreError:
            if properties.retry_count >= self._max_retries:
                return self._dead_letter(
                    FailureCode.TRANSIENT_RETRIES_EXHAUSTED, body, digest, message
                )
            return HandlingResult(
                Disposition.RETRY,
                event_id=message["event_id"],
                correlation_id=message["correlation_id"],
            )
        if outcome is RecordOutcome.CONFLICT:
            return self._dead_letter(FailureCode.EVENT_ID_CONFLICT, body, digest, message)
        return HandlingResult(
            Disposition.ACK,
            event_id=message["event_id"],
            correlation_id=message["correlation_id"],
            duplicate=outcome is RecordOutcome.DUPLICATE,
        )

    def _dead_letter(
        self,
        code: FailureCode,
        body: bytes,
        digest: str,
        message: Mapping[str, Any] | None,
    ) -> HandlingResult:
        def identifier(field: str, pattern: re.Pattern[str]) -> str | None:
            # Only well-formed identifiers are copied; malformed values are not echoed.
            value = message.get(field) if message is not None else None
            return value if isinstance(value, str) and pattern.match(value) else None

        metadata = {
            "schema_version": 1,
            "dead_letter_id": str(uuid.uuid4()),
            "event_id": identifier("event_id", _UUID),
            "scan_id": identifier("scan_id", _UUID),
            "project_id": identifier("project_id", _UUID),
            "organization_id": identifier("organization_id", _UUID),
            "commit_sha": identifier("commit_sha", _SHA),
            "correlation_id": identifier("correlation_id", _UUID),
            "created_at": _iso(self._clock()),
            "failure_code": code.value,
            "detail": _DETAILS[code],
            "original_message_sha256": digest,
            "original_size_bytes": len(body),
            "worker_id": self._worker_id,
            "worker_version": self._worker_version,
        }
        errors = contracts.validator(contracts.DEAD_LETTER_METADATA_SCHEMA).iter_errors(metadata)
        if next(errors, None) is not None:  # pragma: no cover - guards our own output
            raise AssertionError("dead-letter metadata does not conform to its contract")
        return HandlingResult(
            Disposition.DEAD_LETTER,
            event_id=metadata["event_id"],
            correlation_id=metadata["correlation_id"],
            failure_code=code,
            dead_letter_metadata=metadata,
        )

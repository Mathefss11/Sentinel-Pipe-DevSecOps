"""Durable processing receipts used to deduplicate deliveries.

RabbitMQ delivers at least once, so the same event can arrive several times (publisher
retries, redelivery after a consumer crash). Each processed event leaves a receipt keyed
by ``event_id``; the receipt is committed to disk *before* the message is acknowledged.

The store is SQLite (standard library), so receipts survive process restarts. It is
local to one worker host: workers that share a queue must share a receipt store to
deduplicate across instances (see docs/runbooks/messaging.md, "Known limitations").
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from sentinel_worker.messaging import contracts

_SCHEMA = """
CREATE TABLE IF NOT EXISTS processing_receipts (
    event_id        TEXT NOT NULL PRIMARY KEY,
    message_sha256  TEXT NOT NULL CHECK (length(message_sha256) = 64),
    scan_id         TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    received_at     TEXT NOT NULL,
    receipt_json    TEXT NOT NULL
) STRICT
"""


class RecordOutcome(StrEnum):
    NEW = "new"
    """First delivery of this event; the receipt was committed."""

    DUPLICATE = "duplicate"
    """Same event and identical message seen before; nothing was written."""

    CONFLICT = "conflict"
    """Same event_id with a *different* message: replay or tampering; nothing written."""


class ReceiptStoreError(Exception):
    """The receipt could not be stored. Transient: the message must not be acknowledged."""


@dataclass(frozen=True, slots=True)
class Receipt:
    """A processing receipt (packages/contracts/messages/v1/processing-receipt.v1)."""

    document: dict[str, Any]

    def __post_init__(self) -> None:
        errors = list(
            contracts.validator(contracts.PROCESSING_RECEIPT_SCHEMA).iter_errors(self.document)
        )
        if errors:
            raise ValueError("receipt does not conform to processing-receipt.v1")

    @property
    def event_id(self) -> str:
        return str(self.document["event_id"])

    @property
    def message_sha256(self) -> str:
        return str(self.document["message_sha256"])


class SqliteReceiptStore:
    """Receipt store backed by a local SQLite database file.

    Durability: WAL journal with ``synchronous=FULL``, so a committed receipt survives a
    process crash or power loss. Every ``record`` call is one ``BEGIN IMMEDIATE``
    transaction; concurrent writers serialize on the database lock.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            # Owner-only permissions where the platform supports them.
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        self._connection = sqlite3.connect(path, isolation_level=None, timeout=5.0)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(_SCHEMA)

    def record(self, receipt: Receipt) -> RecordOutcome:
        """Commits the receipt unless one exists for the event.

        Raises :class:`ReceiptStoreError` if the outcome cannot be determined durably.
        """
        document = receipt.document
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                inserted = self._connection.execute(
                    """
                    INSERT INTO processing_receipts (event_id, message_sha256, scan_id, project_id,
                        organization_id, received_at, receipt_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        receipt.event_id,
                        receipt.message_sha256,
                        document["scan_id"],
                        document["project_id"],
                        document["organization_id"],
                        document["received_at"],
                        json.dumps(document, sort_keys=True, separators=(",", ":")),
                    ),
                ).rowcount
                if inserted == 1:
                    outcome = RecordOutcome.NEW
                else:
                    row = self._connection.execute(
                        "SELECT message_sha256 FROM processing_receipts WHERE event_id = ?",
                        (receipt.event_id,),
                    ).fetchone()
                    outcome = (
                        RecordOutcome.DUPLICATE
                        if row is not None and row[0] == receipt.message_sha256
                        else RecordOutcome.CONFLICT
                    )
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        except sqlite3.Error as exc:
            raise ReceiptStoreError("receipt store unavailable") from exc
        return outcome

    def get(self, event_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT receipt_json FROM processing_receipts WHERE event_id = ?", (event_id,)
        ).fetchone()
        return None if row is None else json.loads(row[0])

    def count(self) -> int:
        return int(
            self._connection.execute("SELECT count(*) FROM processing_receipts").fetchone()[0]
        )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SqliteReceiptStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

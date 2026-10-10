"""Durable processing receipts used to deduplicate deliveries.

RabbitMQ delivers at least once, so the same event can arrive several times (publisher
retries, redelivery after a consumer crash). Each accepted event leaves a receipt keyed
by ``event_id``; the receipt is committed *before* the message is acknowledged.

A receipt records **acceptance** of a delivery, not completion of any scanner work.

Backends:

* :class:`PostgresReceiptStore` (default, required outside development): receipts live
  in the shared control-plane PostgreSQL database (Flyway V005, schema ``worker``), so
  every worker instance deduplicates against the same unique ``event_id``. The worker's
  database role may only execute ``worker.record_receipt``, which also verifies the
  message against the authoritative outbox event, scan and project before accepting it.
* :class:`SqliteReceiptStore` (development only): a local file. It deduplicates only
  within one host and cannot verify tenant relationships; see
  docs/runbooks/messaging.md, "Known limitations".
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from sentinel_worker.messaging import contracts


class RecordOutcome(StrEnum):
    NEW = "NEW"
    """First acceptance of this event; the receipt was committed."""

    DUPLICATE = "DUPLICATE"
    """Same event and identical message seen before; nothing was written."""

    CONFLICT = "CONFLICT"
    """Same event_id with a *different* message: replay or tampering; nothing written."""

    REJECTED_UNKNOWN_EVENT = "REJECTED_UNKNOWN_EVENT"
    """No such scan.requested event exists in the control plane (possible forgery)."""

    REJECTED_DIGEST_MISMATCH = "REJECTED_DIGEST_MISMATCH"
    """The message differs from the payload the control plane committed (tampering)."""

    REJECTED_RELATIONSHIP_MISMATCH = "REJECTED_RELATIONSHIP_MISMATCH"
    """Claimed scan, project, organization or commit differ from the authoritative rows."""


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

    def canonical_json(self) -> str:
        return json.dumps(self.document, sort_keys=True, separators=(",", ":"))


class ReceiptStore(Protocol):
    def record(self, receipt: Receipt) -> RecordOutcome:
        """Commits the receipt unless one exists for the event.

        Returns only after the outcome is durable. Raises :class:`ReceiptStoreError` if the
        outcome cannot be determined durably.
        """
        ...  # pragma: no cover

    def close(self) -> None: ...  # pragma: no cover


# ---------------------------------------------------------------------------
# PostgreSQL (shared, default)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    host: str
    port: int
    dbname: str
    user: str
    password: str = field(repr=False)
    sslmode: str = "prefer"
    connect_timeout_seconds: int = 5
    statement_timeout_ms: int = 5000

    def connection_kwargs(self, application_name: str) -> dict[str, Any]:
        timeout = self.statement_timeout_ms
        return {
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "user": self.user,
            "password": self.password,
            "sslmode": self.sslmode,
            "connect_timeout": self.connect_timeout_seconds,
            "application_name": application_name[:63],
            # Bounded waits: a stuck database surfaces as a transient error, never a hang.
            "options": (
                f"-c statement_timeout={timeout} -c lock_timeout={timeout} "
                f"-c idle_in_transaction_session_timeout={timeout * 2}"
            ),
            "autocommit": True,
        }


class PostgresReceiptStore:
    """Receipt store in the shared PostgreSQL database (Flyway V005, schema ``worker``).

    Each :meth:`record` is one explicit transaction around ``worker.record_receipt``;
    the method returns only after ``COMMIT`` succeeded. Any database error (including an
    ambiguous commit after a lost connection) raises :class:`ReceiptStoreError`; the
    connection is discarded and re-established on the next call. Retrying after an
    ambiguous commit is safe: the receipt then reports ``DUPLICATE``.
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

    def record(self, receipt: Receipt) -> RecordOutcome:
        import psycopg

        try:
            connection = self._open()
            with connection.transaction():
                row = connection.execute(
                    "SELECT worker.record_receipt(%s::jsonb)", (receipt.canonical_json(),)
                ).fetchone()
        except psycopg.Error as exc:
            self._discard()
            raise ReceiptStoreError("receipt store unavailable") from exc
        try:
            return RecordOutcome(row[0])
        except (TypeError, ValueError, IndexError) as exc:
            # Unknown outcome: fail closed (never acknowledge on an unexpected answer).
            raise ReceiptStoreError("unexpected receipt store response") from exc

    def check(self) -> None:
        """Verifies connectivity (``SELECT 1``). Raises :class:`ReceiptStoreError`."""
        import psycopg

        try:
            self._open().execute("SELECT 1").fetchone()
        except psycopg.Error as exc:
            self._discard()
            raise ReceiptStoreError("receipt store unavailable") from exc

    def close(self) -> None:
        self._discard()

    def __enter__(self) -> PostgresReceiptStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# SQLite (development only)
# ---------------------------------------------------------------------------

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


class SqliteReceiptStore:
    """Development-only receipt store backed by a local SQLite database file.

    Deduplicates within one host only and performs **no** verification against the
    control plane (identifiers are taken from the message). Never use it with more than
    one worker host or outside the ``development`` environment.

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
                        receipt.canonical_json(),
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

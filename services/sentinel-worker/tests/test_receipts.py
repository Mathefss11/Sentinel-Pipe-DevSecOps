import hashlib
import uuid
from pathlib import Path

import pytest

from sentinel_worker.messaging.receipts import (
    Receipt,
    ReceiptStoreError,
    RecordOutcome,
    SqliteReceiptStore,
)


def receipt(
    event_id: str | None = None, sha: str | None = None, organization_id: str | None = None
) -> Receipt:
    return Receipt(
        {
            "schema_version": 1,
            "event_id": event_id or str(uuid.uuid4()),
            "event_type": "scan.requested",
            "event_schema_version": 1,
            "scan_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "organization_id": organization_id or str(uuid.uuid4()),
            "commit_sha": "a" * 40,
            "correlation_id": str(uuid.uuid4()),
            "occurred_at": "2026-10-09T12:00:00Z",
            "message_sha256": sha or hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
            "outcome": "ACCEPTED",
            "received_at": "2026-10-09T12:00:01.000000Z",
            "worker_id": "sentinel-worker-test",
            "worker_version": "0.1.0",
        }
    )


def test_first_record_is_new_and_identical_repeat_is_duplicate(store: SqliteReceiptStore) -> None:
    first = receipt()

    assert store.record(first) is RecordOutcome.NEW
    assert store.record(first) is RecordOutcome.DUPLICATE
    assert store.count() == 1


def test_same_event_id_with_different_message_is_a_conflict_and_keeps_the_original(
    store: SqliteReceiptStore,
) -> None:
    original = receipt()
    tampered = receipt(event_id=original.event_id, organization_id=str(uuid.uuid4()))
    store.record(original)

    assert store.record(tampered) is RecordOutcome.CONFLICT
    assert store.get(original.event_id) == original.document
    assert store.count() == 1


def test_receipts_survive_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "durable" / "receipts.sqlite3"
    first = receipt()
    with SqliteReceiptStore(path) as store:
        assert store.record(first) is RecordOutcome.NEW

    with SqliteReceiptStore(path) as restarted:
        assert restarted.record(first) is RecordOutcome.DUPLICATE
        assert restarted.get(first.event_id) == first.document


def test_receipts_must_conform_to_the_contract() -> None:
    document = receipt().document | {"outcome": "SCANNED"}

    with pytest.raises(ValueError, match="processing-receipt"):
        Receipt(document)


def test_store_failures_are_reported_as_transient_errors(tmp_path: Path) -> None:
    store = SqliteReceiptStore(tmp_path / "receipts.sqlite3")
    store.close()

    with pytest.raises(ReceiptStoreError):
        store.record(receipt())


def test_concurrent_stores_on_one_file_agree(tmp_path: Path) -> None:
    path = tmp_path / "receipts.sqlite3"
    shared = receipt()
    with SqliteReceiptStore(path) as a, SqliteReceiptStore(path) as b:
        outcomes = {a.record(shared), b.record(shared)}

    assert outcomes == {RecordOutcome.NEW, RecordOutcome.DUPLICATE}

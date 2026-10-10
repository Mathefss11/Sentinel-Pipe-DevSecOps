import json
import uuid
from datetime import UTC, datetime

import pytest

from sentinel_worker.messaging import contracts
from sentinel_worker.messaging.handler import (
    MAX_MESSAGE_BYTES,
    Disposition,
    FailureCode,
    HandlingResult,
    MessageHandler,
    MessageProperties,
)
from sentinel_worker.messaging.receipts import ReceiptStoreError, SqliteReceiptStore
from support import encode, properties_for, scan_requested

FIXED_NOW = datetime(2026, 10, 9, 12, 5, tzinfo=UTC)


@pytest.fixture
def handler(store: SqliteReceiptStore) -> MessageHandler:
    return MessageHandler(store, "sentinel-worker-test", clock=lambda: FIXED_NOW)


def assert_dead_letter(result: HandlingResult, code: FailureCode) -> None:
    assert result.disposition is Disposition.DEAD_LETTER
    assert result.failure_code is code
    metadata = result.dead_letter_metadata
    assert metadata is not None
    validator = contracts.validator(contracts.DEAD_LETTER_METADATA_SCHEMA)
    assert list(validator.iter_errors(metadata)) == []
    assert metadata["failure_code"] == code.value


def test_valid_message_is_recorded_then_acknowledged(
    handler: MessageHandler, store: SqliteReceiptStore
) -> None:
    message = scan_requested()

    result = handler.handle(encode(message), properties_for(message))

    assert result.disposition is Disposition.ACK
    assert not result.duplicate
    receipt = store.get(message["event_id"])
    assert receipt is not None
    for field in ("scan_id", "project_id", "organization_id", "commit_sha", "correlation_id"):
        assert receipt[field] == message[field]
    assert receipt["outcome"] == "ACCEPTED"
    assert receipt["received_at"] == "2026-10-09T12:05:00.000000Z"


def test_redelivery_of_the_same_message_is_an_acknowledged_duplicate(
    handler: MessageHandler, store: SqliteReceiptStore
) -> None:
    message = scan_requested()
    handler.handle(encode(message), properties_for(message))

    result = handler.handle(encode(message), properties_for(message))

    assert result.disposition is Disposition.ACK
    assert result.duplicate
    assert store.count() == 1


def test_cross_tenant_tampering_with_a_known_event_id_is_dead_lettered(
    handler: MessageHandler, store: SqliteReceiptStore
) -> None:
    original = scan_requested()
    handler.handle(encode(original), properties_for(original))
    tampered = {**original, "organization_id": str(uuid.uuid4()), "project_id": str(uuid.uuid4())}

    result = handler.handle(encode(tampered), properties_for(tampered))

    assert_dead_letter(result, FailureCode.EVENT_ID_CONFLICT)
    receipt = store.get(original["event_id"])
    assert receipt is not None
    assert receipt["organization_id"] == original["organization_id"]
    assert store.count() == 1


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"x" * (MAX_MESSAGE_BYTES + 1), FailureCode.MESSAGE_TOO_LARGE),
        (b"\xff\xfe not utf-8", FailureCode.INVALID_ENCODING),
        (b"{not json", FailureCode.INVALID_JSON),
        (b"[1, 2, 3]", FailureCode.INVALID_JSON),
        (b'{"event_id": NaN}', FailureCode.INVALID_JSON),
        (b'{"a": 1, "a": 2}', FailureCode.INVALID_JSON),
        (b"{}", FailureCode.SCHEMA_VIOLATION),
    ],
    ids=["too-large", "not-utf8", "not-json", "array", "nan", "duplicate-keys", "empty-object"],
)
def test_malformed_messages_are_dead_lettered_not_dropped(
    handler: MessageHandler, store: SqliteReceiptStore, body: bytes, code: FailureCode
) -> None:
    result = handler.handle(body, MessageProperties(None, "scan.requested.v1", "application/json"))

    assert_dead_letter(result, code)
    assert store.count() == 0


def test_duplicate_keys_cannot_smuggle_a_second_tenant(handler: MessageHandler) -> None:
    message = scan_requested()
    body = encode(message)[:-1] + f', "organization_id": "{uuid.uuid4()}"}}'.encode()

    assert_dead_letter(handler.handle(body, properties_for(message)), FailureCode.INVALID_JSON)


def test_schema_violations_are_dead_lettered_with_only_well_formed_identifiers(
    handler: MessageHandler,
) -> None:
    message = scan_requested(schema_version=2, organization_id="'; DROP TABLE x; --")

    result = handler.handle(encode(message), properties_for(message))

    assert_dead_letter(result, FailureCode.SCHEMA_VIOLATION)
    metadata = result.dead_letter_metadata
    assert metadata is not None
    assert metadata["event_id"] == message["event_id"]
    assert metadata["organization_id"] is None
    assert "DROP" not in json.dumps(metadata)


@pytest.mark.parametrize(
    "properties",
    [
        MessageProperties(str(uuid.uuid4()), "scan.requested.v1", "application/json"),
        MessageProperties(None, "scan.requested.v1", "application/json"),
        MessageProperties("__event__", "scan.requested.v2", "application/json"),
        MessageProperties("__event__", "scan.requested.v1", "text/plain"),
    ],
)
def test_amqp_properties_must_match_the_message(
    handler: MessageHandler, store: SqliteReceiptStore, properties: MessageProperties
) -> None:
    message = scan_requested()
    if properties.message_id == "__event__":
        properties = MessageProperties(
            message["event_id"], properties.message_type, properties.content_type
        )

    assert_dead_letter(handler.handle(encode(message), properties), FailureCode.PROPERTIES_MISMATCH)
    assert store.count() == 0


def test_dead_letter_metadata_never_contains_message_content(handler: MessageHandler) -> None:
    secret = "ghp_" + "x" * 36
    message = scan_requested(branch="main", access_token=secret)

    result = handler.handle(encode(message), properties_for(message))

    assert_dead_letter(result, FailureCode.SCHEMA_VIOLATION)
    assert secret not in json.dumps(result.dead_letter_metadata)


class FailingStore:
    def record(self, receipt: object) -> None:
        raise ReceiptStoreError("disk unavailable")


def test_receipt_store_failures_are_retried_not_acknowledged() -> None:
    handler = MessageHandler(FailingStore(), "sentinel-worker-test")  # type: ignore[arg-type]
    message = scan_requested()

    result = handler.handle(encode(message), properties_for(message))

    assert result.disposition is Disposition.RETRY
    assert result.event_id == message["event_id"]


def test_transient_failures_are_dead_lettered_once_retries_are_exhausted() -> None:
    handler = MessageHandler(FailingStore(), "sentinel-worker-test", max_retries=3)  # type: ignore[arg-type]
    message = scan_requested()
    base = properties_for(message)

    retried = handler.handle(
        encode(message),
        MessageProperties(base.message_id, base.message_type, base.content_type, retry_count=2),
    )
    exhausted = handler.handle(
        encode(message),
        MessageProperties(base.message_id, base.message_type, base.content_type, retry_count=3),
    )

    assert retried.disposition is Disposition.RETRY
    assert_dead_letter(exhausted, FailureCode.TRANSIENT_RETRIES_EXHAUSTED)
    assert exhausted.dead_letter_metadata is not None
    assert exhausted.dead_letter_metadata["scan_id"] == message["scan_id"]

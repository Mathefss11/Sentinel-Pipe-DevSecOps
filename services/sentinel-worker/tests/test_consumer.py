import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pika.exceptions
import pytest
from pika.spec import Basic, BasicProperties

from sentinel_worker.config import ConfigurationError
from sentinel_worker.messaging import consumer as consumer_module
from sentinel_worker.messaging.consumer import (
    DEAD_LETTER_EXCHANGE,
    DEAD_LETTER_HEADER,
    RETRY_COUNT_HEADER,
    RETRY_EXCHANGE,
    WORKER_QUEUE,
    ScanRequestConsumer,
    retry_count,
)
from sentinel_worker.messaging.handler import DEFAULT_MAX_RETRIES, MessageHandler
from sentinel_worker.messaging.receipts import Receipt, ReceiptStoreError, SqliteReceiptStore
from sentinel_worker.messaging.settings import PASSWORD_VAR, USERNAME_VAR, ConsumerSettings
from support import encode, scan_requested

SETTINGS = ConsumerSettings(
    host="localhost",
    port=5672,
    virtual_host="/",
    username="sentinel-worker",
    password="dev-only-test-password",
    receipt_db=Path("unused"),
)


@dataclass
class RecordingChannel:
    """Records broker calls in order, together with store writes."""

    events: list[str] = field(default_factory=list)
    published: list[dict[str, Any]] = field(default_factory=list)
    fail_publish: bool = False

    def basic_ack(self, delivery_tag: int) -> None:
        self.events.append(f"ack:{delivery_tag}")

    def basic_nack(self, delivery_tag: int, requeue: bool) -> None:
        self.events.append(f"nack:{delivery_tag}:requeue={requeue}")

    def basic_publish(self, **kwargs: Any) -> None:
        if self.fail_publish:
            raise pika.exceptions.NackError([])
        self.events.append(f"publish:{kwargs['exchange']}")
        self.published.append(kwargs)


class RecordingStore(SqliteReceiptStore):
    def __init__(self, path: Path, channel: RecordingChannel) -> None:
        super().__init__(path)
        self._channel = channel

    def record(self, receipt: Receipt) -> Any:
        outcome = super().record(receipt)
        self._channel.events.append("receipt-committed")
        return outcome


def properties(message: dict[str, Any], headers: dict[str, Any] | None = None) -> BasicProperties:
    return BasicProperties(
        message_id=message.get("event_id"),
        type="scan.requested.v1",
        content_type="application/json",
        headers=headers,
        delivery_mode=2,
    )


def deliver(tag: int = 7) -> Basic.Deliver:
    return Basic.Deliver(delivery_tag=tag, redelivered=False, routing_key="scan.requested.v1")


def make_consumer(
    tmp_path: Path, channel: RecordingChannel
) -> tuple[ScanRequestConsumer, list[float]]:
    sleeps: list[float] = []
    store = RecordingStore(tmp_path / "receipts.sqlite3", channel)
    consumer = ScanRequestConsumer(
        SETTINGS,
        MessageHandler(store, "sentinel-worker-test"),
        "sentinel-worker-test",
        sleeps.append,
    )
    return consumer, sleeps


def test_topology_names_come_from_the_shared_contract() -> None:
    assert WORKER_QUEUE == "sentinel.scan-requests.worker"
    assert DEAD_LETTER_EXCHANGE == "sentinel.scan-requests.dlx"
    assert DEAD_LETTER_HEADER == "x-sentinel-dead-letter"
    assert RETRY_EXCHANGE == "sentinel.scan-requests.retry"
    assert RETRY_COUNT_HEADER == "x-sentinel-retry-count"


def test_message_is_acknowledged_only_after_the_receipt_is_committed(tmp_path: Path) -> None:
    channel = RecordingChannel()
    consumer, _ = make_consumer(tmp_path, channel)
    message = scan_requested()

    consumer.process(channel, deliver(), properties(message), encode(message))  # type: ignore[arg-type]

    assert channel.events == ["receipt-committed", "ack:7"]
    assert consumer.stats.outcomes == {"accepted": 1}


def test_invalid_message_is_dead_lettered_with_metadata_before_acknowledgement(
    tmp_path: Path,
) -> None:
    channel = RecordingChannel()
    consumer, _ = make_consumer(tmp_path, channel)
    body = b"{not json"

    consumer.process(channel, deliver(), properties({}, {"trace": "kept"}), body)  # type: ignore[arg-type]

    assert channel.events == [f"publish:{DEAD_LETTER_EXCHANGE}", "ack:7"]
    published = channel.published[0]
    assert published["body"] == body
    assert published["mandatory"] is True
    assert published["properties"].delivery_mode == 2
    assert published["properties"].headers["trace"] == "kept"
    metadata = json.loads(published["properties"].headers[DEAD_LETTER_HEADER])
    assert metadata["failure_code"] == "INVALID_JSON"
    assert consumer.stats.outcomes == {"dead_lettered": 1}


def test_failed_dead_letter_publication_requeues_instead_of_dropping(tmp_path: Path) -> None:
    channel = RecordingChannel(fail_publish=True)
    consumer, sleeps = make_consumer(tmp_path, channel)

    consumer.process(channel, deliver(), properties({}), b"{not json")  # type: ignore[arg-type]

    assert channel.events == ["nack:7:requeue=True"]
    assert sleeps == [consumer_module.REPUBLISH_FAILURE_PAUSE_SECONDS]
    assert consumer.stats.outcomes == {"republish_failed_requeued": 1}


def failing_record(self: SqliteReceiptStore, receipt: Receipt) -> None:
    raise ReceiptStoreError("locked")


def test_transient_failure_is_retried_through_the_retry_exchange(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    channel = RecordingChannel()
    consumer, sleeps = make_consumer(tmp_path, channel)
    monkeypatch.setattr(RecordingStore, "record", failing_record)
    message = scan_requested()

    consumer.process(  # type: ignore[arg-type]
        channel, deliver(), properties(message, {RETRY_COUNT_HEADER: 2}), encode(message)
    )

    assert channel.events == [f"publish:{RETRY_EXCHANGE}", "ack:7"]
    published = channel.published[0]
    assert published["body"] == encode(message)
    assert published["properties"].headers[RETRY_COUNT_HEADER] == 3
    assert published["properties"].message_id == message["event_id"]
    assert sleeps == []  # the delay is the retry queue's TTL, not a blocked consumer
    assert consumer.stats.outcomes == {"retry_scheduled": 1}


def test_exhausted_transient_retries_are_dead_lettered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    channel = RecordingChannel()
    consumer, _ = make_consumer(tmp_path, channel)
    monkeypatch.setattr(RecordingStore, "record", failing_record)
    message = scan_requested()

    consumer.process(  # type: ignore[arg-type]
        channel,
        deliver(),
        properties(message, {RETRY_COUNT_HEADER: DEFAULT_MAX_RETRIES}),
        encode(message),
    )

    assert channel.events == [f"publish:{DEAD_LETTER_EXCHANGE}", "ack:7"]
    metadata = json.loads(channel.published[0]["properties"].headers[DEAD_LETTER_HEADER])
    assert metadata["failure_code"] == "TRANSIENT_RETRIES_EXHAUSTED"
    assert metadata["event_id"] == message["event_id"]


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (None, 0),
        ({}, 0),
        ({RETRY_COUNT_HEADER: 3}, 3),
        ({RETRY_COUNT_HEADER: -1}, DEFAULT_MAX_RETRIES),
        ({RETRY_COUNT_HEADER: "2"}, DEFAULT_MAX_RETRIES),
        ({RETRY_COUNT_HEADER: True}, DEFAULT_MAX_RETRIES),
    ],
)
def test_retry_count_header_is_parsed_fail_safe(
    headers: dict[str, Any] | None, expected: int
) -> None:
    assert retry_count(headers) == expected


def test_settings_require_credentials_and_never_expose_the_password() -> None:
    secret = "do-not-print-me"
    settings = ConsumerSettings.from_env({USERNAME_VAR: "sentinel-worker", PASSWORD_VAR: secret})

    assert secret not in repr(settings)
    assert settings.prefetch == 1
    with pytest.raises(ConfigurationError, match=PASSWORD_VAR):
        ConsumerSettings.from_env({USERNAME_VAR: "sentinel-worker"})
    with pytest.raises(ConfigurationError, match=USERNAME_VAR):
        ConsumerSettings.from_env({PASSWORD_VAR: secret})


@pytest.mark.parametrize("value", ["0", "51", "many", "-1"])
def test_prefetch_is_bounded(value: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        ConsumerSettings.from_env(
            {USERNAME_VAR: "u", PASSWORD_VAR: "p", "SENTINEL_WORKER_PREFETCH": value}
        )

    assert "SENTINEL_WORKER_PREFETCH" in str(excinfo.value)
    assert "between 1 and 50" in str(excinfo.value)

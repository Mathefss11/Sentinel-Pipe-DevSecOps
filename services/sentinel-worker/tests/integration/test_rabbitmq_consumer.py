"""Consumer behaviour against a real RabbitMQ broker (Testcontainers).

These tests exercise the consumer mechanics (acknowledgement, retry, dead-lettering,
crash recovery) with the development SQLite receipt store. The broker is provisioned by
the production script (infrastructure/docker/rabbitmq/provision.sh), and the consumer
runs as the least-privileged worker user it creates. Shared-store, tenant-verification
and multi-worker behaviour with PostgreSQL is covered in test_distributed_processing.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pika
import pika.exceptions
import pytest
from infrastructure import (
    ROUTE,
    TOPOLOGY,
    Broker,
    drain,
    publish,
    queue_depth,
    wait_for_depth,
)

from sentinel_worker.messaging import contracts
from sentinel_worker.messaging.consumer import (
    DEAD_LETTER_EXCHANGE,
    DEAD_LETTER_HEADER,
    RETRY_COUNT_HEADER,
    RETRY_EXCHANGE,
    WORKER_QUEUE,
    ScanRequestConsumer,
)
from sentinel_worker.messaging.handler import MessageHandler
from sentinel_worker.messaging.receipts import ReceiptStoreError, SqliteReceiptStore
from support import encode, scan_requested

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("empty_queues")]

DEAD_LETTER_QUEUE = next(
    b["queue"] for b in TOPOLOGY["bindings"] if b["exchange"] == DEAD_LETTER_EXCHANGE
)


def consume(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path, max_messages: int = 50
) -> ScanRequestConsumer:
    consumer = ScanRequestConsumer(
        broker.worker_settings(tmp_path / "unused.sqlite3"),
        MessageHandler(store, "sentinel-worker-it"),
        "sentinel-worker-it",
        sleep=lambda _: None,
    )
    consumer.run(max_messages=max_messages, inactivity_timeout=2)
    return consumer


def test_valid_message_is_recorded_and_acknowledged(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    message = scan_requested()
    publish(broker, message)

    consumer = consume(broker, store, tmp_path)

    assert consumer.stats.outcomes == {"accepted": 1}
    receipt = store.get(message["event_id"])
    assert receipt is not None
    assert receipt["organization_id"] == message["organization_id"]
    assert queue_depth(broker, WORKER_QUEUE) == 0


def test_duplicate_deliveries_produce_one_receipt(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    message = scan_requested()
    publish(broker, message)
    publish(broker, message)

    consumer = consume(broker, store, tmp_path)

    assert consumer.stats.outcomes == {"accepted": 1, "duplicate": 1}
    assert store.count() == 1
    assert queue_depth(broker, WORKER_QUEUE) == 0


def test_malformed_messages_reach_the_dead_letter_queue_intact_with_metadata(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    body = b'{"event_id": "not-a-uuid", "secret": "do-not-log"}'
    publish(broker, {"event_id": "not-a-uuid"}, body=body)

    consumer = consume(broker, store, tmp_path)

    assert consumer.stats.outcomes == {"dead_lettered": 1}
    assert queue_depth(broker, WORKER_QUEUE) == 0
    dead = drain(broker, DEAD_LETTER_QUEUE)
    assert len(dead) == 1
    properties, dead_body = dead[0]
    assert dead_body == body
    assert properties.delivery_mode == pika.DeliveryMode.Persistent.value
    metadata = json.loads(properties.headers[DEAD_LETTER_HEADER])
    validator = contracts.validator(contracts.DEAD_LETTER_METADATA_SCHEMA)
    assert list(validator.iter_errors(metadata)) == []
    assert metadata["failure_code"] == "SCHEMA_VIOLATION"
    assert "do-not-log" not in properties.headers[DEAD_LETTER_HEADER]
    assert store.count() == 0


def test_cross_tenant_replay_of_an_event_id_is_dead_lettered(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    original = scan_requested()
    tampered = {**original, "organization_id": scan_requested()["organization_id"]}
    publish(broker, original)
    publish(broker, tampered)

    consumer = consume(broker, store, tmp_path)

    assert consumer.stats.outcomes == {"accepted": 1, "dead_lettered": 1}
    receipt = store.get(original["event_id"])
    assert receipt is not None
    assert receipt["organization_id"] == original["organization_id"]
    (properties, _), *_ = drain(broker, DEAD_LETTER_QUEUE)
    assert json.loads(properties.headers[DEAD_LETTER_HEADER])["failure_code"] == "EVENT_ID_CONFLICT"


def test_crash_before_acknowledgement_leads_to_redelivery(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    message = scan_requested()
    publish(broker, message)
    # A worker receives the message and dies before doing anything.
    crashed = pika.BlockingConnection(broker.worker_parameters())
    method, _, _ = crashed.channel().basic_get(WORKER_QUEUE, auto_ack=False)
    assert method is not None
    crashed.close()

    consumer = consume(broker, store, tmp_path)

    assert consumer.stats.outcomes == {"accepted": 1}
    assert store.count() == 1


class AlwaysFailingStore:
    def record(self, receipt: object) -> None:
        raise ReceiptStoreError("disk unavailable")


RETRY_QUEUE = next(b["queue"] for b in TOPOLOGY["bindings"] if b["exchange"] == RETRY_EXCHANGE)


class SimulatedCrashError(Exception):
    """Raised where a real worker process would have died."""


class CrashBeforeAck:
    """Delegates to a real channel, but the worker dies when it tries to acknowledge."""

    def __init__(self, channel: Any) -> None:
        self._channel = channel

    def __getattr__(self, name: str) -> Any:
        return getattr(self._channel, name)

    def basic_ack(self, delivery_tag: int) -> None:
        raise SimulatedCrashError


def process_then_crash_before_ack(broker: Broker, handler: MessageHandler) -> None:
    """Receives one message as the worker user, runs the real processing path, and dies
    at the acknowledgement: the connection closes with the delivery unacknowledged."""
    connection = pika.BlockingConnection(broker.worker_parameters())
    channel = connection.channel()
    channel.confirm_delivery()
    method, properties, body = channel.basic_get(WORKER_QUEUE, auto_ack=False)
    assert method is not None
    consumer = ScanRequestConsumer(
        broker.worker_settings(Path("unused")), handler, "crashing-worker", sleep=lambda _: None
    )
    with pytest.raises(SimulatedCrashError):
        consumer.process(CrashBeforeAck(channel), method, properties, body)  # type: ignore[arg-type]
    connection.close()


def test_crash_after_receipt_commit_but_before_ack_is_deduplicated(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    message = scan_requested()
    publish(broker, message)

    process_then_crash_before_ack(broker, MessageHandler(store, "crashing-worker"))

    # Receipt committed, message not acknowledged: it is redelivered, not lost.
    assert store.count() == 1
    assert queue_depth(broker, WORKER_QUEUE) == 1
    consumer = consume(broker, store, tmp_path)
    assert consumer.stats.outcomes == {"duplicate": 1}
    assert store.count() == 1
    assert queue_depth(broker, WORKER_QUEUE) == 0


def test_crash_after_dead_letter_copy_but_before_ack_duplicates_the_dead_letter(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    publish(broker, {"event_id": "not-a-uuid"}, body=b'{"malformed": true}')

    process_then_crash_before_ack(broker, MessageHandler(store, "crashing-worker"))

    # The confirmed copy is in the dead-letter queue AND the original is still queued.
    assert queue_depth(broker, DEAD_LETTER_QUEUE) == 1
    assert queue_depth(broker, WORKER_QUEUE) == 1
    consumer = consume(broker, store, tmp_path)
    assert consumer.stats.outcomes == {"dead_lettered": 1}
    # At-least-once: a duplicate dead letter, never a lost message.
    dead = drain(broker, DEAD_LETTER_QUEUE)
    assert [body for _, body in dead] == [b'{"malformed": true}', b'{"malformed": true}']
    assert queue_depth(broker, WORKER_QUEUE) == 0


def test_crash_after_retry_copy_but_before_ack_is_deduplicated_once_processing_succeeds(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path
) -> None:
    message = scan_requested()
    publish(broker, message)

    process_then_crash_before_ack(
        broker,
        MessageHandler(AlwaysFailingStore(), "crashing-worker"),  # type: ignore[arg-type]
    )

    assert queue_depth(broker, RETRY_QUEUE) == 1
    assert queue_depth(broker, WORKER_QUEUE) == 1
    # The store recovers. The redelivered original is processed ...
    assert consume(broker, store, tmp_path, max_messages=1).stats.outcomes == {"accepted": 1}
    # ... and the retry copy, once its delay expires, is absorbed as a duplicate.
    (properties, body), *_ = drain(broker, RETRY_QUEUE)
    assert properties.headers[RETRY_COUNT_HEADER] == 1
    publish(broker, message, body=body)
    assert consume(broker, store, tmp_path).stats.outcomes == {"duplicate": 1}
    assert store.count() == 1


def test_logs_contain_no_credentials_or_payload_content(
    broker: Broker, store: SqliteReceiptStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    marker = "confidential-repo-marker"
    valid = scan_requested(repository={"provider": "GITHUB", "owner": "acme-corp", "name": marker})
    publish(broker, valid)
    publish(broker, {"event_id": "x"}, body=json.dumps({"secret": marker}).encode())
    caplog.set_level("DEBUG")

    consumer = consume(broker, store, tmp_path)

    assert consumer.stats.outcomes == {"accepted": 1, "dead_lettered": 1}
    assert valid["event_id"] in caplog.text
    assert marker not in caplog.text
    assert broker.worker_password not in caplog.text
    drain(broker, DEAD_LETTER_QUEUE)


def test_deduplication_survives_a_worker_restart(broker: Broker, tmp_path: Path) -> None:
    path = tmp_path / "restart" / "receipts.sqlite3"
    message = scan_requested()
    publish(broker, message)
    with SqliteReceiptStore(path) as first_run:
        assert consume(broker, first_run, tmp_path).stats.outcomes == {"accepted": 1}

    # The publisher re-publishes the event (at-least-once), and the worker restarted.
    publish(broker, message)
    with SqliteReceiptStore(path) as restarted:
        assert consume(broker, restarted, tmp_path).stats.outcomes == {"duplicate": 1}
        assert restarted.count() == 1


def failing_consumer(broker: Broker, tmp_path: Path) -> ScanRequestConsumer:
    return ScanRequestConsumer(
        broker.worker_settings(tmp_path / "unused.sqlite3"),
        MessageHandler(AlwaysFailingStore(), "sentinel-worker-it"),  # type: ignore[arg-type]
        "sentinel-worker-it",
        sleep=lambda _: None,
    )


def test_transient_failure_moves_the_message_to_the_retry_queue(
    broker: Broker, tmp_path: Path
) -> None:
    message = scan_requested()
    publish(broker, message)

    consumer = failing_consumer(broker, tmp_path)
    consumer.run(max_messages=1, inactivity_timeout=2)

    assert consumer.stats.outcomes == {"retry_scheduled": 1}
    assert queue_depth(broker, WORKER_QUEUE) == 0
    retried = drain(broker, RETRY_QUEUE)
    assert len(retried) == 1
    assert retried[0][1] == encode(message)
    assert retried[0][0].headers[RETRY_COUNT_HEADER] == 1


def test_retry_queue_returns_messages_to_the_work_queue_after_its_ttl(broker: Broker) -> None:
    message = scan_requested()
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    channel.confirm_delivery()
    # A per-message TTL shorter than the queue TTL keeps the test fast; the dead-lettering
    # path (retry queue -> scan-requests exchange -> work queue) is the production one.
    channel.basic_publish(
        RETRY_EXCHANGE,
        "",
        encode(message),
        pika.BasicProperties(
            message_id=message["event_id"],
            delivery_mode=pika.DeliveryMode.Persistent,
            expiration="100",
            headers={RETRY_COUNT_HEADER: 1},
        ),
        mandatory=True,
    )
    connection.close()

    wait_for_depth(broker, WORKER_QUEUE, 1)

    (properties, body), *_ = drain(broker, WORKER_QUEUE)
    assert body == encode(message)
    assert properties.headers[RETRY_COUNT_HEADER] == 1


def test_exhausted_retries_are_dead_lettered_with_metadata(broker: Broker, tmp_path: Path) -> None:
    message = scan_requested()
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    channel.confirm_delivery()
    channel.basic_publish(
        ROUTE["exchange"],
        ROUTE["routing_key"],
        encode(message),
        pika.BasicProperties(
            message_id=message["event_id"],
            type="scan.requested.v1",
            content_type="application/json",
            delivery_mode=pika.DeliveryMode.Persistent,
            headers={RETRY_COUNT_HEADER: TOPOLOGY["retry"]["max_retries"]},
        ),
        mandatory=True,
    )
    connection.close()

    consumer = failing_consumer(broker, tmp_path)
    consumer.run(max_messages=1, inactivity_timeout=2)

    assert consumer.stats.outcomes == {"dead_lettered": 1}
    (properties, body), *_ = drain(broker, DEAD_LETTER_QUEUE)
    assert body == encode(message)
    metadata = json.loads(properties.headers[DEAD_LETTER_HEADER])
    assert metadata["failure_code"] == "TRANSIENT_RETRIES_EXHAUSTED"
    assert metadata["scan_id"] == message["scan_id"]


def test_consumer_crash_loops_are_bounded_by_the_delivery_limit(broker: Broker) -> None:
    message = scan_requested()
    publish(broker, message)
    limit = next(q for q in TOPOLOGY["queues"] if q["name"] == WORKER_QUEUE)["arguments"][
        "x-delivery-limit"
    ]

    # A poison message that crashes every consumer before it can acknowledge.
    for _ in range(limit + 1):
        crashed = pika.BlockingConnection(broker.worker_parameters())
        method, _, _ = crashed.channel().basic_get(WORKER_QUEUE, auto_ack=False)
        crashed.close()
        if method is None:
            break

    wait_for_depth(broker, DEAD_LETTER_QUEUE, 1)
    assert queue_depth(broker, WORKER_QUEUE) == 0
    (properties, body), *_ = drain(broker, DEAD_LETTER_QUEUE)
    assert body == encode(message)
    assert properties.headers.get("x-first-death-reason") == "delivery_limit"


def test_worker_credentials_are_least_privilege(broker: Broker) -> None:
    def refused(action: Any) -> None:
        connection = pika.BlockingConnection(broker.worker_parameters())
        channel = connection.channel()
        with pytest.raises(pika.exceptions.ChannelClosedByBroker) as excinfo:
            action(channel)
        assert excinfo.value.reply_code == 403
        connection.close()

    # Cannot inject scan requests.
    refused(
        lambda channel: (
            channel.confirm_delivery(),
            channel.basic_publish(ROUTE["exchange"], ROUTE["routing_key"], b"{}"),
        )
    )
    # Cannot create or alter topology.
    refused(lambda channel: channel.queue_declare("attacker-queue", durable=True))
    # Cannot read the dead-letter queue.
    refused(lambda channel: channel.basic_get(DEAD_LETTER_QUEUE, auto_ack=False))

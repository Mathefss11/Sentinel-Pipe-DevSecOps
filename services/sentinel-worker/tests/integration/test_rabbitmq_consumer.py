"""Consumer behaviour against a real RabbitMQ broker (Testcontainers).

The broker image is pinned to the same digest as compose.yaml and the Java tests. The
topology is declared from packages/contracts/messaging/topology.v1.json (as the control
plane does), and the consumer runs as a least-privileged user with exactly the
permissions documented in docs/runbooks/messaging.md.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pika
import pika.exceptions
import pytest
from broker_diagnostics import diagnosed
from testcontainers.community.rabbitmq import RabbitMqContainer

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
from sentinel_worker.messaging.settings import ConsumerSettings
from support import encode, scan_requested

pytestmark = pytest.mark.integration

# rabbitmq:4.3.6-management-alpine, identical to compose.yaml and TestcontainersConfiguration.
RABBITMQ_IMAGE = "rabbitmq@sha256:3ef7f7e89fed709a78f79b8b5f4e30e1312a1d4089da752e23595566d9d61a95"

TOPOLOGY = contracts.topology()
ROUTE = TOPOLOGY["messages"]["scan.requested"]
DEAD_LETTER_QUEUE = next(
    b["queue"] for b in TOPOLOGY["bindings"] if b["exchange"] == DEAD_LETTER_EXCHANGE
)
WORKER_USER = "sentinel-worker"
# Least privilege: no configure, write only to the dead-letter and retry exchanges, read only
# the worker queue (see docs/runbooks/messaging.md).
WORKER_PERMISSIONS = (
    "^$",
    r"^sentinel\.scan-requests\.(dlx|retry)$",
    r"^sentinel\.scan-requests\.worker$",
)


@dataclass(frozen=True)
class Broker:
    admin: pika.ConnectionParameters
    host: str
    port: int
    worker_password: str

    def worker_settings(self, receipt_db: Path) -> ConsumerSettings:
        return ConsumerSettings(
            host=self.host,
            port=self.port,
            virtual_host="/",
            username=WORKER_USER,
            password=self.worker_password,
            receipt_db=receipt_db,
            prefetch=1,
        )

    def worker_parameters(self) -> pika.ConnectionParameters:
        return pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            credentials=pika.PlainCredentials(WORKER_USER, self.worker_password),
        )


def _new_password() -> str:
    # Hex only. rabbitmqctl parses an argument starting with "-" as an option, and
    # token_urlsafe() can start with "-": that was the root cause of the intermittent
    # fixture failure (exit code 64, "Invalid options for this command").
    return secrets.token_hex(24)


def _exec(container: RabbitMqContainer, *command: str, secret: str = "") -> None:
    result = container.exec(list(command))
    if result.exit_code != 0:
        output = result.output.decode("utf-8", errors="replace")
        if secret:
            output = output.replace(secret, "<redacted>")
        # Report the command name and redacted output only; never the arguments.
        raise RuntimeError(f"{command[0]} {command[1]} exited with {result.exit_code}: {output}")


@pytest.fixture(scope="module")
def broker() -> Iterator[Broker]:
    admin_password = _new_password()
    container = RabbitMqContainer(
        RABBITMQ_IMAGE, username="sentinel-admin", password=admin_password
    )
    with diagnosed(container, "container start"):
        container.start()
    try:
        with diagnosed(container, "topology and user provisioning"):
            admin = container.get_connection_params()
            connection = pika.BlockingConnection(admin)
            channel = connection.channel()
            for exchange in TOPOLOGY["exchanges"]:
                channel.exchange_declare(
                    exchange["name"],
                    exchange_type=exchange["type"],
                    durable=exchange["durable"],
                    auto_delete=exchange["auto_delete"],
                )
            for queue in TOPOLOGY["queues"]:
                channel.queue_declare(
                    queue["name"], durable=queue["durable"], arguments=queue["arguments"]
                )
            for binding in TOPOLOGY["bindings"]:
                channel.queue_bind(
                    binding["queue"], binding["exchange"], routing_key=binding["routing_key"]
                )
            connection.close()

            worker_password = _new_password()
            _exec(
                container,
                "rabbitmqctl",
                "add_user",
                WORKER_USER,
                worker_password,
                secret=worker_password,
            )
            _exec(
                container,
                "rabbitmqctl",
                "set_permissions",
                "-p",
                "/",
                WORKER_USER,
                *WORKER_PERMISSIONS,
            )
        yield Broker(admin, admin.host, int(admin.port), worker_password)
    finally:
        container.stop()


@pytest.fixture(autouse=True)
def empty_queues(broker: Broker) -> None:
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    for queue in TOPOLOGY["queues"]:
        channel.queue_purge(queue["name"])
    connection.close()


def publish(broker: Broker, message: dict[str, Any], body: bytes | None = None) -> None:
    """Publishes like the control plane: persistent, confirmed, mandatory."""
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    channel.confirm_delivery()
    channel.basic_publish(
        exchange=ROUTE["exchange"],
        routing_key=ROUTE["routing_key"],
        body=encode(message) if body is None else body,
        properties=pika.BasicProperties(
            message_id=message.get("event_id"),
            correlation_id=message.get("correlation_id"),
            type="scan.requested.v1",
            content_type="application/json",
            delivery_mode=pika.DeliveryMode.Persistent,
        ),
        mandatory=True,
    )
    connection.close()


def queue_depth(broker: Broker, queue: str) -> int:
    connection = pika.BlockingConnection(broker.admin)
    depth = connection.channel().queue_declare(queue, passive=True).method.message_count
    connection.close()
    return int(depth)


def drain(broker: Broker, queue: str) -> list[tuple[pika.BasicProperties, bytes]]:
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    messages = []
    while True:
        method, properties, body = channel.basic_get(queue, auto_ack=True)
        if method is None:
            break
        messages.append((properties, body))
    connection.close()
    return messages


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


def wait_for_depth(broker: Broker, queue: str, expected: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while queue_depth(broker, queue) != expected:
        assert time.monotonic() < deadline, f"{queue} did not reach depth {expected}"
        time.sleep(0.2)


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

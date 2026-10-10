"""RabbitMQ consumer for ``scan.requested`` v1 messages.

Delivery semantics: at-least-once. Every message is acknowledged manually and only after
its outcome is durable:

* ``ACK``: the processing receipt is committed first, then ``basic.ack``;
* ``DEAD_LETTER``: the original body and properties are published to the dead-letter
  exchange with an ``x-sentinel-dead-letter`` metadata header (persistent, publisher
  confirms, mandatory); only after the broker confirms is the original acknowledged;
* ``RETRY`` (transient failure): the message is published to the retry exchange with an
  incremented ``x-sentinel-retry-count`` header, then acknowledged. The retry queue holds
  it for its TTL and dead-letters it back to the work queue. After ``max_retries`` the
  handler dead-letters it permanently. Retries never block the consumer thread.

If a republication (dead-letter or retry) is not confirmed, the original is requeued
after a bounded pause instead of being dropped. If the worker crashes before
acknowledging, RabbitMQ redelivers the message (counted against the queue's delivery
limit); the receipt store makes the redelivery a no-op duplicate.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pika
import pika.exceptions
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties

from sentinel_worker.messaging import contracts
from sentinel_worker.messaging.handler import (
    DEFAULT_MAX_RETRIES,
    Disposition,
    HandlingResult,
    MessageHandler,
    MessageProperties,
)
from sentinel_worker.messaging.settings import ConsumerSettings

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _Topology:
    worker_queue: str
    dead_letter_exchange: str
    retry_exchange: str
    dead_letter_header: str
    retry_count_header: str


def _resolve_topology() -> _Topology:
    """Derives names from the shared topology contract (packages/contracts/messaging)."""
    topology = contracts.topology()
    route = topology["messages"]["scan.requested"]
    queue = next(
        binding["queue"]
        for binding in topology["bindings"]
        if binding["exchange"] == route["exchange"]
        and binding["routing_key"] == route["routing_key"]
    )
    arguments = next(q["arguments"] for q in topology["queues"] if q["name"] == queue)
    return _Topology(
        worker_queue=queue,
        dead_letter_exchange=arguments["x-dead-letter-exchange"],
        retry_exchange=topology["retry"]["exchange"],
        dead_letter_header=topology["headers"]["dead_letter_metadata"],
        retry_count_header=topology["retry"]["count_header"],
    )


TOPOLOGY = _resolve_topology()
WORKER_QUEUE = TOPOLOGY.worker_queue
DEAD_LETTER_EXCHANGE = TOPOLOGY.dead_letter_exchange
RETRY_EXCHANGE = TOPOLOGY.retry_exchange
DEAD_LETTER_HEADER = TOPOLOGY.dead_letter_header
RETRY_COUNT_HEADER = TOPOLOGY.retry_count_header

REPUBLISH_FAILURE_PAUSE_SECONDS = 5.0


def new_worker_id() -> str:
    return f"sentinel-worker-{uuid.uuid4().hex[:12]}"


def retry_count(headers: dict[str, Any] | None) -> int:
    """Retries already performed. A malformed header is treated as exhausted (fail safe)."""
    value = (headers or {}).get(RETRY_COUNT_HEADER, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return DEFAULT_MAX_RETRIES
    return value


@dataclass(slots=True)
class ConsumerStats:
    """In-process outcome counters (also emitted as structured log events)."""

    outcomes: Counter[str] = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.outcomes.values())


def _log(event: str, level: int = logging.INFO, **fields: Any) -> None:
    # Structured, payload-free log line; values are identifiers and outcome codes only.
    logger.log(level, json.dumps({"event": event, **fields}, sort_keys=True))


class ScanRequestConsumer:
    def __init__(
        self,
        settings: ConsumerSettings,
        handler: MessageHandler,
        worker_id: str,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._settings = settings
        self._handler = handler
        self._worker_id = worker_id
        self._sleep = sleep
        self.stats = ConsumerStats()

    def connection_parameters(self) -> pika.ConnectionParameters:
        return pika.ConnectionParameters(
            host=self._settings.host,
            port=self._settings.port,
            virtual_host=self._settings.virtual_host,
            credentials=pika.PlainCredentials(self._settings.username, self._settings.password),
            heartbeat=30,
            blocked_connection_timeout=60,
            connection_attempts=3,
            retry_delay=2,
            client_properties={"connection_name": self._worker_id},
        )

    def run(
        self, max_messages: int | None = None, inactivity_timeout: float | None = None
    ) -> ConsumerStats:
        """Consumes until ``max_messages`` were handled, the queue stayed idle for
        ``inactivity_timeout`` seconds, or the process is interrupted."""
        connection = pika.BlockingConnection(self.connection_parameters())
        try:
            channel = connection.channel()
            channel.confirm_delivery()
            # Topology is owned by the control plane; the worker only verifies it.
            channel.queue_declare(queue=WORKER_QUEUE, passive=True)
            channel.exchange_declare(exchange=DEAD_LETTER_EXCHANGE, passive=True)
            channel.exchange_declare(exchange=RETRY_EXCHANGE, passive=True)
            channel.basic_qos(prefetch_count=self._settings.prefetch)
            _log(
                "consumer.started",
                worker_id=self._worker_id,
                queue=WORKER_QUEUE,
                prefetch=self._settings.prefetch,
            )
            start = self.stats.total
            for method, properties, body in channel.consume(
                WORKER_QUEUE, auto_ack=False, inactivity_timeout=inactivity_timeout
            ):
                if method is None:  # inactivity timeout elapsed
                    break
                self.process(channel, method, properties, body)
                if max_messages is not None and self.stats.total - start >= max_messages:
                    break
            channel.cancel()
        except KeyboardInterrupt:
            _log("consumer.interrupted", worker_id=self._worker_id)
        finally:
            if connection.is_open:
                connection.close()
            _log("consumer.stopped", worker_id=self._worker_id, outcomes=dict(self.stats.outcomes))
        return self.stats

    def process(
        self,
        channel: BlockingChannel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes,
    ) -> HandlingResult:
        retries = retry_count(properties.headers)
        result = self._handler.handle(
            body,
            MessageProperties(
                message_id=properties.message_id,
                message_type=properties.type,
                content_type=properties.content_type,
                retry_count=retries,
            ),
        )
        tag = method.delivery_tag
        if result.disposition is Disposition.ACK:
            channel.basic_ack(delivery_tag=tag)
            outcome = "duplicate" if result.duplicate else "accepted"
        elif result.disposition is Disposition.DEAD_LETTER:
            extra = {DEAD_LETTER_HEADER: json.dumps(result.dead_letter_metadata, sort_keys=True)}
            outcome = self._republish_then_ack(
                channel, tag, DEAD_LETTER_EXCHANGE, properties, body, extra, "dead_lettered"
            )
        else:
            outcome = self._republish_then_ack(
                channel,
                tag,
                RETRY_EXCHANGE,
                properties,
                body,
                {RETRY_COUNT_HEADER: retries + 1},
                "retry_scheduled",
            )
        self.stats.outcomes[outcome] += 1
        _log(
            "message.processed",
            level=logging.WARNING if outcome not in ("accepted", "duplicate") else logging.INFO,
            outcome=outcome,
            event_id=result.event_id,
            correlation_id=result.correlation_id,
            failure_code=result.failure_code.value if result.failure_code else None,
            retry_count=retries,
            redelivered=bool(method.redelivered),
        )
        return result

    def _republish_then_ack(
        self,
        channel: BlockingChannel,
        tag: int,
        exchange: str,
        properties: BasicProperties,
        body: bytes,
        extra_headers: dict[str, Any],
        success_outcome: str,
    ) -> str:
        """Publishes a persistent copy (confirmed, mandatory), then acks the original.

        If the copy is not confirmed, the original is requeued after a pause; it is never
        acknowledged without its copy being safely stored by the broker.
        """
        copy_properties = BasicProperties(
            content_type=properties.content_type,
            content_encoding=properties.content_encoding,
            message_id=properties.message_id,
            correlation_id=properties.correlation_id,
            type=properties.type,
            timestamp=properties.timestamp,
            app_id=properties.app_id,
            headers={**(properties.headers or {}), **extra_headers},
            delivery_mode=pika.DeliveryMode.Persistent,
        )
        try:
            channel.basic_publish(
                exchange=exchange,
                routing_key="",
                body=body,
                properties=copy_properties,
                mandatory=True,
            )
        except (pika.exceptions.UnroutableError, pika.exceptions.NackError):
            _log("republish.failed", level=logging.ERROR, exchange=exchange)
            self._sleep(REPUBLISH_FAILURE_PAUSE_SECONDS)
            channel.basic_nack(delivery_tag=tag, requeue=True)
            return "republish_failed_requeued"
        channel.basic_ack(delivery_tag=tag)
        return success_outcome

"""Operator recovery tools: dead-letter replay and outbox requeue.

These commands run with a dedicated **operator** identity, never the worker's:

* RabbitMQ user ``sentinel-operator``: read the dead-letter queue, write the
  ``sentinel.scan-requests`` exchange, no configure permission;
* PostgreSQL login role in ``sentinel_operator``: EXECUTE on the ``ops.*`` functions only.

Every action is bounded (at most 100 items per call) and audited in
``ops.recovery_actions`` **before** it takes effect, with the operator name and reason.
Replay never bypasses deduplication or tenant verification: a replayed message is
consumed by a worker like any other and is checked against the worker receipts and the
authoritative outbox event. Message bodies are never logged or printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.messaging import contracts
from sentinel_worker.messaging.receipts import DatabaseSettings
from sentinel_worker.messaging.settings import DB_SSLMODE_VAR, PRODUCTION_SSL_MODES, SSL_MODES

OPERATOR_RABBITMQ_HOST_VAR = "SENTINEL_OPERATOR_RABBITMQ_HOST"
OPERATOR_RABBITMQ_PORT_VAR = "SENTINEL_OPERATOR_RABBITMQ_PORT"
OPERATOR_RABBITMQ_VHOST_VAR = "SENTINEL_OPERATOR_RABBITMQ_VHOST"
OPERATOR_RABBITMQ_USERNAME_VAR = "SENTINEL_OPERATOR_RABBITMQ_USERNAME"
OPERATOR_RABBITMQ_PASSWORD_VAR = "SENTINEL_OPERATOR_RABBITMQ_PASSWORD"  # noqa: S105
OPERATOR_DB_HOST_VAR = "SENTINEL_OPERATOR_DB_HOST"
OPERATOR_DB_PORT_VAR = "SENTINEL_OPERATOR_DB_PORT"
OPERATOR_DB_NAME_VAR = "SENTINEL_OPERATOR_DB_NAME"
OPERATOR_DB_USERNAME_VAR = "SENTINEL_OPERATOR_DB_USERNAME"
OPERATOR_DB_PASSWORD_VAR = "SENTINEL_OPERATOR_DB_PASSWORD"  # noqa: S105

MAX_BATCH = 100
OPERATOR_NAME = re.compile(r"[A-Za-z0-9._@-]{1,100}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_FAILURE_CODE = re.compile(r"[A-Z0-9_]{1,100}\Z")

REPLAY_AUDIT_HEADER = "x-sentinel-replay-audit-id"
# Broker-managed and transient-retry headers are not carried into a replay.
_DROPPED_HEADERS = (
    "x-death",
    "x-first-death-exchange",
    "x-first-death-queue",
    "x-first-death-reason",
    "x-last-death-exchange",
    "x-last-death-queue",
    "x-last-death-reason",
    "x-delivery-count",
)


def _topology() -> tuple[str, str, str, str, str]:
    topology = contracts.topology()
    route = topology["messages"]["scan.requested"]
    work_queue = next(
        binding["queue"]
        for binding in topology["bindings"]
        if binding["exchange"] == route["exchange"]
        and binding["routing_key"] == route["routing_key"]
    )
    arguments = next(q["arguments"] for q in topology["queues"] if q["name"] == work_queue)
    dead_letter_queue = next(
        binding["queue"]
        for binding in topology["bindings"]
        if binding["exchange"] == arguments["x-dead-letter-exchange"]
    )
    return (
        route["exchange"],
        route["routing_key"],
        dead_letter_queue,
        topology["headers"]["dead_letter_metadata"],
        topology["retry"]["count_header"],
    )


(
    SCAN_REQUESTS_EXCHANGE,
    SCAN_REQUESTED_ROUTING_KEY,
    DEAD_LETTER_QUEUE,
    DEAD_LETTER_HEADER,
    RETRY_COUNT_HEADER,
) = _topology()


def require_audit_fields(operator: str, reason: str) -> None:
    if not OPERATOR_NAME.match(operator or ""):
        raise ConfigurationError("--operator must be 1-100 characters: letters, digits, ._@-")
    if not reason or not reason.strip() or len(reason) > 500:
        raise ConfigurationError("--reason must be 1-500 characters")


def require_batch(limit: int) -> None:
    if not 1 <= limit <= MAX_BATCH:
        raise ConfigurationError(f"the batch size must be between 1 and {MAX_BATCH}")


@dataclass(frozen=True, slots=True)
class OperatorBrokerSettings:
    host: str
    port: int
    virtual_host: str
    username: str
    password: str = field(repr=False)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> OperatorBrokerSettings:
        env = os.environ if environ is None else environ
        username = env.get(OPERATOR_RABBITMQ_USERNAME_VAR, "").strip()
        password = env.get(OPERATOR_RABBITMQ_PASSWORD_VAR, "")
        if not username or not password:
            raise ConfigurationError(
                f"{OPERATOR_RABBITMQ_USERNAME_VAR} and {OPERATOR_RABBITMQ_PASSWORD_VAR} must be set"
            )
        return cls(
            host=env.get(OPERATOR_RABBITMQ_HOST_VAR, "localhost").strip() or "localhost",
            port=_port(env, OPERATOR_RABBITMQ_PORT_VAR, 5672),
            virtual_host=env.get(OPERATOR_RABBITMQ_VHOST_VAR, "/") or "/",
            username=username,
            password=password,
        )


def operator_database_settings(
    environment: Environment, environ: Mapping[str, str] | None = None
) -> DatabaseSettings:
    env = os.environ if environ is None else environ
    username = env.get(OPERATOR_DB_USERNAME_VAR, "").strip()
    password = env.get(OPERATOR_DB_PASSWORD_VAR, "")
    if not username or not password:
        raise ConfigurationError(
            f"{OPERATOR_DB_USERNAME_VAR} and {OPERATOR_DB_PASSWORD_VAR} must be set"
        )
    sslmode = env.get(DB_SSLMODE_VAR, "").strip() or (
        "verify-full" if environment is Environment.PRODUCTION else "prefer"
    )
    if sslmode not in SSL_MODES or (
        environment is Environment.PRODUCTION and sslmode not in PRODUCTION_SSL_MODES
    ):
        raise ConfigurationError(f"{DB_SSLMODE_VAR} is not permitted in this environment")
    return DatabaseSettings(
        host=env.get(OPERATOR_DB_HOST_VAR, "localhost").strip() or "localhost",
        port=_port(env, OPERATOR_DB_PORT_VAR, 5432),
        dbname=env.get(OPERATOR_DB_NAME_VAR, "").strip() or "sentinelpipe",
        user=username,
        password=password,
        sslmode=sslmode,
    )


def _port(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be an integer between 1 and 65535") from None
    if not 1 <= value <= 65535:
        raise ConfigurationError(f"{name} must be an integer between 1 and 65535")
    return value


# ---------------------------------------------------------------------------
# Dead-letter replay
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ReplayReport:
    replayed: int = 0
    stopped_reason: str | None = None
    items: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "replayed": self.replayed,
            "stopped_reason": self.stopped_reason,
            "items": self.items,
        }


def _metadata(
    headers: Mapping[str, Any] | None, message_id: str | None = None
) -> tuple[str | None, str | None]:
    """(event_id, failure_code) for the audit record; untrusted, format-checked.

    Worker dead letters carry the ``x-sentinel-dead-letter`` metadata. Messages the broker
    dead-lettered itself (delivery limit) only carry RabbitMQ's ``x-first-death-reason``;
    their event id is then taken from the AMQP ``message-id``.
    """
    raw = (headers or {}).get(DEAD_LETTER_HEADER)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        metadata = json.loads(raw) if isinstance(raw, str) else {}
    except ValueError:
        metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    event_id = metadata.get("event_id") or message_id
    code = metadata.get("failure_code")
    if code is None:
        reason = (headers or {}).get("x-first-death-reason")
        if isinstance(reason, bytes):
            reason = reason.decode("utf-8", errors="replace")
        code = reason.upper() if isinstance(reason, str) else None
    return (
        event_id if isinstance(event_id, str) and _UUID.match(event_id) else None,
        code if isinstance(code, str) and _FAILURE_CODE.match(code) else None,
    )


def replay_dead_letters(
    channel: Any,
    record_audit: Callable[[str | None, str, str | None], str],
    max_messages: int,
) -> ReplayReport:
    """Moves up to ``max_messages`` messages from the dead-letter queue back to the
    ``sentinel.scan-requests`` exchange, oldest first.

    For each message: audit (committed) → publish (persistent, mandatory, confirmed) →
    acknowledge the dead-letter copy. If auditing or publishing fails, the message is
    returned to the dead-letter queue and the run stops. A crash between publish and
    acknowledgment replays the message twice; workers absorb the duplicate.

    ``channel`` must have publisher confirms enabled.
    """
    import pika
    import pika.exceptions

    require_batch(max_messages)
    report = ReplayReport()
    for _ in range(max_messages):
        method, properties, body = channel.basic_get(DEAD_LETTER_QUEUE, auto_ack=False)
        if method is None:
            report.stopped_reason = "queue_empty"
            break
        digest = hashlib.sha256(body).hexdigest()
        event_id, failure_code = _metadata(properties.headers, properties.message_id)
        try:
            audit_id = record_audit(event_id, digest, failure_code)
        except Exception:
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            report.stopped_reason = "audit_failed"
            break
        headers = {
            key: value
            for key, value in (properties.headers or {}).items()
            if key not in _DROPPED_HEADERS and key != RETRY_COUNT_HEADER
        }
        headers[REPLAY_AUDIT_HEADER] = audit_id
        replay_properties = pika.BasicProperties(
            content_type=properties.content_type,
            content_encoding=properties.content_encoding,
            message_id=properties.message_id,
            correlation_id=properties.correlation_id,
            type=properties.type,
            timestamp=properties.timestamp,
            app_id=properties.app_id,
            headers=headers,
            delivery_mode=pika.DeliveryMode.Persistent,
        )
        try:
            channel.basic_publish(
                exchange=SCAN_REQUESTS_EXCHANGE,
                routing_key=SCAN_REQUESTED_ROUTING_KEY,
                body=body,
                properties=replay_properties,
                mandatory=True,
            )
        except (pika.exceptions.UnroutableError, pika.exceptions.NackError):
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            report.stopped_reason = "publish_not_confirmed"
            break
        channel.basic_ack(delivery_tag=method.delivery_tag)
        report.replayed += 1
        report.items.append(
            {
                "audit_id": audit_id,
                "event_id": event_id,
                "failure_code": failure_code,
                "message_sha256": digest,
            }
        )
    else:
        report.stopped_reason = "limit_reached"
    return report


def dead_letter_depth(channel: Any) -> int:
    """Ready messages in the dead-letter queue (passive declare)."""
    return int(channel.queue_declare(queue=DEAD_LETTER_QUEUE, passive=True).method.message_count)


# ---------------------------------------------------------------------------
# Outbox (control plane) through the audited ops.* functions
# ---------------------------------------------------------------------------


def outbox_summary(connection: Any) -> dict[str, Any]:
    row = connection.execute(
        "SELECT pending, failed, expired_leases, oldest_pending_age_seconds"
        " FROM ops.outbox_summary()"
    ).fetchone()
    return {
        "pending": row[0],
        "failed": row[1],
        "expired_leases": row[2],
        "oldest_pending_age_seconds": row[3],
    }


def list_failed_outbox_events(connection: Any, limit: int) -> list[dict[str, Any]]:
    require_batch(limit)
    rows = connection.execute(
        "SELECT event_id, event_type, attempts, last_error, failed_at"
        " FROM ops.list_failed_outbox_events(%s)",
        (limit,),
    ).fetchall()
    return [
        {
            "event_id": str(row[0]),
            "event_type": row[1],
            "attempts": row[2],
            "last_error": row[3],
            "failed_at": row[4].isoformat(),
        }
        for row in rows
    ]


def requeue_failed_outbox_events(
    connection: Any, operator: str, reason: str, event_ids: list[str] | None, limit: int
) -> list[str]:
    require_audit_fields(operator, reason)
    require_batch(limit)
    if event_ids is not None and (
        not 1 <= len(event_ids) <= MAX_BATCH or not all(_UUID.match(e) for e in event_ids)
    ):
        raise ConfigurationError(f"--event-id must be 1-{MAX_BATCH} lowercase UUIDs")
    with connection.transaction():
        rows = connection.execute(
            "SELECT event_id FROM ops.requeue_failed_outbox_events(%s, %s, %s::uuid[], %s)",
            (operator, reason, event_ids, limit),
        ).fetchall()
    return [str(row[0]) for row in rows]


def audit_dead_letter_replay(
    connection: Any, operator: str, reason: str
) -> Callable[[str | None, str, str | None], str]:
    require_audit_fields(operator, reason)

    def record(event_id: str | None, digest: str, failure_code: str | None) -> str:
        with connection.transaction():
            row = connection.execute(
                "SELECT ops.record_dead_letter_replay(%s, %s, %s::uuid, %s, %s)",
                (operator, reason, event_id, digest, failure_code),
            ).fetchone()
        return str(row[0])

    return record

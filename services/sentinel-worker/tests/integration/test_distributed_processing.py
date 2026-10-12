"""Shared PostgreSQL receipts, tenant verification, least privilege and recovery.

Real PostgreSQL (schema from the Flyway migrations, roles from provision-roles.sh) and
real RabbitMQ (provision.sh). Every worker in these tests uses its own connection and
store instance, as separate worker processes on separate hosts would.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter
from pathlib import Path
from typing import Any

import pika
import pika.exceptions
import psycopg
import pytest
from infrastructure import (
    ROUTE,
    TOPOLOGY,
    Broker,
    ControlPlane,
    SeededEvent,
    drain,
    publish,
    queue_depth,
    wait_for_depth,
)
from prometheus_client import generate_latest

from sentinel_worker import operations
from sentinel_worker.messaging.consumer import (
    DEAD_LETTER_EXCHANGE,
    DEAD_LETTER_HEADER,
    WORKER_QUEUE,
    ScanRequestConsumer,
)
from sentinel_worker.messaging.handler import Disposition, FailureCode, MessageHandler
from sentinel_worker.messaging.receipts import (
    DatabaseSettings,
    PostgresReceiptStore,
    Receipt,
    ReceiptStoreError,
    RecordOutcome,
)
from sentinel_worker.metrics import WorkerMetrics
from support import properties_for, scan_requested

pytestmark = pytest.mark.integration

DEAD_LETTER_QUEUE = next(
    b["queue"] for b in TOPOLOGY["bindings"] if b["exchange"] == DEAD_LETTER_EXCHANGE
)


def receipt_for(event: SeededEvent | dict[str, Any], body: bytes | None = None) -> Receipt:
    message = event.message if isinstance(event, SeededEvent) else event
    raw = event.body if isinstance(event, SeededEvent) and body is None else body
    assert raw is not None
    return Receipt(
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
            "message_sha256": hashlib.sha256(raw).hexdigest(),
            "outcome": "ACCEPTED",
            "received_at": "2026-10-10T12:00:00.000000Z",
            "worker_id": "sentinel-worker-it",
            "worker_version": "0.0.0",
        }
    )


def tampered(event: SeededEvent, **changes: Any) -> tuple[dict[str, Any], bytes]:
    message = {**event.message, **changes}
    return message, json.dumps(message).encode("utf-8")


def store(control_plane: ControlPlane, name: str = "worker") -> PostgresReceiptStore:
    return PostgresReceiptStore(control_plane.worker_settings(), f"sentinel-worker-{name}")


# ---------------------------------------------------------------------------
# Receipt store: deduplication and verification
# ---------------------------------------------------------------------------


def test_genuine_event_is_accepted_with_authoritative_identifiers(
    control_plane: ControlPlane,
) -> None:
    event = control_plane.seed_scan_event()
    with store(control_plane) as worker:
        assert worker.record(receipt_for(event)) is RecordOutcome.NEW

    rows = control_plane.receipt_rows(event.event_id)
    assert len(rows) == 1
    _, digest, organization_id, project_id, scan_id, outcome = rows[0]
    assert digest == hashlib.sha256(event.body).hexdigest()
    assert str(organization_id) == event.message["organization_id"]
    assert str(project_id) == event.message["project_id"]
    assert str(scan_id) == event.message["scan_id"]
    # Acceptance, not scan execution.
    assert outcome == "ACCEPTED"


def test_redelivery_to_a_different_worker_is_a_duplicate(control_plane: ControlPlane) -> None:
    event = control_plane.seed_scan_event()
    with store(control_plane, "a") as first, store(control_plane, "b") as second:
        assert first.record(receipt_for(event)) is RecordOutcome.NEW
        assert second.record(receipt_for(event)) is RecordOutcome.DUPLICATE
    assert len(control_plane.receipt_rows(event.event_id)) == 1


def test_concurrent_workers_accept_an_event_exactly_once(control_plane: ControlPlane) -> None:
    event = control_plane.seed_scan_event()
    workers = 8
    barrier = threading.Barrier(workers)
    outcomes: list[RecordOutcome] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        try:
            with store(control_plane, f"concurrent-{index}") as own:
                own.check()  # connect before the race starts
                barrier.wait(timeout=30)
                outcome = own.record(receipt_for(event))
            with lock:
                outcomes.append(outcome)
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    assert Counter(outcomes) == {RecordOutcome.NEW: 1, RecordOutcome.DUPLICATE: workers - 1}
    assert len(control_plane.receipt_rows(event.event_id)) == 1


def test_tampered_duplicate_is_a_conflict_and_the_original_receipt_is_kept(
    control_plane: ControlPlane,
) -> None:
    event = control_plane.seed_scan_event()
    message, body = tampered(event, branch="attacker-branch")
    with store(control_plane) as worker:
        assert worker.record(receipt_for(event)) is RecordOutcome.NEW
        assert worker.record(receipt_for(message, body)) is RecordOutcome.CONFLICT

    rows = control_plane.receipt_rows(event.event_id)
    assert [row[1] for row in rows] == [hashlib.sha256(event.body).hexdigest()]
    assert control_plane.rejections(hashlib.sha256(body).hexdigest()) == [("EVENT_ID_CONFLICT", 1)]


def test_a_forged_first_delivery_cannot_block_the_genuine_event(
    control_plane: ControlPlane,
) -> None:
    event = control_plane.seed_scan_event()
    message, body = tampered(event, commit_sha="f" * 40)
    with store(control_plane) as worker:
        assert worker.record(receipt_for(message, body)) is RecordOutcome.REJECTED_DIGEST_MISMATCH
        assert control_plane.receipt_rows(event.event_id) == []
        assert worker.record(receipt_for(event)) is RecordOutcome.NEW


def test_an_event_unknown_to_the_control_plane_is_rejected(control_plane: ControlPlane) -> None:
    forged = scan_requested()
    body = json.dumps(forged).encode("utf-8")
    with store(control_plane) as worker:
        assert worker.record(receipt_for(forged, body)) is RecordOutcome.REJECTED_UNKNOWN_EVENT
        assert worker.record(receipt_for(forged, body)) is RecordOutcome.REJECTED_UNKNOWN_EVENT
    assert control_plane.receipt_rows(forged["event_id"]) == []
    # Forensic record, deduplicated by content and reason.
    assert control_plane.rejections(hashlib.sha256(body).hexdigest()) == [("UNKNOWN_EVENT", 2)]


def test_payload_tenant_identifiers_are_never_trusted(control_plane: ControlPlane) -> None:
    victim = control_plane.seed_scan_event()
    attacker = control_plane.seed_scan_event()
    # Re-targets the attacker's genuine event at the victim's scan and organization.
    message, body = tampered(
        attacker,
        scan_id=victim.message["scan_id"],
        project_id=victim.message["project_id"],
        organization_id=victim.message["organization_id"],
    )
    with store(control_plane) as worker:
        assert worker.record(receipt_for(message, body)) is RecordOutcome.REJECTED_DIGEST_MISMATCH
    assert control_plane.receipt_rows(attacker.event_id) == []


def test_an_outbox_payload_inconsistent_with_the_scan_is_rejected(
    control_plane: ControlPlane,
) -> None:
    other = control_plane.seed_scan_event()
    # The committed payload itself names another organization (defense in depth against a
    # control-plane defect): the digest matches, the relationships do not.
    event = control_plane.seed_scan_event({"organization_id": other.message["organization_id"]})
    with store(control_plane) as worker:
        assert worker.record(receipt_for(event)) is RecordOutcome.REJECTED_RELATIONSHIP_MISMATCH
    assert control_plane.receipt_rows(event.event_id) == []


def test_a_rolled_back_receipt_transaction_leaves_no_receipt(control_plane: ControlPlane) -> None:
    event = control_plane.seed_scan_event()
    with control_plane.connect(control_plane.worker_settings()) as connection:
        transaction = connection.transaction()
        transaction.__enter__()
        outcome = connection.execute(
            "SELECT worker.record_receipt(%s::jsonb)", (receipt_for(event).canonical_json(),)
        ).fetchone()[0]
        assert outcome == "NEW"
        transaction.__exit__(RuntimeError, RuntimeError("rollback"), None)
    assert control_plane.receipt_rows(event.event_id) == []
    with store(control_plane) as worker:
        assert worker.record(receipt_for(event)) is RecordOutcome.NEW


def test_a_connection_lost_before_commit_records_nothing_and_a_retry_succeeds(
    control_plane: ControlPlane,
) -> None:
    event = control_plane.seed_scan_event()
    worker = store(control_plane, "outage")
    worker.check()
    with control_plane.admin() as admin, admin.transaction():
        # Blocks the worker's insert inside its transaction, then kills its connection:
        # the database becomes unreachable for it before the receipt can commit.
        admin.execute("LOCK TABLE worker.processing_receipts IN ACCESS EXCLUSIVE MODE")
        errors: list[BaseException] = []
        thread = threading.Thread(
            target=lambda: _record_expecting_error(worker, receipt_for(event), errors)
        )
        thread.start()
        admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
            " WHERE application_name = 'sentinel-worker-outage' AND wait_event_type = 'Lock'"
        )
        _wait_for_terminated(admin)
        thread.join(timeout=30)
    assert len(errors) == 1
    assert isinstance(errors[0], ReceiptStoreError)
    assert control_plane.receipt_rows(event.event_id) == []
    # The store reconnects on the next call; the receipt was never committed.
    assert worker.record(receipt_for(event)) is RecordOutcome.NEW
    worker.close()


def _record_expecting_error(
    worker: PostgresReceiptStore, receipt: Receipt, errors: list[BaseException]
) -> None:
    try:
        worker.record(receipt)
    except BaseException as exc:
        errors.append(exc)


def _wait_for_terminated(admin: psycopg.Connection[Any]) -> None:
    for _ in range(100):
        waiting = admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
            " WHERE application_name = 'sentinel-worker-outage' AND wait_event_type = 'Lock'"
        ).fetchall()
        if waiting:
            return
        threading.Event().wait(0.1)


def test_an_unreachable_database_is_a_bounded_transient_error(
    control_plane: ControlPlane,
) -> None:
    settings = control_plane.worker_settings()
    unreachable = DatabaseSettings(
        host=settings.host,
        port=1,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password,
        sslmode="disable",
        connect_timeout_seconds=2,
    )
    event = control_plane.seed_scan_event()
    with (
        PostgresReceiptStore(unreachable, "sentinel-worker-unreachable") as worker,
        pytest.raises(ReceiptStoreError) as excinfo,
    ):
        worker.record(receipt_for(event))
    # Error messages never echo credentials.
    assert settings.password not in str(excinfo.value)
    assert settings.password not in repr(unreachable)


def test_the_handler_dead_letters_every_rejection_with_its_code(
    control_plane: ControlPlane,
) -> None:
    event = control_plane.seed_scan_event()
    forged = scan_requested()
    message, body = tampered(event, branch="other")
    with store(control_plane) as worker:
        handler = MessageHandler(worker, "sentinel-worker-it")
        assert handler.handle(event.body, properties_for(event.message)).disposition is (
            Disposition.ACK
        )
        cases = [
            (json.dumps(forged).encode(), forged, FailureCode.UNKNOWN_EVENT),
            (body, message, FailureCode.EVENT_ID_CONFLICT),
        ]
        for raw, claimed, code in cases:
            result = handler.handle(raw, properties_for(claimed))
            assert result.disposition is Disposition.DEAD_LETTER
            assert result.failure_code is code


def test_record_receipt_rejects_oversized_or_malformed_documents(
    control_plane: ControlPlane,
) -> None:
    event = control_plane.seed_scan_event()
    oversized = {**receipt_for(event).document, "padding": "x" * 5000}
    with control_plane.connect(control_plane.worker_settings()) as connection:
        for document in (oversized, {"outcome": "ACCEPTED"}, [1, 2, 3]):
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                connection.execute(
                    "SELECT worker.record_receipt(%s::jsonb)", (json.dumps(document),)
                )
    assert control_plane.receipt_rows(event.event_id) == []


# ---------------------------------------------------------------------------
# Database least privilege
# ---------------------------------------------------------------------------

FORBIDDEN_FOR_WORKER = [
    "SELECT count(*) FROM scans",
    "SELECT count(*) FROM organizations",
    "SELECT count(*) FROM outbox_events",
    "SELECT count(*) FROM organization_memberships",
    "UPDATE scans SET branch = 'x'",
    "DELETE FROM outbox_events",
    "SELECT count(*) FROM worker.processing_receipts",
    "DELETE FROM worker.processing_receipts",
    "SELECT count(*) FROM worker.delivery_rejections",
    "SELECT worker.note_rejection('{}'::jsonb, 'UNKNOWN_EVENT')",
    "SELECT * FROM ops.outbox_summary()",
    "SELECT * FROM ops.requeue_failed_outbox_events('mallory', 'x', NULL, 1)",
    "SELECT count(*) FROM ops.recovery_actions",
    "CREATE TABLE public.attacker (id int)",
    "CREATE TABLE worker.attacker (id int)",
    "CREATE FUNCTION worker.attacker() RETURNS int LANGUAGE sql AS 'SELECT 1'",
]


@pytest.mark.parametrize("statement", FORBIDDEN_FOR_WORKER)
def test_the_worker_role_has_no_access_beyond_record_receipt(
    control_plane: ControlPlane, statement: str
) -> None:
    with (
        control_plane.connect(control_plane.worker_settings()) as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(statement)


FORBIDDEN_FOR_OPERATOR = [
    "SELECT count(*) FROM scans",
    "SELECT payload FROM outbox_events",
    "UPDATE outbox_events SET status = 'PENDING'",
    "SELECT count(*) FROM worker.processing_receipts",
    "INSERT INTO ops.recovery_actions (action, operator, reason) VALUES"
    " ('OUTBOX_REQUEUE_FAILED', 'mallory', 'forged audit')",
    "DELETE FROM ops.recovery_actions",
    "SELECT worker.record_receipt('{}'::jsonb)",
]


@pytest.mark.parametrize("statement", FORBIDDEN_FOR_OPERATOR)
def test_the_operator_role_is_limited_to_the_audited_functions(
    control_plane: ControlPlane, statement: str
) -> None:
    with (
        control_plane.connect(control_plane.operator_settings()) as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(statement)


# ---------------------------------------------------------------------------
# Outbox recovery (operator)
# ---------------------------------------------------------------------------


def _fail(control_plane: ControlPlane, event: SeededEvent) -> None:
    with control_plane.admin() as admin:
        admin.execute(
            "UPDATE outbox_events SET status = 'FAILED', attempts = 8,"
            " last_error = 'BROKER_UNAVAILABLE', updated_at = now() WHERE id = %s",
            (event.event_id,),
        )


def test_failed_outbox_events_are_requeued_bounded_and_audited(
    control_plane: ControlPlane,
) -> None:
    events = [control_plane.seed_scan_event() for _ in range(3)]
    for event in events:
        _fail(control_plane, event)
    with control_plane.connect(control_plane.operator_settings()) as connection:
        listed = {e["event_id"] for e in operations.list_failed_outbox_events(connection, 100)}
        assert {e.event_id for e in events} <= listed
        assert all("payload" not in e for e in operations.list_failed_outbox_events(connection, 5))

        requeued = operations.requeue_failed_outbox_events(
            connection, "alice", "INC-42 broker outage", [events[0].event_id], 10
        )
        assert requeued == [events[0].event_id]
        # Not FAILED any more: a second requeue is a no-op.
        assert (
            operations.requeue_failed_outbox_events(
                connection, "alice", "again", [events[0].event_id], 10
            )
            == []
        )
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            connection.execute(
                "SELECT * FROM ops.requeue_failed_outbox_events('alice', 'x', NULL, 101)"
            )
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            connection.execute(
                "SELECT * FROM ops.requeue_failed_outbox_events('alice', '  ', NULL, 1)"
            )

    with control_plane.admin() as admin:
        status, attempts, last_error = admin.execute(
            "SELECT status, attempts, last_error FROM outbox_events WHERE id = %s",
            (events[0].event_id,),
        ).fetchone()
        audit = admin.execute(
            "SELECT action, operator, reason, database_user FROM ops.recovery_actions"
            " WHERE event_id = %s",
            (events[0].event_id,),
        ).fetchall()
    assert (status, attempts, last_error) == ("PENDING", 0, None)
    assert audit == [
        ("OUTBOX_REQUEUE_FAILED", "alice", "INC-42 broker outage", "sentinel_operator_app")
    ]


# ---------------------------------------------------------------------------
# End to end through RabbitMQ with several workers
# ---------------------------------------------------------------------------


def _consumer(
    broker: Broker,
    control_plane: ControlPlane,
    name: str,
    metrics: WorkerMetrics | None = None,
) -> tuple[ScanRequestConsumer, PostgresReceiptStore]:
    own = store(control_plane, name)
    consumer = ScanRequestConsumer(
        broker.worker_settings(Path("unused")),
        MessageHandler(own, f"sentinel-worker-{name}"),
        f"sentinel-worker-{name}",
        sleep=lambda _: None,
        metrics=metrics,
    )
    return consumer, own


def _publish_event(broker: Broker, event: SeededEvent) -> None:
    publish(broker, event.message, body=event.body, parameters=broker.publisher_parameters())


@pytest.mark.usefixtures("empty_queues")
def test_two_concurrent_workers_share_deduplication(
    broker: Broker, control_plane: ControlPlane
) -> None:
    events = [control_plane.seed_scan_event() for _ in range(6)]
    for event in events:
        for _ in range(3):  # at-least-once: every event is delivered three times
            _publish_event(broker, event)

    workers = [_consumer(broker, control_plane, name) for name in ("host-a", "host-b")]
    threads = [threading.Thread(target=lambda c=c: c.run(inactivity_timeout=3)) for c, _ in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    for _, own in workers:
        own.close()

    totals: Counter[str] = Counter()
    for consumer, _ in workers:
        totals.update(consumer.stats.outcomes)
    assert totals == {"accepted": 6, "duplicate": 12}
    assert all(consumer.stats.total > 0 for consumer, _ in workers), "both workers consumed"
    for event in events:
        assert len(control_plane.receipt_rows(event.event_id)) == 1
    assert queue_depth(broker, WORKER_QUEUE) == 0


class SimulatedCrashError(Exception):
    pass


class CrashBeforeAck:
    def __init__(self, channel: Any) -> None:
        self._channel = channel

    def __getattr__(self, name: str) -> Any:
        return getattr(self._channel, name)

    def basic_ack(self, delivery_tag: int) -> None:
        raise SimulatedCrashError


@pytest.mark.usefixtures("empty_queues")
def test_a_crash_after_commit_before_ack_is_absorbed_by_another_worker(
    broker: Broker, control_plane: ControlPlane
) -> None:
    event = control_plane.seed_scan_event()
    _publish_event(broker, event)

    # Worker A commits the receipt and dies before acknowledging.
    connection = pika.BlockingConnection(broker.worker_parameters())
    channel = connection.channel()
    channel.confirm_delivery()
    method, properties, body = channel.basic_get(WORKER_QUEUE, auto_ack=False)
    crashed, crashed_store = _consumer(broker, control_plane, "crashed")
    with pytest.raises(SimulatedCrashError):
        crashed.process(CrashBeforeAck(channel), method, properties, body)  # type: ignore[arg-type]
    connection.close()
    crashed_store.close()
    assert len(control_plane.receipt_rows(event.event_id)) == 1
    assert queue_depth(broker, WORKER_QUEUE) == 1

    # Worker B (another host, another store instance) gets the redelivery.
    survivor, own = _consumer(broker, control_plane, "survivor")
    survivor.run(inactivity_timeout=2)
    own.close()
    assert survivor.stats.outcomes == {"duplicate": 1}
    assert len(control_plane.receipt_rows(event.event_id)) == 1


@pytest.mark.usefixtures("empty_queues")
def test_tampered_and_forged_messages_are_dead_lettered_and_counted(
    broker: Broker, control_plane: ControlPlane
) -> None:
    genuine = control_plane.seed_scan_event()
    message, body = tampered(genuine, organization_id=scan_requested()["organization_id"])
    forged = scan_requested()
    _publish_event(broker, genuine)
    publish(broker, message, body=body)
    publish(broker, forged)
    metrics = WorkerMetrics()

    consumer, own = _consumer(broker, control_plane, "metrics", metrics)
    consumer.run(inactivity_timeout=2)
    own.close()

    assert consumer.stats.outcomes == {"accepted": 1, "dead_lettered": 2}
    codes = sorted(
        json.loads(properties.headers[DEAD_LETTER_HEADER])["failure_code"]
        for properties, _ in drain(broker, DEAD_LETTER_QUEUE)
    )
    assert codes == ["EVENT_ID_CONFLICT", "UNKNOWN_EVENT"]
    exposition = generate_latest(metrics.registry).decode()
    assert 'sentinel_worker_messages_total{outcome="accepted"} 1.0' in exposition
    assert 'sentinel_worker_messages_total{outcome="dead_lettered"} 2.0' in exposition
    assert "sentinel_worker_rejected_tampered_messages_total 2.0" in exposition
    for identifier in (genuine.event_id, forged["event_id"], forged["organization_id"]):
        assert identifier not in exposition


# ---------------------------------------------------------------------------
# Dead-letter replay (operator)
# ---------------------------------------------------------------------------


def _dead_letter(broker: Broker, body: bytes, message: dict[str, Any], code: str) -> None:
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    channel.confirm_delivery()
    channel.basic_publish(
        DEAD_LETTER_EXCHANGE,
        "",
        body,
        pika.BasicProperties(
            message_id=message["event_id"],
            type="scan.requested.v1",
            content_type="application/json",
            delivery_mode=pika.DeliveryMode.Persistent,
            headers={
                DEAD_LETTER_HEADER: json.dumps(
                    {"event_id": message["event_id"], "failure_code": code}
                ),
                "x-sentinel-retry-count": 5,
            },
        ),
        mandatory=True,
    )
    connection.close()


@pytest.mark.usefixtures("empty_queues")
def test_dead_letter_replay_is_audited_and_never_bypasses_verification(
    broker: Broker, control_plane: ControlPlane
) -> None:
    genuine = control_plane.seed_scan_event()
    message, body = tampered(genuine, branch="attacker")
    _dead_letter(broker, genuine.body, genuine.message, "TRANSIENT_RETRIES_EXHAUSTED")
    _dead_letter(broker, body, message, "DIGEST_MISMATCH")

    amqp = pika.BlockingConnection(broker.operator_parameters())
    channel = amqp.channel()
    channel.confirm_delivery()
    with control_plane.connect(control_plane.operator_settings()) as database:
        audit = operations.audit_dead_letter_replay(database, "bob", "INC-7 database outage")
        report = operations.replay_dead_letters(channel, audit, max_messages=10)
    amqp.close()

    assert report.replayed == 2
    assert report.stopped_reason == "queue_empty"
    assert queue_depth(broker, DEAD_LETTER_QUEUE) == 0
    with control_plane.admin() as admin:
        audited = admin.execute(
            "SELECT detail, message_sha256 FROM ops.recovery_actions"
            " WHERE action = 'DEAD_LETTER_REPLAY' AND event_id = %s ORDER BY performed_at",
            (genuine.event_id,),
        ).fetchall()
    assert audited == [
        ("TRANSIENT_RETRIES_EXHAUSTED", hashlib.sha256(genuine.body).hexdigest()),
        ("DIGEST_MISMATCH", hashlib.sha256(body).hexdigest()),
    ]

    consumer, own = _consumer(broker, control_plane, "after-replay")
    consumer.run(inactivity_timeout=2)
    own.close()
    # The genuine event is accepted once. The tampered copy is rejected again: its
    # event_id now has an accepted receipt with a different digest (EVENT_ID_CONFLICT).
    assert consumer.stats.outcomes == {"accepted": 1, "dead_lettered": 1}
    (properties, _), *_ = drain(broker, DEAD_LETTER_QUEUE)
    assert json.loads(properties.headers[DEAD_LETTER_HEADER])["failure_code"] == (
        "EVENT_ID_CONFLICT"
    )
    assert "x-sentinel-retry-count" not in properties.headers
    assert operations.REPLAY_AUDIT_HEADER in properties.headers


@pytest.mark.usefixtures("empty_queues")
def test_replay_without_a_committed_audit_record_does_not_move_the_message(
    broker: Broker,
) -> None:
    forged = scan_requested()
    body = json.dumps(forged).encode()
    _dead_letter(broker, body, forged, "UNKNOWN_EVENT")

    def failing_audit(*_: Any) -> str:
        raise psycopg.OperationalError("database unavailable")

    amqp = pika.BlockingConnection(broker.operator_parameters())
    channel = amqp.channel()
    channel.confirm_delivery()
    report = operations.replay_dead_letters(channel, failing_audit, max_messages=5)
    amqp.close()

    assert report.replayed == 0
    assert report.stopped_reason == "audit_failed"
    assert report.items == []
    # The requeue (nack or channel close) is applied asynchronously by the quorum queue.
    wait_for_depth(broker, DEAD_LETTER_QUEUE, 1)
    assert queue_depth(broker, WORKER_QUEUE) == 0
    # The dead-letter copy is returned unchanged: same body and failure metadata, and no
    # replay audit header (nothing was audited, so nothing may be marked as replayed).
    (properties, requeued), *rest = drain(broker, DEAD_LETTER_QUEUE)
    assert rest == []
    assert requeued == body
    assert json.loads(properties.headers[DEAD_LETTER_HEADER])["failure_code"] == "UNKNOWN_EVENT"
    assert operations.REPLAY_AUDIT_HEADER not in properties.headers


@pytest.mark.usefixtures("empty_queues")
def test_the_dead_letter_queue_never_drops_messages_after_many_redeliveries(
    broker: Broker,
) -> None:
    # RabbitMQ 4 quorum queues default to delivery-limit 20 and the dead-letter queue has
    # no dead-letter exchange, so without the provisioned policy (delivery-limit -1) a
    # message returned 20 times by inspection or failed replays would be DROPPED.
    forged = scan_requested()
    _dead_letter(broker, json.dumps(forged).encode(), forged, "UNKNOWN_EVENT")
    connection = pika.BlockingConnection(broker.operator_parameters())
    channel = connection.channel()
    for _ in range(25):
        method, _, _ = channel.basic_get(DEAD_LETTER_QUEUE, auto_ack=False)
        assert method is not None, "dead-lettered message was discarded"
        channel.basic_nack(method.delivery_tag, requeue=True)
    connection.close()
    wait_for_depth(broker, DEAD_LETTER_QUEUE, 1)


# ---------------------------------------------------------------------------
# Broker least privilege
# ---------------------------------------------------------------------------


def _refused(parameters: pika.ConnectionParameters, action: Any) -> None:
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    with pytest.raises(pika.exceptions.ChannelClosedByBroker) as excinfo:
        action(channel)
    assert excinfo.value.reply_code == 403
    connection.close()


@pytest.mark.usefixtures("empty_queues")
def test_the_publisher_identity_can_only_publish_scan_requests(broker: Broker) -> None:
    publisher = broker.publisher_parameters()
    publish(broker, scan_requested(), parameters=publisher)
    assert queue_depth(broker, WORKER_QUEUE) == 1

    # No topology changes (configure), no reads, no writes to other exchanges.
    _refused(publisher, lambda c: c.queue_declare("attacker-queue", durable=True))
    _refused(publisher, lambda c: c.exchange_declare("attacker-exchange", "fanout"))
    _refused(publisher, lambda c: c.queue_delete(WORKER_QUEUE))
    _refused(publisher, lambda c: c.exchange_delete(ROUTE["exchange"]))
    _refused(publisher, lambda c: c.queue_purge(WORKER_QUEUE))
    _refused(publisher, lambda c: c.basic_get(WORKER_QUEUE, auto_ack=False))
    _refused(publisher, lambda c: c.basic_get(DEAD_LETTER_QUEUE, auto_ack=False))
    _refused(
        publisher,
        lambda c: (c.confirm_delivery(), c.basic_publish(DEAD_LETTER_EXCHANGE, "", b"{}")),
    )
    # RabbitMQ 4 refuses even a passive declare without a permission on the queue, so the
    # publisher cannot observe queue depths either (monitoring uses the broker's metrics).
    _refused(publisher, lambda c: c.queue_declare(DEAD_LETTER_QUEUE, passive=True))


def test_the_operator_identity_can_only_replay_dead_letters(broker: Broker) -> None:
    operator = broker.operator_parameters()
    _refused(operator, lambda c: c.basic_get(WORKER_QUEUE, auto_ack=False))
    _refused(operator, lambda c: c.queue_declare("attacker-queue", durable=True))
    _refused(operator, lambda c: c.queue_delete(DEAD_LETTER_QUEUE))
    _refused(operator, lambda c: c.queue_purge(WORKER_QUEUE))
    _refused(
        operator,
        lambda c: (c.confirm_delivery(), c.basic_publish(DEAD_LETTER_EXCHANGE, "", b"{}")),
    )


@pytest.mark.usefixtures("empty_queues")
def test_read_permission_includes_purge_a_documented_broker_limitation(broker: Broker) -> None:
    # RabbitMQ authorizes queue.purge with the READ permission, so an identity that may
    # consume a queue may also purge it. Vhost permissions cannot separate the two; see
    # docs/runbooks/messaging.md ("Known limitations") for the compensating controls.
    forged = scan_requested()
    _dead_letter(broker, json.dumps(forged).encode(), forged, "UNKNOWN_EVENT")
    connection = pika.BlockingConnection(broker.operator_parameters())
    connection.channel().queue_purge(DEAD_LETTER_QUEUE)
    connection.close()
    assert queue_depth(broker, DEAD_LETTER_QUEUE) == 0


def test_the_worker_identity_cannot_alter_topology(broker: Broker) -> None:
    worker = broker.worker_parameters()
    _refused(worker, lambda c: c.queue_delete(WORKER_QUEUE))
    _refused(worker, lambda c: c.queue_purge(DEAD_LETTER_QUEUE))
    _refused(worker, lambda c: c.exchange_delete(DEAD_LETTER_EXCHANGE))
    _refused(worker, lambda c: c.queue_bind(WORKER_QUEUE, DEAD_LETTER_EXCHANGE))

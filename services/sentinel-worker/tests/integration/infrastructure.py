"""Real RabbitMQ and PostgreSQL for integration tests (Testcontainers).

Images are pinned to the same digests as compose.yaml and the Java tests. Both are
provisioned with the **production provisioning artifacts**, so the tests verify exactly
what operators run:

* RabbitMQ: infrastructure/docker/rabbitmq/provision.sh (topology from definitions.json,
  least-privileged publisher, worker and operator users);
* PostgreSQL: the Flyway migrations V001..V005 from services/sentinel-api, then
  infrastructure/docker/postgres/provision-roles.sh (worker and operator login roles).

Credentials are random per run, hexadecimal (rabbitmqctl parses a leading "-" as an
option), and never printed.
"""

from __future__ import annotations

import io
import json
import secrets
import tarfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pika
import psycopg

from sentinel_worker.messaging import contracts
from sentinel_worker.messaging.receipts import DatabaseSettings
from sentinel_worker.messaging.settings import ConsumerSettings

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
MIGRATIONS_DIR = (
    REPOSITORY_ROOT
    / "services"
    / "sentinel-api"
    / "src"
    / "main"
    / "resources"
    / "db"
    / "migration"
)
RABBITMQ_PROVISIONING_DIR = REPOSITORY_ROOT / "infrastructure" / "docker" / "rabbitmq"
POSTGRES_PROVISIONING_DIR = REPOSITORY_ROOT / "infrastructure" / "docker" / "postgres"

# rabbitmq:4.3.6-management-alpine, identical to compose.yaml and TestcontainersConfiguration.
RABBITMQ_IMAGE = "rabbitmq@sha256:3ef7f7e89fed709a78f79b8b5f4e30e1312a1d4089da752e23595566d9d61a95"
# postgres:18.6-alpine, identical to compose.yaml and TestcontainersConfiguration.
POSTGRES_IMAGE = "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873"

TOPOLOGY = contracts.topology()
ROUTE = TOPOLOGY["messages"]["scan.requested"]

WORKER_USER = "sentinel-worker"
PUBLISHER_USER = "sentinel-publisher"
OPERATOR_USER = "sentinel-operator"
WORKER_DB_USER = "sentinel_worker_app"
OPERATOR_DB_USER = "sentinel_operator_app"


def new_password() -> str:
    return secrets.token_hex(24)


def copy_directory(container: Any, source: Path, target: str) -> None:
    """Copies ``source``'s files into ``target`` (created) in a running container."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path in sorted(source.iterdir()):
            if path.is_file():
                data = path.read_bytes().replace(b"\r\n", b"\n")
                info = tarfile.TarInfo(name=path.name)
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
    wrapped = container.get_wrapped_container()
    wrapped.exec_run(["mkdir", "-p", target])
    wrapped.put_archive(target, buffer.getvalue())


def run_script(
    container: Any, script: str, environment: dict[str, str], secrets_: list[str]
) -> str:
    result = container.get_wrapped_container().exec_run(["sh", script], environment=environment)
    output = result.output.decode("utf-8", errors="replace")
    for secret in secrets_:
        output = output.replace(secret, "<redacted>")
    if result.exit_code != 0:
        raise RuntimeError(f"{script} exited with {result.exit_code}: {output}")
    return output


# ---------------------------------------------------------------------------
# RabbitMQ
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Broker:
    admin: pika.ConnectionParameters
    host: str
    port: int
    worker_password: str
    publisher_password: str
    operator_password: str
    container: Any

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

    def parameters(self, user: str, password: str) -> pika.ConnectionParameters:
        return pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            credentials=pika.PlainCredentials(user, password),
            connection_attempts=3,
            retry_delay=1,
        )

    def worker_parameters(self) -> pika.ConnectionParameters:
        return self.parameters(WORKER_USER, self.worker_password)

    def publisher_parameters(self) -> pika.ConnectionParameters:
        return self.parameters(PUBLISHER_USER, self.publisher_password)

    def operator_parameters(self) -> pika.ConnectionParameters:
        return self.parameters(OPERATOR_USER, self.operator_password)


def provision_broker(container: Any) -> Broker:
    copy_directory(container, RABBITMQ_PROVISIONING_DIR, "/etc/sentinelpipe/rabbitmq")
    worker, publisher, operator = new_password(), new_password(), new_password()
    run_script(
        container,
        "/etc/sentinelpipe/rabbitmq/provision.sh",
        {
            "SENTINEL_RABBITMQ_PUBLISHER_USERNAME": PUBLISHER_USER,
            "SENTINEL_RABBITMQ_PUBLISHER_PASSWORD": publisher,
            "SENTINEL_WORKER_RABBITMQ_USERNAME": WORKER_USER,
            "SENTINEL_WORKER_RABBITMQ_PASSWORD": worker,
            "SENTINEL_OPERATOR_RABBITMQ_USERNAME": OPERATOR_USER,
            "SENTINEL_OPERATOR_RABBITMQ_PASSWORD": operator,
        },
        [worker, publisher, operator],
    )
    admin = container.get_connection_params()
    return Broker(admin, admin.host, int(admin.port), worker, publisher, operator, container)


def publish(
    broker: Broker,
    message: dict[str, Any],
    body: bytes | None = None,
    parameters: pika.ConnectionParameters | None = None,
) -> None:
    """Publishes like the control plane: persistent, confirmed, mandatory."""
    connection = pika.BlockingConnection(parameters or broker.admin)
    channel = connection.channel()
    channel.confirm_delivery()
    channel.basic_publish(
        exchange=ROUTE["exchange"],
        routing_key=ROUTE["routing_key"],
        body=json.dumps(message).encode("utf-8") if body is None else body,
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


def purge_all(broker: Broker) -> None:
    connection = pika.BlockingConnection(broker.admin)
    channel = connection.channel()
    for queue in TOPOLOGY["queues"]:
        channel.queue_purge(queue["name"])
    connection.close()


# ---------------------------------------------------------------------------
# PostgreSQL (control-plane schema)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeededEvent:
    """A scan.requested event committed by the 'control plane', with its exact body."""

    message: dict[str, Any]
    body: bytes

    @property
    def event_id(self) -> str:
        return str(self.message["event_id"])


@dataclass(frozen=True)
class ControlPlane:
    host: str
    port: int
    dbname: str
    admin_user: str
    admin_password: str
    worker_password: str
    operator_password: str
    container: Any

    def _settings(self, user: str, password: str) -> DatabaseSettings:
        return DatabaseSettings(
            host=self.host,
            port=self.port,
            dbname=self.dbname,
            user=user,
            password=password,
            sslmode="disable",
        )

    def worker_settings(self) -> DatabaseSettings:
        return self._settings(WORKER_DB_USER, self.worker_password)

    def operator_settings(self) -> DatabaseSettings:
        return self._settings(OPERATOR_DB_USER, self.operator_password)

    def admin_settings(self) -> DatabaseSettings:
        return self._settings(self.admin_user, self.admin_password)

    def connect(self, settings: DatabaseSettings) -> psycopg.Connection[Any]:
        return psycopg.connect(**settings.connection_kwargs("sentinel-tests"))

    def admin(self) -> psycopg.Connection[Any]:
        return self.connect(self.admin_settings())

    def seed_scan_event(self, payload_overrides: dict[str, Any] | None = None) -> SeededEvent:
        """Inserts organization, project, scan and outbox event like the control plane,
        and returns the exact message body the publisher would send (payload::text)."""
        organization_id, project_id, scan_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        event_id, correlation_id = uuid.uuid4(), uuid.uuid4()
        suffix = uuid.uuid4().hex[:10]
        now = datetime.now(UTC)
        commit_sha = secrets.token_hex(20)
        payload: dict[str, Any] = {
            "event_id": str(event_id),
            "event_type": "scan.requested",
            "schema_version": 1,
            "occurred_at": now.isoformat().replace("+00:00", "Z"),
            "correlation_id": str(correlation_id),
            "scan_id": str(scan_id),
            "project_id": str(project_id),
            "organization_id": str(organization_id),
            "commit_sha": commit_sha,
            "branch": "main",
            "trigger_type": "PUSH",
            "repository": {"provider": "GITHUB", "owner": "acme", "name": f"repo-{suffix}"},
        }
        payload.update(payload_overrides or {})
        with self.admin() as connection, connection.transaction():
            connection.execute(
                "INSERT INTO organizations (id, name, slug, version, created_at, updated_at)"
                " VALUES (%s, %s, %s, 0, %s, %s)",
                (organization_id, f"Org {suffix}", f"org-{suffix}", now, now),
            )
            connection.execute(
                "INSERT INTO projects (id, organization_id, name, repository_provider,"
                " repository_owner, repository_name, default_branch, enabled, version,"
                " created_at, updated_at)"
                " VALUES (%s, %s, %s, 'GITHUB', 'acme', %s, 'main', true, 0, %s, %s)",
                (project_id, organization_id, f"Project {suffix}", f"repo-{suffix}", now, now),
            )
            connection.execute(
                "INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type,"
                " execution_status, security_decision, version, requested_at, updated_at)"
                " VALUES (%s, %s, %s, 'main', 'PUSH', 'QUEUED', 'PENDING', 0, %s, %s)",
                (scan_id, project_id, commit_sha, now, now),
            )
            connection.execute(
                "INSERT INTO outbox_events (id, event_type, schema_version, aggregate_type,"
                " aggregate_id, organization_id, correlation_id, payload, status, attempts,"
                " next_attempt_at, created_at, updated_at)"
                " VALUES (%s, 'scan.requested', 1, 'scan', %s, %s, %s, %s::jsonb, 'PENDING', 0,"
                " %s, %s, %s)",
                (
                    event_id,
                    scan_id,
                    organization_id,
                    correlation_id,
                    json.dumps(payload),
                    now,
                    now,
                    now,
                ),
            )
            body = connection.execute(
                "SELECT payload::text FROM outbox_events WHERE id = %s", (event_id,)
            ).fetchone()[0]
        return SeededEvent(message=json.loads(body), body=body.encode("utf-8"))

    def receipt_rows(self, event_id: str) -> list[tuple[Any, ...]]:
        with self.admin() as connection:
            return connection.execute(
                "SELECT event_id, message_sha256, organization_id, project_id, scan_id, outcome"
                " FROM worker.processing_receipts WHERE event_id = %s",
                (event_id,),
            ).fetchall()

    def rejections(self, sha256: str) -> list[tuple[Any, ...]]:
        with self.admin() as connection:
            return connection.execute(
                "SELECT reason, occurrences FROM worker.delivery_rejections"
                " WHERE message_sha256 = %s ORDER BY reason",
                (sha256,),
            ).fetchall()


def provision_control_plane(container: Any, admin_user: str, admin_password: str) -> ControlPlane:
    host = container.get_container_host_ip()
    port = int(container.get_exposed_port(5432))
    dbname = "sentinelpipe"
    admin = DatabaseSettings(
        host=host,
        port=port,
        dbname=dbname,
        user=admin_user,
        password=admin_password,
        sslmode="disable",
    )
    with psycopg.connect(**admin.connection_kwargs("sentinel-tests-migrate")) as connection:
        for script in sorted(MIGRATIONS_DIR.glob("V*.sql")):
            # No parameters: psycopg sends the script with the simple query protocol.
            connection.execute(script.read_text(encoding="utf-8").encode("utf-8"))
    copy_directory(container, POSTGRES_PROVISIONING_DIR, "/etc/sentinelpipe/postgres")
    worker, operator = new_password(), new_password()
    run_script(
        container,
        "/etc/sentinelpipe/postgres/provision-roles.sh",
        {
            "SENTINEL_WORKER_DB_USERNAME": WORKER_DB_USER,
            "SENTINEL_WORKER_DB_PASSWORD": worker,
            "SENTINEL_OPERATOR_DB_USERNAME": OPERATOR_DB_USER,
            "SENTINEL_OPERATOR_DB_PASSWORD": operator,
        },
        [worker, operator],
    )
    return ControlPlane(host, port, dbname, admin_user, admin_password, worker, operator, container)

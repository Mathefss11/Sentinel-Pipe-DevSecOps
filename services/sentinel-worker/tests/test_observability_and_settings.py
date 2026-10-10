"""Worker metrics, receipt-store settings and operator-tool guards (no infrastructure)."""

from __future__ import annotations

import json
import re

import pytest
from prometheus_client import generate_latest

from sentinel_worker import cli, operations
from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.messaging.receipts import DatabaseSettings
from sentinel_worker.messaging.settings import ReceiptBackend, ReceiptStoreSettings
from sentinel_worker.metrics import (
    FAILURE_CODES,
    OUTCOMES,
    MetricsSettings,
    WorkerMetrics,
)

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# --- metrics -----------------------------------------------------------------------


def test_metrics_count_outcomes_dead_letters_tampering_and_store_errors() -> None:
    metrics = WorkerMetrics()
    metrics.observe("accepted", None, store_error=False)
    metrics.observe("duplicate", None, store_error=False)
    metrics.observe("dead_lettered", "DIGEST_MISMATCH", store_error=False)
    metrics.observe("dead_lettered", "SCHEMA_VIOLATION", store_error=False)
    metrics.observe("retry_scheduled", None, store_error=True)

    text = generate_latest(metrics.registry).decode()
    assert 'sentinel_worker_messages_total{outcome="accepted"} 1.0' in text
    assert 'sentinel_worker_messages_total{outcome="dead_lettered"} 2.0' in text
    assert 'sentinel_worker_dead_letters_total{failure_code="DIGEST_MISMATCH"} 1.0' in text
    assert "sentinel_worker_rejected_tampered_messages_total 1.0" in text
    assert "sentinel_worker_receipt_store_errors_total 1.0" in text


def test_metric_labels_are_a_fixed_low_cardinality_set() -> None:
    metrics = WorkerMetrics()
    with pytest.raises(ValueError, match="outcome"):
        metrics.observe("6e8cec90-7324-4ff0-aa53-b4605446eb8c", None, store_error=False)
    with pytest.raises(ValueError, match="failure code"):
        metrics.observe("dead_lettered", "org-1234", store_error=False)

    text = generate_latest(metrics.registry).decode()
    labels = set(re.findall(r'(\w+)="([^"]*)"', text))
    assert {key for key, _ in labels} <= {"outcome", "failure_code"}
    assert {value for _, value in labels} <= OUTCOMES | FAILURE_CODES
    assert not UUID.search(text)


def test_metrics_server_is_disabled_by_default() -> None:
    assert MetricsSettings.from_env({}).port is None


@pytest.mark.parametrize("address", ["127.0.0.1", "127.0.0.9", "::1"])
def test_metrics_server_binds_only_to_loopback(address: str) -> None:
    settings = MetricsSettings.from_env(
        {"SENTINEL_WORKER_METRICS_PORT": "9465", "SENTINEL_WORKER_METRICS_ADDRESS": address}
    )
    assert (settings.port, settings.address) == (9465, address)


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "10.0.0.5", "localhost", "metrics.example"])  # noqa: S104
def test_metrics_server_rejects_non_loopback_addresses(address: str) -> None:
    with pytest.raises(ConfigurationError, match="loopback"):
        MetricsSettings.from_env(
            {"SENTINEL_WORKER_METRICS_PORT": "9465", "SENTINEL_WORKER_METRICS_ADDRESS": address}
        )


@pytest.mark.parametrize("port", ["0", "65536", "abc"])
def test_metrics_port_is_validated(port: str) -> None:
    with pytest.raises(ConfigurationError):
        MetricsSettings.from_env({"SENTINEL_WORKER_METRICS_PORT": port})


# --- receipt store settings --------------------------------------------------------

DB = {
    "SENTINEL_WORKER_DB_USERNAME": "sentinel_worker_app",
    "SENTINEL_WORKER_DB_PASSWORD": "pw-secret",
}


def test_postgres_is_the_default_backend() -> None:
    settings = ReceiptStoreSettings.from_env(Environment.DEVELOPMENT, DB)
    assert settings.backend is ReceiptBackend.POSTGRES
    assert settings.database is not None
    assert settings.database.dbname == "sentinelpipe"
    assert settings.database.sslmode == "prefer"


def test_postgres_credentials_are_required_and_never_echoed() -> None:
    with pytest.raises(ConfigurationError, match="SENTINEL_WORKER_DB_USERNAME"):
        ReceiptStoreSettings.from_env(Environment.DEVELOPMENT, {})
    with pytest.raises(ConfigurationError, match="SENTINEL_WORKER_DB_PASSWORD"):
        ReceiptStoreSettings.from_env(
            Environment.DEVELOPMENT, {"SENTINEL_WORKER_DB_USERNAME": "worker"}
        )
    settings = ReceiptStoreSettings.from_env(Environment.DEVELOPMENT, DB)
    assert "pw-secret" not in repr(settings)


@pytest.mark.parametrize("environment", [Environment.CI, Environment.PRODUCTION])
def test_the_sqlite_store_is_refused_outside_development(environment: Environment) -> None:
    with pytest.raises(ConfigurationError, match="development"):
        ReceiptStoreSettings.from_env(environment, {"SENTINEL_WORKER_RECEIPT_BACKEND": "sqlite"})


def test_the_sqlite_store_is_available_for_isolated_development() -> None:
    settings = ReceiptStoreSettings.from_env(
        Environment.DEVELOPMENT, {"SENTINEL_WORKER_RECEIPT_BACKEND": "sqlite"}
    )
    assert settings.backend is ReceiptBackend.SQLITE
    assert settings.database is None


def test_production_requires_verified_tls_to_the_database() -> None:
    assert ReceiptStoreSettings.from_env(Environment.PRODUCTION, DB).database.sslmode == (  # type: ignore[union-attr]
        "verify-full"
    )
    for mode in ("disable", "prefer", "require"):
        with pytest.raises(ConfigurationError, match="production"):
            ReceiptStoreSettings.from_env(
                Environment.PRODUCTION, {**DB, "SENTINEL_WORKER_DB_SSLMODE": mode}
            )


def test_database_connections_have_bounded_timeouts() -> None:
    kwargs = DatabaseSettings(
        host="db", port=5432, dbname="sentinelpipe", user="worker", password="pw"
    ).connection_kwargs("sentinel-worker-x")
    assert kwargs["connect_timeout"] == 5
    assert "statement_timeout=5000" in kwargs["options"]
    assert "lock_timeout=5000" in kwargs["options"]
    assert "idle_in_transaction_session_timeout" in kwargs["options"]


# --- operator tools ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("operator", "reason"),
    [("", "reason"), ("bad name", "reason"), ("x" * 101, "reason"), ("alice", ""), ("alice", " ")],
)
def test_recovery_actions_require_a_valid_operator_and_reason(operator: str, reason: str) -> None:
    with pytest.raises(ConfigurationError):
        operations.require_audit_fields(operator, reason)


@pytest.mark.parametrize("limit", [0, 101])
def test_recovery_batches_are_bounded(limit: int) -> None:
    with pytest.raises(ConfigurationError):
        operations.require_batch(limit)


def test_dead_letter_metadata_is_parsed_defensively() -> None:
    header = operations.DEAD_LETTER_HEADER
    good = {"event_id": "6e8cec90-7324-4ff0-aa53-b4605446eb8c", "failure_code": "UNKNOWN_EVENT"}
    assert operations._metadata({header: json.dumps(good)}) == (
        good["event_id"],
        "UNKNOWN_EVENT",
    )
    hostile = {"event_id": "'; DROP TABLE x; --", "failure_code": "lower case"}
    assert operations._metadata({header: json.dumps(hostile)}) == (None, None)
    assert operations._metadata({header: "not json"}) == (None, None)
    assert operations._metadata(None) == (None, None)


def test_broker_dead_letters_are_audited_by_message_id_and_death_reason() -> None:
    event_id = "6e8cec90-7324-4ff0-aa53-b4605446eb8c"
    headers = {"x-first-death-reason": "delivery_limit"}
    assert operations._metadata(headers, event_id) == (event_id, "DELIVERY_LIMIT")
    assert operations._metadata(headers, "not-a-uuid") == (None, "DELIVERY_LIMIT")


def test_operator_commands_fail_closed_without_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in [
        "SENTINEL_OPERATOR_DB_USERNAME",
        "SENTINEL_OPERATOR_DB_PASSWORD",
        "SENTINEL_OPERATOR_RABBITMQ_USERNAME",
        "SENTINEL_OPERATOR_RABBITMQ_PASSWORD",
    ]:
        monkeypatch.delenv(name, raising=False)
    code = cli.main(["dlq-replay", "--operator", "alice", "--reason", "INC-1"])
    assert code == cli.EXIT_CONFIGURATION
    assert "must be set" in capsys.readouterr().err


def test_operator_commands_require_an_audit_reason(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["outbox-requeue-failed", "--operator", "alice", "--reason", " "])
    assert code == cli.EXIT_CONFIGURATION
    assert "--reason" in capsys.readouterr().err

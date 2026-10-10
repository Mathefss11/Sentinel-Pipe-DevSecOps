"""Worker metrics (Prometheus text exposition via ``prometheus-client``).

Labels are low-cardinality enumerations only (outcomes and sanitized failure codes);
event, scan, project and organization identifiers and payload content are never used as
labels. Every label value is validated against a fixed set, so a bug can never turn an
identifier into a time series.

The HTTP exposition server is **off by default**. When enabled
(``SENTINEL_WORKER_METRICS_PORT``) it binds to a literal loopback address only
(``SENTINEL_WORKER_METRICS_ADDRESS``, default ``127.0.0.1``); scraping from another host
requires a local agent or an authenticated tunnel. See docs/runbooks/observability.md.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, start_http_server

from sentinel_worker.config import ConfigurationError

PORT_VAR = "SENTINEL_WORKER_METRICS_PORT"
ADDRESS_VAR = "SENTINEL_WORKER_METRICS_ADDRESS"

OUTCOMES = frozenset(
    {"accepted", "duplicate", "dead_lettered", "retry_scheduled", "republish_failed_requeued"}
)
FAILURE_CODES = frozenset(
    {
        "MESSAGE_TOO_LARGE",
        "INVALID_ENCODING",
        "INVALID_JSON",
        "SCHEMA_VIOLATION",
        "PROPERTIES_MISMATCH",
        "EVENT_ID_CONFLICT",
        "UNKNOWN_EVENT",
        "DIGEST_MISMATCH",
        "RELATIONSHIP_MISMATCH",
        "TRANSIENT_RETRIES_EXHAUSTED",
    }
)
#: Failure codes that indicate forged or tampered messages.
TAMPERING_CODES = frozenset(
    {"EVENT_ID_CONFLICT", "UNKNOWN_EVENT", "DIGEST_MISMATCH", "RELATIONSHIP_MISMATCH"}
)


class WorkerMetrics:
    """Counters for one worker process, in their own registry (testable, no globals)."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.messages = Counter(
            "sentinel_worker_messages",
            "Handled deliveries by final outcome.",
            ["outcome"],
            registry=self.registry,
        )
        self.dead_letters = Counter(
            "sentinel_worker_dead_letters",
            "Messages dead-lettered by the worker, by sanitized failure code.",
            ["failure_code"],
            registry=self.registry,
        )
        self.tampering = Counter(
            "sentinel_worker_rejected_tampered_messages",
            "Messages rejected as possibly forged or tampered (subset of dead letters).",
            registry=self.registry,
        )
        self.store_errors = Counter(
            "sentinel_worker_receipt_store_errors",
            "Deliveries whose receipt could not be stored durably (transient).",
            registry=self.registry,
        )
        for outcome in OUTCOMES:
            self.messages.labels(outcome=outcome)
        for code in FAILURE_CODES:
            self.dead_letters.labels(failure_code=code)

    def observe(self, outcome: str, failure_code: str | None, store_error: bool) -> None:
        if outcome not in OUTCOMES:
            raise ValueError("unknown outcome label")
        self.messages.labels(outcome=outcome).inc()
        if outcome == "dead_lettered" and failure_code is not None:
            if failure_code not in FAILURE_CODES:
                raise ValueError("unknown failure code label")
            self.dead_letters.labels(failure_code=failure_code).inc()
            if failure_code in TAMPERING_CODES:
                self.tampering.inc()
        if store_error:
            self.store_errors.inc()


@dataclass(frozen=True, slots=True)
class MetricsSettings:
    port: int | None
    address: str = "127.0.0.1"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> MetricsSettings:
        env = os.environ if environ is None else environ
        raw_port = env.get(PORT_VAR, "").strip()
        address = env.get(ADDRESS_VAR, "").strip() or "127.0.0.1"
        if not raw_port:
            return cls(port=None, address=address)
        try:
            port = int(raw_port)
        except ValueError:
            raise ConfigurationError(f"{PORT_VAR} must be an integer between 1 and 65535") from None
        if not 1 <= port <= 65535:
            raise ConfigurationError(f"{PORT_VAR} must be an integer between 1 and 65535")
        try:
            loopback = ipaddress.ip_address(address).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ConfigurationError(f"{ADDRESS_VAR} must be a literal loopback IP address")
        return cls(port=port, address=address)


def serve(metrics: WorkerMetrics, settings: MetricsSettings) -> None:
    """Starts the exposition server in a daemon thread when a port is configured."""
    if settings.port is not None:
        start_http_server(settings.port, addr=settings.address, registry=metrics.registry)

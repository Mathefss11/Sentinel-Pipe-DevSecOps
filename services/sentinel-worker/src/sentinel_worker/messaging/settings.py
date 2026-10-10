"""Consumer settings from environment variables.

The worker connects with its **own** least-privileged RabbitMQ user (read on the worker
queue, write on the dead-letter exchange, no configure). The password has no default
and is never included in error messages, reprs or logs.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_worker.config import ConfigurationError

HOST_VAR = "SENTINEL_WORKER_RABBITMQ_HOST"
PORT_VAR = "SENTINEL_WORKER_RABBITMQ_PORT"
VHOST_VAR = "SENTINEL_WORKER_RABBITMQ_VHOST"
USERNAME_VAR = "SENTINEL_WORKER_RABBITMQ_USERNAME"
PASSWORD_VAR = "SENTINEL_WORKER_RABBITMQ_PASSWORD"  # noqa: S105 - variable name, not a secret
RECEIPT_DB_VAR = "SENTINEL_WORKER_RECEIPT_DB"
PREFETCH_VAR = "SENTINEL_WORKER_PREFETCH"

MAX_PREFETCH = 50


@dataclass(frozen=True, slots=True)
class ConsumerSettings:
    host: str
    port: int
    virtual_host: str
    username: str
    password: str = field(repr=False)
    receipt_db: Path
    prefetch: int = 1

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ConsumerSettings:
        env = os.environ if environ is None else environ

        username = env.get(USERNAME_VAR, "").strip()
        if not username:
            raise ConfigurationError(f"{USERNAME_VAR} must be set")
        password = env.get(PASSWORD_VAR, "")
        if not password:
            raise ConfigurationError(f"{PASSWORD_VAR} must be set")

        port = _bounded_int(env, PORT_VAR, default=5672, minimum=1, maximum=65535)
        prefetch = _bounded_int(env, PREFETCH_VAR, default=1, minimum=1, maximum=MAX_PREFETCH)
        receipt_db = env.get(RECEIPT_DB_VAR, "").strip() or ".sentinel-worker/receipts.sqlite3"

        return cls(
            host=env.get(HOST_VAR, "localhost").strip() or "localhost",
            port=port,
            virtual_host=env.get(VHOST_VAR, "/") or "/",
            username=username,
            password=password,
            receipt_db=Path(receipt_db),
            prefetch=prefetch,
        )


def _bounded_int(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(
            f"{name} must be an integer between {minimum} and {maximum}"
        ) from None
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be an integer between {minimum} and {maximum}")
    return value

"""Consumer and receipt-store settings from environment variables.

The worker connects with its **own** least-privileged RabbitMQ user (read on the worker
queue, write on the dead-letter and retry exchanges, no configure) and its **own**
PostgreSQL login role (member of ``sentinel_worker``: EXECUTE on
``worker.record_receipt`` only). Passwords have no default and are never included in
error messages, reprs or logs.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.messaging.receipts import DatabaseSettings

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


# --- Receipt store -------------------------------------------------------------------

RECEIPT_BACKEND_VAR = "SENTINEL_WORKER_RECEIPT_BACKEND"
DB_HOST_VAR = "SENTINEL_WORKER_DB_HOST"
DB_PORT_VAR = "SENTINEL_WORKER_DB_PORT"
DB_NAME_VAR = "SENTINEL_WORKER_DB_NAME"
DB_USERNAME_VAR = "SENTINEL_WORKER_DB_USERNAME"
DB_PASSWORD_VAR = "SENTINEL_WORKER_DB_PASSWORD"  # noqa: S105 - variable name, not a secret
DB_SSLMODE_VAR = "SENTINEL_WORKER_DB_SSLMODE"

SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
PRODUCTION_SSL_MODES = ("verify-ca", "verify-full")


class ReceiptBackend(StrEnum):
    POSTGRES = "postgres"
    """Shared PostgreSQL store (default; required outside development)."""

    SQLITE = "sqlite"
    """Local file; single host, no tenant verification. Development only."""


@dataclass(frozen=True, slots=True)
class ReceiptStoreSettings:
    backend: ReceiptBackend
    database: DatabaseSettings | None
    sqlite_path: Path | None

    @classmethod
    def from_env(
        cls, environment: Environment, environ: Mapping[str, str] | None = None
    ) -> ReceiptStoreSettings:
        env = os.environ if environ is None else environ
        raw = env.get(RECEIPT_BACKEND_VAR, ReceiptBackend.POSTGRES.value).strip().lower()
        try:
            backend = ReceiptBackend(raw)
        except ValueError:
            allowed = ", ".join(member.value for member in ReceiptBackend)
            raise ConfigurationError(f"{RECEIPT_BACKEND_VAR} must be one of: {allowed}") from None

        if backend is ReceiptBackend.SQLITE:
            if environment is not Environment.DEVELOPMENT:
                # Fail closed: the SQLite store cannot deduplicate across workers and does
                # not verify messages against the control plane.
                raise ConfigurationError(
                    f"{RECEIPT_BACKEND_VAR}=sqlite is only permitted in the development environment"
                )
            path = env.get(RECEIPT_DB_VAR, "").strip() or ".sentinel-worker/receipts.sqlite3"
            return cls(backend=backend, database=None, sqlite_path=Path(path))

        username = env.get(DB_USERNAME_VAR, "").strip()
        if not username:
            raise ConfigurationError(f"{DB_USERNAME_VAR} must be set")
        password = env.get(DB_PASSWORD_VAR, "")
        if not password:
            raise ConfigurationError(f"{DB_PASSWORD_VAR} must be set")
        sslmode = env.get(DB_SSLMODE_VAR, "").strip() or (
            "verify-full" if environment is Environment.PRODUCTION else "prefer"
        )
        if sslmode not in SSL_MODES:
            raise ConfigurationError(f"{DB_SSLMODE_VAR} must be one of: {', '.join(SSL_MODES)}")
        if environment is Environment.PRODUCTION and sslmode not in PRODUCTION_SSL_MODES:
            raise ConfigurationError(
                f"{DB_SSLMODE_VAR} must be one of {', '.join(PRODUCTION_SSL_MODES)} in production"
            )
        database = DatabaseSettings(
            host=env.get(DB_HOST_VAR, "localhost").strip() or "localhost",
            port=_bounded_int(env, DB_PORT_VAR, default=5432, minimum=1, maximum=65535),
            dbname=env.get(DB_NAME_VAR, "").strip() or "sentinelpipe",
            user=username,
            password=password,
            sslmode=sslmode,
        )
        return cls(backend=backend, database=database, sqlite_path=None)

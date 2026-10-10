"""Diagnostics for RabbitMQ Testcontainers startup failures.

An intermittent startup failure was observed once (all integration tests errored in
setup within about five seconds) and its error output was not preserved. This module
makes sure any future failure leaves a complete report instead of a one-line summary:

* full exception chain and traceback;
* Docker engine version, container ID, state, exit code and health;
* the broker container's log output;
* library and platform versions.

The report is printed to stderr (visible in CI logs) and written to
``$SENTINEL_TEST_DIAGNOSTICS_DIR`` (default ``.test-diagnostics/`` in the worker
directory, git-ignored). The container's environment and configuration are deliberately
excluded: they contain the broker credentials.
"""

from __future__ import annotations

import os
import platform
import sys
import traceback
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

DIAGNOSTICS_DIR_VAR = "SENTINEL_TEST_DIAGNOSTICS_DIR"
_DEFAULT_DIR = Path(__file__).resolve().parents[2] / ".test-diagnostics"
_LOG_TAIL_LINES = 400


class BrokerStartupError(RuntimeError):
    """The test broker could not be started or prepared; see the attached report."""


def _version(package: str) -> str:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return "not installed"


def _section(title: str, body: str) -> str:
    return f"===== {title} =====\n{body.rstrip()}\n"


def _safe(collect: Callable[[], str]) -> str:
    try:
        return collect()
    except Exception as exc:
        return f"<unavailable: {type(exc).__name__}: {exc}>"


def _docker_engine(container: Any) -> str:
    version = container.get_docker_client().client.version()
    return "\n".join(
        f"{key}: {version.get(key)}" for key in ("Version", "ApiVersion", "Os", "Arch")
    )


def _container_state(container: Any) -> str:
    wrapped = container.get_wrapped_container()
    if wrapped is None:
        return "container was not created"
    wrapped.reload()
    state = wrapped.attrs.get("State", {})
    fields = ("Status", "Running", "ExitCode", "Error", "OOMKilled", "StartedAt", "FinishedAt")
    lines = [f"id: {wrapped.id}", f"image: {wrapped.attrs.get('Image')}"]
    lines += [f"{field}: {state.get(field)}" for field in fields]
    health = state.get("Health") or {}
    if health:
        lines.append(f"health: {health.get('Status')}")
    ports = wrapped.attrs.get("NetworkSettings", {}).get("Ports")
    lines.append(f"ports: {ports}")
    return "\n".join(lines)


def _container_logs(container: Any) -> str:
    wrapped = container.get_wrapped_container()
    if wrapped is None:
        return "container was not created"
    logs = wrapped.logs(tail=_LOG_TAIL_LINES, timestamps=True)
    return logs.decode("utf-8", errors="replace")


def build_report(container: Any, error: BaseException, phase: str) -> str:
    environment = "\n".join(
        [
            f"utc: {datetime.now(UTC).isoformat()}",
            f"phase: {phase}",
            f"python: {sys.version.split()[0]} ({platform.platform()})",
            f"testcontainers: {_version('testcontainers')}",
            f"pika: {_version('pika')}",
            f"docker (python sdk): {_version('docker')}",
            f"image: {getattr(container, 'image', '?')}",
            "TESTCONTAINERS_RYUK_DISABLED: "
            + os.environ.get("TESTCONTAINERS_RYUK_DISABLED", "<unset>"),
            f"DOCKER_HOST: {os.environ.get('DOCKER_HOST', '<unset>')}",
        ]
    )
    return "".join(
        [
            _section("RabbitMQ test broker failure", environment),
            _section(
                "exception",
                "".join(traceback.format_exception(type(error), error, error.__traceback__)),
            ),
            _section("docker engine", _safe(lambda: _docker_engine(container))),
            _section("container state", _safe(lambda: _container_state(container))),
            _section(
                f"container logs (last {_LOG_TAIL_LINES} lines)",
                _safe(lambda: _container_logs(container)),
            ),
        ]
    )


def write_report(report: str) -> Path:
    directory = Path(os.environ.get(DIAGNOSTICS_DIR_VAR) or _DEFAULT_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"rabbitmq-startup-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}.log"
    path.write_text(report, encoding="utf-8")
    return path


@contextmanager
def diagnosed(container: Any, phase: str) -> Iterator[None]:
    """Turns any failure in ``phase`` into a :class:`BrokerStartupError` with a full report."""
    try:
        yield
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        report = build_report(container, error, phase)
        path = _safe(lambda: str(write_report(report)))
        print(report, file=sys.stderr)
        raise BrokerStartupError(
            f"RabbitMQ test broker failed during {phase}; full diagnostics: {path}"
        ) from error

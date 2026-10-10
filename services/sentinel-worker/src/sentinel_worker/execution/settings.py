"""Execution settings from environment variables.

The worker uses its own PostgreSQL login (``SENTINEL_WORKER_DB_*``, shared with the
receipt store); see :func:`sentinel_worker.messaging.settings.worker_database_settings`.

The FIXTURE scanner runs in a Docker sandbox by default (``SENTINEL_WORKER_FIXTURE_EXECUTOR
=sandbox``); ``inline`` runs the in-process fixture without any container. Sandbox
limits are bounded here, and the image and command are fixed in code (ADR-0009).
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass

from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.messaging.receipts import DatabaseSettings
from sentinel_worker.messaging.settings import worker_database_settings
from sentinel_worker.sandbox.fixture import FixtureMode
from sentinel_worker.sandbox.policy import ALLOWED_RUNTIMES, SandboxPolicy

POLL_INTERVAL_VAR = "SENTINEL_WORKER_EXECUTION_POLL_SECONDS"
FIXTURE_ENABLED_VAR = "SENTINEL_WORKER_FIXTURE_ENABLED"
FIXTURE_SECONDS_VAR = "SENTINEL_WORKER_FIXTURE_SECONDS"
FIXTURE_EXECUTOR_VAR = "SENTINEL_WORKER_FIXTURE_EXECUTOR"
FIXTURE_MODE_VAR = "SENTINEL_WORKER_FIXTURE_MODE"
DOCKER_CLI_VAR = "SENTINEL_WORKER_DOCKER_CLI"
SANDBOX_TIMEOUT_VAR = "SENTINEL_WORKER_SANDBOX_TIMEOUT_SECONDS"
SANDBOX_MEMORY_VAR = "SENTINEL_WORKER_SANDBOX_MEMORY_MB"
SANDBOX_CPUS_VAR = "SENTINEL_WORKER_SANDBOX_CPUS"
SANDBOX_PIDS_VAR = "SENTINEL_WORKER_SANDBOX_PIDS"
SANDBOX_RUNTIME_VAR = "SENTINEL_WORKER_SANDBOX_RUNTIME"
EXECUTORS = ("sandbox", "inline")


@dataclass(frozen=True, slots=True)
class ExecutionSettings:
    database: DatabaseSettings
    poll_interval_seconds: float
    fixture_enabled: bool
    fixture_seconds: float
    fixture_executor: str = "sandbox"
    fixture_mode: FixtureMode = FixtureMode.SUCCESS
    docker_cli: str | None = None
    sandbox_policy: SandboxPolicy | None = None

    @classmethod
    def from_env(
        cls, environment: Environment, environ: Mapping[str, str] | None = None
    ) -> ExecutionSettings:
        env = os.environ if environ is None else environ
        fixture = env.get(FIXTURE_ENABLED_VAR, "false").strip().lower()
        if fixture not in ("true", "false"):
            raise ConfigurationError(f"{FIXTURE_ENABLED_VAR} must be true or false")
        fixture_enabled = fixture == "true"
        if fixture_enabled and environment is Environment.PRODUCTION:
            raise ConfigurationError(f"{FIXTURE_ENABLED_VAR}=true is not permitted in production")
        if not fixture_enabled:
            # No real scanner is executable in this version.
            raise ConfigurationError(
                f"no executable scanner is enabled; set {FIXTURE_ENABLED_VAR}=true "
                "(development and CI only)"
            )
        executor = env.get(FIXTURE_EXECUTOR_VAR, "sandbox").strip().lower() or "sandbox"
        if executor not in EXECUTORS:
            raise ConfigurationError(
                f"{FIXTURE_EXECUTOR_VAR} must be one of: {', '.join(EXECUTORS)}"
            )
        raw_mode = env.get(FIXTURE_MODE_VAR, FixtureMode.SUCCESS.value).strip().lower()
        try:
            mode = FixtureMode(raw_mode)
        except ValueError:
            allowed = ", ".join(m.value for m in FixtureMode)
            raise ConfigurationError(f"{FIXTURE_MODE_VAR} must be one of: {allowed}") from None
        if executor == "inline" and mode is not FixtureMode.SUCCESS:
            raise ConfigurationError(f"{FIXTURE_MODE_VAR} other than success requires the sandbox")
        docker_cli = None
        policy = None
        if executor == "sandbox":
            docker_cli = _docker_cli(env)
            runtime = env.get(SANDBOX_RUNTIME_VAR, "").strip() or None
            if runtime is not None and runtime not in ALLOWED_RUNTIMES:
                allowed = ", ".join(sorted(ALLOWED_RUNTIMES))
                raise ConfigurationError(
                    f"{SANDBOX_RUNTIME_VAR} must be empty or one of: {allowed}"
                )
            policy = SandboxPolicy(
                timeout_seconds=_bounded(env, SANDBOX_TIMEOUT_VAR, 300.0, 1.0, 900.0),
                memory_bytes=int(_bounded(env, SANDBOX_MEMORY_VAR, 256.0, 16.0, 4096.0))
                * 1024
                * 1024,
                cpus=_bounded(env, SANDBOX_CPUS_VAR, 1.0, 0.1, 4.0),
                pids=int(_bounded(env, SANDBOX_PIDS_VAR, 64.0, 16.0, 1024.0)),
                runtime=runtime,
            )
        return cls(
            database=worker_database_settings(environment, env),
            poll_interval_seconds=_bounded(env, POLL_INTERVAL_VAR, 5.0, 0.1, 60.0),
            fixture_enabled=fixture_enabled,
            fixture_seconds=_bounded(env, FIXTURE_SECONDS_VAR, 2.0, 0.0, 600.0),
            fixture_executor=executor,
            fixture_mode=mode,
            docker_cli=docker_cli,
            sandbox_policy=policy,
        )


def _docker_cli(env: Mapping[str, str]) -> str:
    """The container runtime CLI: an explicit absolute path, or ``docker`` on PATH."""
    configured = env.get(DOCKER_CLI_VAR, "").strip()
    path = configured or shutil.which("docker")
    if not path or not os.path.isabs(path) or not os.path.isfile(path):
        raise ConfigurationError(
            f"{DOCKER_CLI_VAR} must be the absolute path of the Docker CLI (or docker on PATH)"
        )
    return path


def _bounded(
    env: Mapping[str, str], name: str, default: float, minimum: float, maximum: float
) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigurationError(
            f"{name} must be a number between {minimum} and {maximum}"
        ) from None
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be a number between {minimum} and {maximum}")
    return value

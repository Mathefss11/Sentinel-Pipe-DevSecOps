"""Execution settings from environment variables.

The worker uses its own PostgreSQL login (``SENTINEL_WORKER_DB_*``, shared with the
receipt store); see :func:`sentinel_worker.messaging.settings.worker_database_settings`.

The FIXTURE scanner runs in a Docker sandbox by default (``SENTINEL_WORKER_FIXTURE_EXECUTOR
=sandbox``); ``inline`` runs the in-process fixture without any container. Sandbox
limits are bounded here, and the image and command are fixed in code (ADR-0009).

The GITLEAKS scanner (``SENTINEL_WORKER_GITLEAKS_ENABLED=true``, ADR-0010) scans
synthetic repositories under ``SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR``. That local
fixture source is the only repository input in this version, so Gitleaks is refused in
production until a verified commit-snapshot source exists. The SEMGREP scanner
(``SENTINEL_WORKER_SEMGREP_ENABLED=true``, ADR-0011) uses the same fixture source and the
same production restriction. The TRIVY scanner (``SENTINEL_WORKER_TRIVY_ENABLED=true``,
ADR-0012) additionally needs ``SENTINEL_WORKER_TRIVY_IMAGE_LOCK``: the lock file written by
``sentinel-worker trivy-image build``. The lock is validated here; the image it names is
verified by content when the worker starts, never trusted from configuration.
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
GITLEAKS_ENABLED_VAR = "SENTINEL_WORKER_GITLEAKS_ENABLED"
SEMGREP_ENABLED_VAR = "SENTINEL_WORKER_SEMGREP_ENABLED"
TRIVY_ENABLED_VAR = "SENTINEL_WORKER_TRIVY_ENABLED"
TRIVY_IMAGE_LOCK_VAR = "SENTINEL_WORKER_TRIVY_IMAGE_LOCK"
REPOSITORY_FIXTURES_DIR_VAR = "SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR"
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
    gitleaks_enabled: bool = False
    repository_fixtures_dir: str | None = None
    gitleaks_policy: SandboxPolicy | None = None
    semgrep_enabled: bool = False
    semgrep_policy: SandboxPolicy | None = None
    trivy_enabled: bool = False
    trivy_image_lock: str | None = None
    sandbox_timeout_seconds: float = 300.0
    sandbox_cpus: float = 1.0
    sandbox_runtime: str | None = None

    @classmethod
    def from_env(
        cls, environment: Environment, environ: Mapping[str, str] | None = None
    ) -> ExecutionSettings:
        env = os.environ if environ is None else environ
        fixture_enabled = _flag(env, FIXTURE_ENABLED_VAR)
        if fixture_enabled and environment is Environment.PRODUCTION:
            raise ConfigurationError(f"{FIXTURE_ENABLED_VAR}=true is not permitted in production")
        gitleaks_enabled = _flag(env, GITLEAKS_ENABLED_VAR)
        semgrep_enabled = _flag(env, SEMGREP_ENABLED_VAR)
        trivy_enabled = _flag(env, TRIVY_ENABLED_VAR)
        for name, enabled in ((GITLEAKS_ENABLED_VAR, gitleaks_enabled),
                              (SEMGREP_ENABLED_VAR, semgrep_enabled),
                              (TRIVY_ENABLED_VAR, trivy_enabled)):  # fmt: skip
            if enabled and environment is Environment.PRODUCTION:
                # The only repository input is local fixtures (no verified commit
                # snapshots yet), and runc is not a boundary for hostile code (ADR-0009).
                raise ConfigurationError(
                    f"{name}=true is not permitted in production: repository "
                    "input is limited to local fixtures in this version"
                )
        if not (fixture_enabled or gitleaks_enabled or semgrep_enabled or trivy_enabled):
            raise ConfigurationError(
                f"no executable scanner is enabled; set {FIXTURE_ENABLED_VAR}=true, "
                f"{GITLEAKS_ENABLED_VAR}=true, {SEMGREP_ENABLED_VAR}=true or "
                f"{TRIVY_ENABLED_VAR}=true (development and CI only)"
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
        gitleaks_policy = None
        semgrep_policy = None
        fixtures_dir = None
        runtime = env.get(SANDBOX_RUNTIME_VAR, "").strip() or None
        if runtime is not None and runtime not in ALLOWED_RUNTIMES:
            allowed = ", ".join(sorted(ALLOWED_RUNTIMES))
            raise ConfigurationError(f"{SANDBOX_RUNTIME_VAR} must be empty or one of: {allowed}")
        timeout = _bounded(env, SANDBOX_TIMEOUT_VAR, 300.0, 1.0, 900.0)
        cpus = _bounded(env, SANDBOX_CPUS_VAR, 1.0, 0.1, 4.0)
        if fixture_enabled and executor == "sandbox":
            docker_cli = _docker_cli(env)
            policy = SandboxPolicy(
                timeout_seconds=timeout,
                memory_bytes=int(_bounded(env, SANDBOX_MEMORY_VAR, 256.0, 16.0, 4096.0))
                * 1024
                * 1024,
                cpus=cpus,
                pids=int(_bounded(env, SANDBOX_PIDS_VAR, 64.0, 16.0, 1024.0)),
                runtime=runtime,
            )
        if gitleaks_enabled:
            from sentinel_worker.scanners.gitleaks import GitleaksAdapter

            docker_cli = _docker_cli(env)
            fixtures_dir = _fixtures_dir(env)
            gitleaks_policy = GitleaksAdapter().policy(timeout, cpus, runtime)
        if semgrep_enabled:
            from sentinel_worker.scanners.semgrep import SemgrepAdapter

            docker_cli = _docker_cli(env)
            fixtures_dir = _fixtures_dir(env)
            semgrep_policy = SemgrepAdapter().policy(timeout, cpus, runtime)
        trivy_lock = None
        if trivy_enabled:
            docker_cli = _docker_cli(env)
            fixtures_dir = _fixtures_dir(env)
            trivy_lock = _trivy_lock(env)
        return cls(
            database=worker_database_settings(environment, env),
            poll_interval_seconds=_bounded(env, POLL_INTERVAL_VAR, 5.0, 0.1, 60.0),
            fixture_enabled=fixture_enabled,
            fixture_seconds=_bounded(env, FIXTURE_SECONDS_VAR, 2.0, 0.0, 600.0),
            fixture_executor=executor,
            fixture_mode=mode,
            docker_cli=docker_cli,
            sandbox_policy=policy,
            gitleaks_enabled=gitleaks_enabled,
            repository_fixtures_dir=fixtures_dir,
            gitleaks_policy=gitleaks_policy,
            semgrep_enabled=semgrep_enabled,
            semgrep_policy=semgrep_policy,
            trivy_enabled=trivy_enabled,
            trivy_image_lock=trivy_lock,
            sandbox_timeout_seconds=timeout,
            sandbox_cpus=cpus,
            sandbox_runtime=runtime,
        )


def _flag(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "false").strip().lower()
    if value not in ("true", "false"):
        raise ConfigurationError(f"{name} must be true or false")
    return value == "true"


def _fixtures_dir(env: Mapping[str, str]) -> str:
    """The synthetic repository root: an absolute, existing directory that is not a link
    (re-checked by :class:`~sentinel_worker.repository.snapshot.LocalFixtureRepositorySource`)."""
    path = env.get(REPOSITORY_FIXTURES_DIR_VAR, "").strip()
    if not path or not os.path.isabs(path) or not os.path.isdir(path) or os.path.islink(path):
        raise ConfigurationError(
            f"{REPOSITORY_FIXTURES_DIR_VAR} must be the absolute path of an existing directory"
        )
    return path


def _trivy_lock(env: Mapping[str, str]) -> str:
    """The Trivy image lock: an absolute path to a lock that parses (ADR-0012). The image it
    names is verified by content at startup (sentinel_worker.scanners.trivy_image)."""
    from sentinel_worker.scanners.trivy_image import ImageError, parse_lock

    path = env.get(TRIVY_IMAGE_LOCK_VAR, "").strip()
    if not path or not os.path.isabs(path) or not os.path.isfile(path) or os.path.islink(path):
        raise ConfigurationError(
            f"{TRIVY_IMAGE_LOCK_VAR} must be the absolute path of the Trivy image lock "
            "(sentinel-worker trivy-image build)"
        )
    try:
        with open(path, "rb") as handle:
            parse_lock(handle.read(64 * 1024 + 1))
    except (OSError, ImageError) as exc:
        code = exc.code if isinstance(exc, ImageError) else "LOCK_UNREADABLE"
        raise ConfigurationError(f"{TRIVY_IMAGE_LOCK_VAR} is not a valid lock ({code})") from None
    return path


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

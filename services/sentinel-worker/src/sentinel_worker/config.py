"""Worker configuration loaded from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

ENVIRONMENT_VAR = "SENTINEL_WORKER_ENVIRONMENT"
LOG_LEVEL_VAR = "SENTINEL_WORKER_LOG_LEVEL"

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    CI = "ci"
    PRODUCTION = "production"


class ConfigurationError(ValueError):
    """Raised when worker configuration is invalid.

    Messages name the offending variable and the allowed values but never echo the
    supplied value, in case a secret was placed in the wrong variable.
    """


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    environment: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> WorkerSettings:
        env = os.environ if environ is None else environ

        raw_environment = env.get(ENVIRONMENT_VAR, Environment.DEVELOPMENT.value).strip().lower()
        try:
            environment = Environment(raw_environment)
        except ValueError:
            allowed = ", ".join(member.value for member in Environment)
            raise ConfigurationError(f"{ENVIRONMENT_VAR} must be one of: {allowed}") from None

        log_level = env.get(LOG_LEVEL_VAR, "INFO").strip().upper()
        if log_level not in LOG_LEVELS:
            raise ConfigurationError(f"{LOG_LEVEL_VAR} must be one of: {', '.join(LOG_LEVELS)}")

        return cls(environment=environment, log_level=log_level)

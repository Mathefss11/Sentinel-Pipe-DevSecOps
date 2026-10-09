"""Local self-check for the worker process.

The self-check verifies only what the worker itself controls (runtime and
configuration). It does not contact external services.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sentinel_worker import __version__
from sentinel_worker.config import ConfigurationError, WorkerSettings

MINIMUM_PYTHON = (3, 12)


class CheckStatus(StrEnum):
    PASSED = "pass"
    FAILED = "fail"


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True, slots=True)
class SelfCheckReport:
    checks: tuple[CheckResult, ...]

    @property
    def healthy(self) -> bool:
        # Fail closed: a report without any checks is not evidence of health.
        return bool(self.checks) and all(c.status is CheckStatus.PASSED for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "UP" if self.healthy else "DOWN",
            "version": __version__,
            "checks": [
                {"name": c.name, "status": c.status.value, "detail": c.detail} for c in self.checks
            ],
        }


def check_python_version(version_info: Sequence[int]) -> CheckResult:
    current = tuple(version_info[:2])
    required = ".".join(map(str, MINIMUM_PYTHON))
    detail = f"running {'.'.join(map(str, current))}, requires >= {required}"
    status = CheckStatus.PASSED if current >= MINIMUM_PYTHON else CheckStatus.FAILED
    return CheckResult("python_version", status, detail)


def check_configuration(environ: Mapping[str, str] | None) -> CheckResult:
    try:
        settings = WorkerSettings.from_env(environ)
    except ConfigurationError as exc:
        return CheckResult("configuration", CheckStatus.FAILED, str(exc))
    detail = f"environment={settings.environment.value}, log_level={settings.log_level}"
    return CheckResult("configuration", CheckStatus.PASSED, detail)


def run_self_check(
    environ: Mapping[str, str] | None = None,
    version_info: Sequence[int] | None = None,
) -> SelfCheckReport:
    return SelfCheckReport(
        checks=(
            check_python_version(sys.version_info if version_info is None else version_info),
            check_configuration(environ),
        )
    )

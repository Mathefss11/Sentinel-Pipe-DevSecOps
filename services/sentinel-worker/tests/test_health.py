from sentinel_worker import __version__
from sentinel_worker.config import ENVIRONMENT_VAR
from sentinel_worker.health import (
    CheckResult,
    CheckStatus,
    SelfCheckReport,
    check_python_version,
    run_self_check,
)


def test_supported_runtime_and_valid_configuration_is_healthy() -> None:
    report = run_self_check(environ={}, version_info=(3, 12, 0))

    assert report.healthy
    assert report.to_dict()["status"] == "UP"


def test_unsupported_python_version_fails() -> None:
    result = check_python_version((3, 11, 9))

    assert result.status is CheckStatus.FAILED
    assert "3.11" in result.detail


def test_invalid_configuration_makes_report_unhealthy() -> None:
    report = run_self_check(environ={ENVIRONMENT_VAR: "invalid"}, version_info=(3, 12, 0))

    assert not report.healthy
    failed = [c.name for c in report.checks if c.status is CheckStatus.FAILED]
    assert failed == ["configuration"]


def test_empty_report_is_not_healthy() -> None:
    assert not SelfCheckReport(checks=()).healthy


def test_report_serializes_all_checks() -> None:
    report = SelfCheckReport(checks=(CheckResult("example", CheckStatus.PASSED, "ok"),))

    assert report.to_dict() == {
        "status": "UP",
        "version": __version__,
        "checks": [{"name": "example", "status": "pass", "detail": "ok"}],
    }

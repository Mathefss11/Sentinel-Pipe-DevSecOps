import pytest

from sentinel_worker.config import (
    ENVIRONMENT_VAR,
    LOG_LEVEL_VAR,
    ConfigurationError,
    Environment,
    WorkerSettings,
)


def test_defaults_apply_when_variables_are_unset() -> None:
    settings = WorkerSettings.from_env({})

    assert settings == WorkerSettings(environment=Environment.DEVELOPMENT, log_level="INFO")


def test_values_are_read_and_normalized() -> None:
    settings = WorkerSettings.from_env({ENVIRONMENT_VAR: " CI ", LOG_LEVEL_VAR: "debug"})

    assert settings.environment is Environment.CI
    assert settings.log_level == "DEBUG"


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match=ENVIRONMENT_VAR):
        WorkerSettings.from_env({ENVIRONMENT_VAR: "staging"})


def test_unknown_log_level_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match=LOG_LEVEL_VAR):
        WorkerSettings.from_env({LOG_LEVEL_VAR: "VERBOSE"})


def test_error_message_does_not_echo_supplied_value() -> None:
    leaked = "ghp_notARealTokenButShouldNeverBeEchoed"

    with pytest.raises(ConfigurationError) as excinfo:
        WorkerSettings.from_env({ENVIRONMENT_VAR: leaked})

    assert leaked not in str(excinfo.value)


def test_settings_are_immutable() -> None:
    settings = WorkerSettings.from_env({})

    with pytest.raises(AttributeError):
        settings.log_level = "DEBUG"  # type: ignore[misc]

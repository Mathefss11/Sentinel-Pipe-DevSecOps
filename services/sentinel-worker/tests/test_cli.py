import json

import pytest

from sentinel_worker import __version__
from sentinel_worker.cli import EXIT_OK, EXIT_UNHEALTHY, main
from sentinel_worker.config import ENVIRONMENT_VAR, LOG_LEVEL_VAR


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENVIRONMENT_VAR, raising=False)
    monkeypatch.delenv(LOG_LEVEL_VAR, raising=False)


def test_self_check_succeeds_and_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["self-check"])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_OK
    assert report["status"] == "UP"
    assert {c["name"] for c in report["checks"]} == {"python_version", "configuration"}


def test_self_check_fails_on_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(LOG_LEVEL_VAR, "LOUD")

    exit_code = main(["self-check"])

    assert exit_code == EXIT_UNHEALTHY
    assert json.loads(capsys.readouterr().out)["status"] == "DOWN"


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_command_is_required() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])

    assert excinfo.value.code == 2

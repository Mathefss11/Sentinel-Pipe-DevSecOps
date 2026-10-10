from pathlib import Path

import pytest

from integration.broker_diagnostics import DIAGNOSTICS_DIR_VAR, BrokerStartupError, diagnosed


class FakeContainer:
    image = "rabbitmq@sha256:test"

    def get_wrapped_container(self) -> None:
        return None

    def get_docker_client(self) -> object:
        raise ConnectionError("docker engine unreachable")


def test_failures_produce_a_preserved_report_without_masking_the_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(DIAGNOSTICS_DIR_VAR, str(tmp_path))

    with (
        pytest.raises(BrokerStartupError, match="container start") as excinfo,
        diagnosed(FakeContainer(), "container start"),
    ):
        raise OSError("port already allocated")

    assert isinstance(excinfo.value.__cause__, OSError)
    reports = list(tmp_path.glob("rabbitmq-startup-*.log"))
    assert len(reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    assert "port already allocated" in report
    assert "Traceback" in report
    assert "docker engine unreachable" in report  # collector failures are reported, not raised
    assert "container was not created" in report
    assert "port already allocated" in capsys.readouterr().err


def test_interrupts_are_not_converted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DIAGNOSTICS_DIR_VAR, str(tmp_path))

    with pytest.raises(KeyboardInterrupt), diagnosed(FakeContainer(), "container start"):
        raise KeyboardInterrupt

    assert not list(tmp_path.iterdir())

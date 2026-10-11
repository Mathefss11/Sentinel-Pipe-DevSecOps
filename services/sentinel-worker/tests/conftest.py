import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinel_worker.messaging.receipts import SqliteReceiptStore
from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox
from sentinel_worker.sandbox.policy import FIXTURE_IMAGE, SandboxPolicy

#: Set in CI's sandbox job: a missing runtime or image fails instead of skipping.
REQUIRE_SANDBOX_VAR = "SENTINEL_REQUIRE_SANDBOX"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SqliteReceiptStore]:
    with SqliteReceiptStore(tmp_path / "receipts.sqlite3") as receipt_store:
        yield receipt_store


@pytest.fixture(scope="session")
def docker_cli() -> DockerCli:
    """The real Docker CLI with the pinned fixture image present (never pulled here)."""
    path = shutil.which("docker")
    problem = None
    if path is None:
        problem = "Docker CLI not available"
    else:
        probe = subprocess.run(  # noqa: S603 - fixed arguments
            [path, "image", "inspect", FIXTURE_IMAGE], capture_output=True, check=False
        )
        if probe.returncode != 0:
            problem = f"sandbox image not present; pull {FIXTURE_IMAGE}"
    if problem is not None:
        if os.environ.get(REQUIRE_SANDBOX_VAR) == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    assert path is not None
    return DockerCli(path)


#: Small limits so that resource tests are fast.
TEST_POLICY: dict[str, Any] = {
    "memory_bytes": 64 * 1024 * 1024,
    "cpus": 0.5,
    "pids": 32,
    "timeout_seconds": 20,
}


@pytest.fixture
def make_sandbox(docker_cli: DockerCli) -> Callable[..., DockerSandbox]:
    def make(**overrides: Any) -> DockerSandbox:
        return DockerSandbox(
            docker_cli, SandboxPolicy(**(TEST_POLICY | overrides)), monitor_interval=0.5
        )

    return make


@pytest.fixture(scope="session")
def trivy_images(docker_cli: DockerCli, tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Verified Trivy images built from the synthetic database (see trivy_images.py)."""
    from trivy_images import trivy_images as build

    return build(docker_cli, tmp_path_factory.mktemp("trivy-db"))

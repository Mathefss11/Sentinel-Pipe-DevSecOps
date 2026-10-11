"""Verified Trivy images built from the synthetic vulnerability database, for the
real-container tests (ADR-0012).

``SENTINEL_TEST_TRIVY_DB_DIR`` names the directory written by
``scripts/trivy/build-fixture-db.sh`` (synthetic advisories only). Every variant is built
with the production code path (:func:`~sentinel_worker.scanners.trivy_image.build_image`,
which ends with a full content verification) from a copy of that directory whose
``metadata.json`` or ``trivy.db`` the test controls:

* ``fresh``/``stale``/``expired``: ``UpdatedAt`` one hour, three days or eight days ago;
* ``corrupted``: valid meta pages and bucket-name pages, every other page inverted;
* ``truncated``: the first half of the database.

Without the directory (or the pinned base image) the tests skip, or fail when
``SENTINEL_REQUIRE_SANDBOX=1`` (CI).
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel_worker.sandbox.docker import DockerCli
from sentinel_worker.sandbox.policy import TRIVY_BASE_IMAGE
from sentinel_worker.scanners.trivy_image import (
    REQUIRED_BUCKETS,
    VerifiedImage,
    build_image,
    verify_image,
)

DB_DIR_VAR = "SENTINEL_TEST_TRIVY_DB_DIR"
AGES = {"fresh": timedelta(hours=1), "stale": timedelta(days=3), "expired": timedelta(days=8)}


def _go_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


class TrivyImages:
    def __init__(self, cli: DockerCli, source: Path, work: Path) -> None:
        self.cli = cli
        self.source = source
        self.work = work
        self._built: dict[str, VerifiedImage] = {}

    def database_dir(self, variant: str) -> Path:
        """A prepared database directory for ``variant`` (built once per session)."""
        target = self.work / variant
        if target.exists():
            return target
        shutil.copytree(self.source, target)
        age = AGES.get(variant, AGES["fresh"])
        updated = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - age
        metadata = json.loads((target / "metadata.json").read_bytes())
        metadata["UpdatedAt"] = _go_time(updated)
        metadata["NextUpdate"] = _go_time(updated + timedelta(hours=24))
        (target / "metadata.json").write_text(json.dumps(metadata, separators=(",", ":")))
        database = (target / "trivy.db").read_bytes()
        if variant == "corrupted":
            # Both meta pages stay intact (the structure check passes), and so does every
            # page naming a required advisory bucket (the coverage check passes); every
            # other data page is inverted.
            page = 4096
            pages = [database[i : i + page] for i in range(0, len(database), page)]
            (target / "trivy.db").write_bytes(
                b"".join(
                    chunk
                    if index < 2 or any(bucket in chunk for bucket in REQUIRED_BUCKETS)
                    else bytes(b ^ 0xFF for b in chunk)
                    for index, chunk in enumerate(pages)
                )
            )
        elif variant == "truncated":
            (target / "trivy.db").write_bytes(database[: len(database) // 2])
        return target

    def image(self, variant: str = "fresh") -> VerifiedImage:
        if variant not in self._built:
            lock = build_image(self.cli, self.database_dir(variant))
            self._built[variant] = verify_image(self.cli, lock)
        return self._built[variant]


def trivy_images(cli: DockerCli, work: Path) -> TrivyImages:
    """The session's image builder, or a skip (failure in CI) when prerequisites miss."""
    source = os.environ.get(DB_DIR_VAR, "").strip()
    problem = None
    if not source or not (Path(source) / "trivy.db").is_file():
        problem = f"{DB_DIR_VAR} must name a synthetic DB (scripts/trivy/build-fixture-db.sh)"
    elif cli.call(["image", "inspect", TRIVY_BASE_IMAGE]).returncode != 0:
        problem = f"Trivy base image not present; pull {TRIVY_BASE_IMAGE}"
    if problem is not None:
        if os.environ.get("SENTINEL_REQUIRE_SANDBOX") == "1":
            pytest.fail(problem)
        pytest.skip(problem)
    return TrivyImages(cli, Path(source), work)

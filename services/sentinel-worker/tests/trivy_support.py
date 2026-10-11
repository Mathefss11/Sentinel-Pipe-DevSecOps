"""Builders for the Trivy tests: locks, verified images, reports and fixture repositories.

All package names are fictitious (``sentinelpipe-fixture-*``) and match only the synthetic
advisories in ``tests/fixtures/trivy-db`` (built by ``scripts/trivy/build-fixture-db.sh``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel_worker.sandbox.policy import register_verified_image
from sentinel_worker.scanners.trivy import (
    PACKAGE_FIELDS,
    REPORT_NAME,
    VERSION,
    VULNERABILITY_FIELDS,
)
from sentinel_worker.scanners.trivy_image import (
    DatabaseMetadata,
    DatabaseSource,
    ImageLock,
    VerifiedImage,
)

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
FAKE_IMAGE_ID = "sha256:" + "ab" * 32
SYNTHETIC = DatabaseSource("SYNTHETIC_FIXTURE", advisories_sha256="cd" * 32)
UPSTREAM = DatabaseSource(
    "UPSTREAM_OCI", manifest_digest="sha256:" + "01" * 32, blob_digest="sha256:" + "02" * 32
)


def make_lock(
    updated_at: datetime = NOW - timedelta(hours=1),
    source: DatabaseSource = SYNTHETIC,
    image_id: str = FAKE_IMAGE_ID,
) -> ImageLock:
    return ImageLock(
        source=source,
        trivy_db_sha256="ef" * 32,
        trivy_db_size=65536,
        metadata_sha256="12" * 32,
        metadata=DatabaseMetadata(2, updated_at, updated_at + timedelta(hours=24)),
        layer_digest="sha256:" + "34" * 32,
        layer_size=70000,
        config_digest="sha256:" + "56" * 32,
        image_id=image_id,
    )


def verified(lock: ImageLock | None = None) -> VerifiedImage:
    """A VerifiedImage built directly (unit tests only; no Docker, nothing verified)."""
    lock = lock or make_lock()
    register_verified_image(lock.image_id)
    return VerifiedImage(lock.image_id, lock)


def package(
    name: str,
    version: str,
    dev: bool = False,
    package_id: str | None = None,
    relationship: str = "direct",
) -> dict[str, Any]:
    return {
        "id": f"{name}@{version}" if package_id is None else package_id,
        "name": name,
        "version": version,
        "dev": dev,
        "relationship": relationship,
    }


def vulnerability(
    advisory: str,
    pkg: dict[str, Any],
    fixed: str = "9.9.9",
    severity: str = "HIGH",
    **overrides: Any,
) -> dict[str, Any]:
    return {
        "id": advisory,
        "vendor_ids": None,
        "pkg_id": pkg["id"],
        "pkg_name": pkg["name"],
        "installed": pkg["version"],
        "fixed": fixed,
        "status": "fixed" if fixed else "affected",
        "severity": severity,
        "source": "ghsa",
        "cwe": None,
    } | overrides


def result(
    target: str,
    kind: str,
    packages: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """One result in the compact report format (positional arrays; dict builders are
    converted, other values are kept so that tests can inject malformed rows)."""
    return {
        "target": target,
        "type": kind,
        "class": "lang-pkgs",
        "packages": [_row(p, PACKAGE_FIELDS) for p in packages],
        "vulnerabilities": [_row(v, VULNERABILITY_FIELDS) for v in vulnerabilities or []],
    }


def _row(value: Any, fields: tuple[str, ...]) -> Any:
    if isinstance(value, dict) and set(value) == set(fields):
        return [value[field] for field in fields]
    return value


def report(*results: dict[str, Any], version: str = VERSION) -> bytes:
    return json.dumps({"version": version, "results": list(results)}).encode("utf-8")


def envelope(report_bytes: bytes, name: str = REPORT_NAME) -> bytes:
    """sandbox-output.v1 as the Trivy script emits it."""
    return json.dumps(
        {
            "artifacts": [
                {
                    "content_base64": base64.b64encode(report_bytes).decode("ascii"),
                    "media_type": "application/json",
                    "name": name,
                }
            ],
            "schema_version": 1,
        },
        separators=(",", ":"),
    ).encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fnv64a(data: bytes) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


#: Filler that contains the advisory bucket names the worker requires.
BUCKETS = b"|".join(
    [
        b"maven::GitHub Security Advisory Maven",
        b"npm::GitHub Security Advisory npm",
        b"pip::GitHub Security Advisory pip",
    ]
)


def fake_bolt(pages: int = 6, page_size: int = 4096, fill: bytes = BUCKETS) -> bytes:
    """A file with two valid bbolt meta pages (high-water mark ``pages``) and filler data
    (by default naming every required advisory bucket): structurally sound and passing the
    coverage presence check, not a usable database."""
    data = bytearray((fill * (pages * page_size // len(fill) + 1))[: pages * page_size])
    for index, txid in ((0, 2), (1, 1)):
        meta = struct.pack("<IIIIQQQQQ", 0xED0CDAED, 2, page_size, 0, 3, 0, 2, pages, txid)
        page = struct.pack("<QHHI", index, 0x04, 0, 0) + meta + struct.pack("<Q", _fnv64a(meta))
        data[index * page_size : index * page_size + len(page)] = page
    return bytes(data)


# --- Fixture repositories (match the synthetic advisories) ------------------------------


#: package-lock.json v3 with one vulnerable runtime and one vulnerable dev dependency.
def npm_lock(vulnerable: str = "2.0.0", devtool: str = "1.0.0") -> str:
    return json.dumps(
        {
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "app",
                    "version": "1.0.0",
                    "dependencies": {"sentinelpipe-fixture-vulnerable": vulnerable},
                    "devDependencies": {"sentinelpipe-fixture-devtool": devtool},
                },
                "node_modules/sentinelpipe-fixture-vulnerable": {"version": vulnerable},
                "node_modules/sentinelpipe-fixture-devtool": {"version": devtool, "dev": True},
            },
        },
        indent=2,
    )


def pom(version: str = "1.4.0") -> str:
    return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.sentinelpipe.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>dev.sentinelpipe.fixture</groupId>
      <artifactId>vulnerable-parser</artifactId>
      <version>{version}</version>
    </dependency>
  </dependencies>
</project>
"""


def gradle_lock(version: str = "1.4.0") -> str:
    return (
        "# This is a Gradle generated file for dependency locking.\n"
        f"dev.sentinelpipe.fixture:vulnerable-parser:{version}=compileClasspath,runtimeClasspath\n"
        "empty=\n"
    )


def requirements(vulnerable: str = "3.0.0", unfixed: str = "1.0.0") -> str:
    return (
        f"sentinelpipe-fixture-vulnerable=={vulnerable}\nsentinelpipe-fixture-unfixed=={unfixed}\n"
    )


def poetry_lock(version: str = "3.0.0") -> str:
    return f"""[[package]]
name = "sentinelpipe-fixture-vulnerable"
version = "{version}"
description = ""
optional = false
python-versions = "*"
files = []

[metadata]
lock-version = "2.0"
python-versions = "*"
content-hash = "0000000000000000000000000000000000000000000000000000000000000000"
"""


def pyproject_poetry() -> str:
    return """[tool.poetry]
name = "app"
version = "1.0.0"
description = ""
authors = []

[tool.poetry.dependencies]
python = "^3.12"
sentinelpipe-fixture-vulnerable = "*"
"""


def pipfile_lock(version: str = "3.0.0") -> str:
    return json.dumps(
        {
            "_meta": {
                "hash": {"sha256": "0" * 64},
                "pipfile-spec": 6,
                "requires": {},
                "sources": [],
            },
            "default": {"sentinelpipe-fixture-vulnerable": {"version": f"=={version}"}},
            "develop": {},
        },
        indent=2,
    )


#: Advisories in the synthetic database (tests/fixtures/trivy-db).
MAVEN_ADVISORY = "GHSA-2f2f-3g3g-4h4h"
NPM_ADVISORY = "CVE-2099-0001"  # GHSA-5j5j-6m6m-7p7p, with a synthetic CVE alias
NPM_ALIAS = "GHSA-5j5j-6m6m-7p7p"
NPM_DEV_ADVISORY = "GHSA-8q8q-9r9r-2v2v"
PYPI_ADVISORY = "GHSA-3w3w-4x4x-5c5c"
PYPI_UNFIXED_ADVISORY = "GHSA-6f6f-7g7g-8h8h"

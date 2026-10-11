# ruff: noqa: E501 - synthetic lockfile and archive fixtures are kept on readable lines.
"""The trusted preparation scripts (scripts/trivy): network hygiene, manifest and archive
validation, mirror corroboration, and the audited refresh (ADR-0012). No network: the
registry is replaced by in-memory responses."""

from __future__ import annotations

import email.message
import hashlib
import importlib.util
import io
import json
import tarfile
import urllib.request
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "trivy"
METADATA = b'{"Version":2,"NextUpdate":"2026-10-12T00:00:00Z","UpdatedAt":"2026-10-11T00:00:00Z"}'


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fetch_script = load("fetch-trivy-db")
refresh_script = load("refresh-trivy-db")


# --- Redirects ----------------------------------------------------------------------------------


def _redirect(target: str) -> urllib.request.Request | None:
    request = urllib.request.Request(
        "https://ghcr.io/v2/aquasecurity/trivy-db/blobs/sha256:00",
        headers={"Authorization": "Bearer synthetic-registry-token"},
    )
    handler = fetch_script.SafeRedirects()
    result: urllib.request.Request | None = handler.redirect_request(
        request, None, 307, "Temporary Redirect", email.message.Message(), target
    )
    return result


def test_the_registry_token_never_follows_a_redirect_to_another_host() -> None:
    # Regression S3-6: urllib's default handler forwards Authorization to any host.
    other = _redirect("https://pkg-containers.githubusercontent.com/ghcr1/blobs/x")
    same = _redirect("https://ghcr.io/v2/aquasecurity/trivy-db/blobs/sha256:01")

    assert other is not None
    assert other.get_header("Authorization") is None
    assert same is not None
    assert same.get_header("Authorization") == "Bearer synthetic-registry-token"


@pytest.mark.parametrize(
    "target", ["http://ghcr.io/v2/x", "ftp://example.com/x", "file:///etc/passwd"]
)
def test_redirects_other_than_https_are_refused(target: str) -> None:
    with pytest.raises(fetch_script.FetchError, match="not https"):
        _redirect(target)


def test_redirect_chains_are_bounded() -> None:
    assert fetch_script.SafeRedirects.max_redirections == 3


# --- Manifests and archives -------------------------------------------------------------------


def manifest(blob: bytes, **changes: Any) -> bytes:
    layer = {
        "mediaType": fetch_script.LAYER_MEDIA_TYPE,
        "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
    }
    document = {
        "schemaVersion": 2,
        "mediaType": fetch_script.MANIFEST_MEDIA_TYPE,
        "layers": [layer],
    }
    for key, value in changes.items():
        if key.startswith("layer_"):
            layer[key[len("layer_") :]] = value
        else:
            document[key] = value
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    "changes",
    [
        {"mediaType": "application/vnd.docker.distribution.manifest.v2+json"},
        {"layer_mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"},
        {"layer_digest": "sha256:short"},
        {"layer_size": 0},
        {"layer_size": 2 * 1024 * 1024 * 1024},
    ],
)
def test_unexpected_manifests_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(fetch_script.FetchError):
        fetch_script._layer(manifest(b"x", **changes))


def test_a_manifest_with_several_layers_is_refused() -> None:
    document = json.loads(manifest(b"x"))
    document["layers"] *= 2
    with pytest.raises(fetch_script.FetchError):
        fetch_script._layer(json.dumps(document).encode())


def archive(*entries: tuple[str, bytes, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as out:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = "/etc/passwd"
            else:
                info.size = len(data)
            out.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


GOOD = archive(
    ("trivy.db", tarfile.REGTYPE, b"bolt" * 100), ("metadata.json", tarfile.REGTYPE, METADATA)
)


class Registry:
    """In-memory replacement for the registry functions of the fetch script."""

    def __init__(self, blob: bytes, mirror: str | None = None, served: bytes | None = None) -> None:
        self.raw = manifest(blob)
        self.digest = "sha256:" + hashlib.sha256(self.raw).hexdigest()
        self.blob_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        self.mirror = mirror or self.blob_digest
        self.served = blob if served is None else served

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fetch_script, "_token", lambda: "synthetic-registry-token")
        monkeypatch.setattr(fetch_script, "_manifest", lambda ref, token: (self.raw, self.digest))
        monkeypatch.setattr(fetch_script, "_request", lambda path, token: io.BytesIO(self.served))
        monkeypatch.setattr(fetch_script, "mirror_blob", lambda: self.mirror)


def test_a_corroborated_artifact_is_fetched_with_provenance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registry = Registry(GOOD)
    registry.install(monkeypatch)

    assert fetch_script.fetch(registry.digest, tmp_path / "db") == 0

    assert sorted(p.name for p in (tmp_path / "db").iterdir()) == [
        "metadata.json",
        "provenance.json",
        "trivy.db",
    ]
    provenance = json.loads((tmp_path / "db" / "provenance.json").read_bytes())
    assert provenance["blob_digest"] == registry.blob_digest
    assert provenance["trivy_db_sha256"] == hashlib.sha256(b"bolt" * 100).hexdigest()


def test_an_artifact_the_mirror_does_not_serve_is_refused_unless_explicitly_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registry = Registry(GOOD, mirror="sha256:" + "0" * 64)
    registry.install(monkeypatch)

    with pytest.raises(fetch_script.FetchError, match="not corroborated"):
        fetch_script.fetch(registry.digest, tmp_path / "refused")
    assert fetch_script.fetch(registry.digest, tmp_path / "skipped", corroborate=False) == 0


@pytest.mark.parametrize(
    "blob",
    [
        archive(("trivy.db", tarfile.REGTYPE, b"x"), ("metadata.json", tarfile.REGTYPE, METADATA),
                ("extra.sh", tarfile.REGTYPE, b"#!/bin/sh")),
        archive(("trivy.db", tarfile.SYMTYPE, b""), ("metadata.json", tarfile.REGTYPE, METADATA)),
        archive(("../trivy.db", tarfile.REGTYPE, b"x"), ("metadata.json", tarfile.REGTYPE, METADATA)),
        archive(("trivy.db", tarfile.REGTYPE, b"x")),
        archive(("trivy.db", tarfile.REGTYPE, b"x"),
                ("metadata.json", tarfile.REGTYPE, METADATA.replace(b'"Version":2', b'"Version":3'))),
    ],
    ids=["extra-entry", "symlink", "traversal", "incomplete", "schema-3"],
)  # fmt: skip
def test_unexpected_archives_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, blob: bytes
) -> None:
    Registry(blob).install(monkeypatch)

    with pytest.raises(fetch_script.FetchError):
        fetch_script.fetch(Registry(blob).digest, tmp_path / "db")
    assert not (tmp_path.parent / "trivy.db").exists()


def test_a_blob_that_does_not_match_its_digest_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registry = Registry(GOOD, served=GOOD[:-1] + bytes([GOOD[-1] ^ 1]))
    registry.install(monkeypatch)

    with pytest.raises(fetch_script.FetchError, match="digest mismatch"):
        fetch_script.fetch(registry.digest, tmp_path / "db")


# --- Audited refresh ----------------------------------------------------------------------------


class Tools:
    """Scripted fetch, build and verify results for the refresh orchestration."""

    def __init__(self, verified_id: str = "sha256:" + "a" * 64) -> None:
        self.commands: list[list[str]] = []
        self.verified_id = verified_id

    def __call__(self, command: Sequence[str]) -> str:
        self.commands.append(list(command))
        if "fetch" in command:
            return json.dumps({"fetched": True, "blob_digest": "sha256:" + "b" * 64})
        if "build" in command:
            lock = Path(command[command.index("--lock-out") + 1])
            lock.write_text(json.dumps({
                "database": {"trivy_db_sha256": "c" * 64,
                             "metadata": {"updated_at": "2026-10-11T00:00:00.000000Z"}},
                "image": {"config_digest": "sha256:" + "d" * 64},
            }))  # fmt: skip
            return json.dumps({"built": True, "image_id": "sha256:" + "a" * 64})
        return json.dumps({"verified": True, "image_id": self.verified_id})


DIGEST = "sha256:" + "9" * 64


def test_a_refresh_is_audited_and_never_touches_the_previous_lock(tmp_path: Path) -> None:
    previous = tmp_path / "old.lock"
    previous.write_text("previous lock")
    tools = Tools()

    record = refresh_script.refresh(
        DIGEST, tmp_path / "work", "operator-a", "weekly refresh", previous,
        run=tools, now=lambda: datetime(2026, 10, 11, 12, tzinfo=UTC),
    )  # fmt: skip

    assert [
        c[c.index("trivy-image") + 1] if "trivy-image" in c else "fetch" for c in tools.commands
    ] == ["fetch", "build", "verify"]
    assert "--skip-corroboration" not in tools.commands[0]
    audit = (tmp_path / "work" / "refresh-audit.jsonl").read_text().splitlines()
    assert json.loads(audit[0]) == record
    assert record["previous_lock_sha256"] == hashlib.sha256(b"previous lock").hexdigest()
    assert record["corroboration_skipped"] is None
    assert record["time"] == "2026-10-11T12:00:00Z"
    assert previous.read_text() == "previous lock"
    with pytest.raises(refresh_script.RefreshError, match="already prepared"):
        refresh_script.refresh(DIGEST, tmp_path / "work", "operator-a", "again", run=Tools())


def test_a_refresh_whose_image_does_not_verify_writes_no_audit_record(tmp_path: Path) -> None:
    with pytest.raises(refresh_script.RefreshError, match="did not verify"):
        refresh_script.refresh(DIGEST, tmp_path, "operator-a", "refresh",
                               run=Tools(verified_id="sha256:" + "e" * 64))  # fmt: skip
    assert not (tmp_path / "refresh-audit.jsonl").exists()


@pytest.mark.parametrize(
    ("digest", "operator", "reason"),
    [("latest", "a", "b"), (DIGEST, "", "b"), (DIGEST, "a", "x\ny"), (DIGEST, "a" * 201, "b")],
)
def test_refresh_inputs_are_validated(
    tmp_path: Path, digest: str, operator: str, reason: str
) -> None:
    with pytest.raises(refresh_script.RefreshError):
        refresh_script.refresh(digest, tmp_path, operator, reason, run=Tools())


def test_skipping_corroboration_is_recorded(tmp_path: Path) -> None:
    tools = Tools()
    record = refresh_script.refresh(DIGEST, tmp_path, "operator-a", "refresh",
                                    skip_corroboration="mirror lagging 2 h", run=tools)  # fmt: skip

    assert "--skip-corroboration" in tools.commands[0]
    assert record["corroboration_skipped"] == "mirror lagging 2 h"

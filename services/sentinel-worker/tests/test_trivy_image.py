"""The Trivy image with an embedded database: lock, metadata and provenance validation,
deterministic construction, and content verification of an image export (ADR-0012).

Verification is exercised against synthetic OCI exports (``docker save`` format) with small
fake base layers, so every tampering case is precise and needs no container runtime. The
real image is covered by tests/sandbox/test_trivy_sandbox.py.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinel_worker.sandbox.policy import SandboxPolicy
from sentinel_worker.scanners import trivy_image
from sentinel_worker.scanners.trivy_image import (
    BASE_CONFIG,
    BASE_CONFIG_DIGEST,
    BASE_DIFF_IDS,
    ImageError,
    ImageLock,
    check_bolt_structure,
    derived_config,
    layer_chunks,
    parse_lock,
    parse_metadata,
    parse_source,
    read_database,
    verify_image,
)
from trivy_support import BUCKETS, SYNTHETIC, UPSTREAM, fake_bolt, make_lock

#: As the pinned trivy-db builder writes it (nanosecond timestamps).
METADATA = (
    b'{"Version":2,"NextUpdate":"2026-10-12T14:19:12.202272339Z",'
    b'"UpdatedAt":"2026-10-11T14:19:12.202272694Z","DownloadedAt":"0001-01-01T00:00:00Z"}'
)
DATABASE = fake_bolt()
BASE_ENV = json.loads(BASE_CONFIG)["config"]["Env"]


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --- Metadata, provenance and lock ------------------------------------------------------------


def test_metadata_as_trivy_writes_it_is_accepted() -> None:
    metadata = parse_metadata(METADATA)

    assert metadata.version == 2
    assert metadata.updated_at == datetime(2026, 10, 11, 14, 19, 12, 202272, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (METADATA.replace(b'"Version":2', b'"Version":1'), "SCHEMA_VERSION_UNSUPPORTED"),
        (METADATA.replace(b'"Version":2', b'"Version":3'), "SCHEMA_VERSION_UNSUPPORTED"),
        (METADATA.replace(b'"Version":2', b'"Version":"2"'), "METADATA_INVALID"),
        (METADATA.replace(b'"Version":2', b'"Version":true'), "METADATA_INVALID"),
        (METADATA.replace(b"14:19:12.202272694Z", b"14:19:12+02:00"), "METADATA_INVALID"),
        (METADATA.replace(b"2026-10-12", b"2026-10-10"), "METADATA_INVALID"),
        (METADATA[:-1] + b',"Version":2}', "METADATA_INVALID"),
        (METADATA[:-1] + b',"Extra":1}', "METADATA_INVALID"),
        (b"{garbage", "METADATA_INVALID"),
        (b"", "METADATA_INVALID"),
        (b" " * 5000, "METADATA_INVALID"),
    ],
)
def test_invalid_or_incompatible_metadata_is_refused(raw: bytes, code: str) -> None:
    with pytest.raises(ImageError) as raised:
        parse_metadata(raw)
    assert raised.value.code == code


@pytest.mark.parametrize(
    "document",
    [
        {
            "kind": "UPSTREAM_OCI",
            "repository": "ghcr.io/attacker/trivy-db",
            "manifest_digest": "sha256:" + "0" * 64,
            "blob_digest": "sha256:" + "0" * 64,
        },
        {
            "kind": "UPSTREAM_OCI",
            "repository": "ghcr.io/aquasecurity/trivy-db",
            "manifest_digest": "latest",
            "blob_digest": "sha256:" + "0" * 64,
        },
        {
            "kind": "SYNTHETIC_FIXTURE",
            "builder": "example.com/other@v1",
            "advisories_sha256": "0" * 64,
        },
        {"kind": "LOCAL", "path": "db"},
        [],
    ],
)
def test_unrecognized_provenance_is_refused(document: Any) -> None:
    with pytest.raises(ImageError, match="PROVENANCE_INVALID"):
        parse_source(document)


@pytest.mark.parametrize("lock", [make_lock(), make_lock(source=UPSTREAM)])
def test_a_lock_round_trips_exactly(lock: ImageLock) -> None:
    assert parse_lock(lock.to_bytes()) == lock


def _mutated(mutate: Any) -> bytes:
    document = json.loads(make_lock().to_bytes())
    mutate(document)
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d: d.update(base_image="ghcr.io/aquasecurity/trivy:latest"), "LOCK_BASE_MISMATCH"),
        (lambda d: d.update(base_config_digest="sha256:" + "0" * 64), "LOCK_BASE_MISMATCH"),
        (lambda d: d["image"].update(id="trivy:latest"), "LOCK_INVALID"),
        (lambda d: d["layer"].update(size=-1), "LOCK_INVALID"),
        (lambda d: d["database"].update(trivy_db_size=True), "LOCK_INVALID"),
        (lambda d: d["database"]["metadata"].update(version=3), "SCHEMA_VERSION_UNSUPPORTED"),
        (lambda d: d.update(extra=1), "LOCK_INVALID"),
        (lambda d: d.update(schema="sentinelpipe.trivy-image-lock.v0"), "LOCK_INVALID"),
    ],
)
def test_a_tampered_lock_is_refused(mutate: Any, code: str) -> None:
    with pytest.raises(ImageError) as raised:
        parse_lock(_mutated(mutate))
    assert raised.value.code == code


# --- Database structure ---------------------------------------------------------------------


def _with_meta(database: bytes, index: int, offset: int, value: bytes) -> bytes:
    start = index * 4096 + 16 + offset
    return database[:start] + value + database[start + len(value) :]


def test_a_sound_database_structure_is_accepted() -> None:
    check_bolt_structure(DATABASE[: 2 * 65536], len(DATABASE))


@pytest.mark.parametrize(
    ("head", "size"),
    [
        (DATABASE, len(DATABASE) - 1),  # truncated below the high-water mark
        (DATABASE[:4096], len(DATABASE)),  # second meta page missing
        (_with_meta(DATABASE, 0, 0, b"\0\0\0\0"), len(DATABASE)),  # magic
        (_with_meta(DATABASE, 1, 4, b"\x03\0\0\0"), len(DATABASE)),  # version
        (_with_meta(DATABASE, 0, 40, b"\xff"), len(DATABASE)),  # pgid changed: checksum
        (_with_meta(DATABASE, 0, 8, b"\x00\x20\0\0"), len(DATABASE)),  # page size
        (b"\0" * 8192, 8192),
    ],
    ids=["truncated", "one-meta", "magic", "version", "checksum", "page-size", "zeros"],
)
def test_a_damaged_database_structure_is_refused(head: bytes, size: int) -> None:
    with pytest.raises(ImageError, match="DATABASE_STRUCTURE_INVALID"):
        check_bolt_structure(head, size)


# --- Deterministic construction -------------------------------------------------------------


def test_the_vendored_base_configuration_is_the_pinned_one() -> None:
    assert sha(BASE_CONFIG) == BASE_CONFIG_DIGEST
    assert len(BASE_DIFF_IDS) == 4


def test_the_database_layer_is_deterministic_and_read_only(tmp_path: Path) -> None:
    db = tmp_path / "trivy.db"
    db.write_bytes(DATABASE)
    first = b"".join(layer_chunks(METADATA, db, len(DATABASE)))
    second = b"".join(layer_chunks(METADATA, db, len(DATABASE)))

    assert first == second
    with tarfile.open(fileobj=io.BytesIO(first)) as archive:
        members = archive.getmembers()
    assert [m.name for m in members] == [
        "opt",
        "opt/sentinelpipe",
        "opt/sentinelpipe/trivy",
        "opt/sentinelpipe/trivy/db",
        "opt/sentinelpipe/trivy/db/metadata.json",
        "opt/sentinelpipe/trivy/db/trivy.db",
    ]
    assert all(m.uid == 0 and m.gid == 0 and m.mtime == 0 for m in members)
    assert all(m.mode & 0o222 == 0 for m in members[1:])
    assert {m.mode for m in members if m.isfile()} == {0o444}


def test_a_database_that_changes_while_streamed_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "trivy.db"
    db.write_bytes(DATABASE)
    with pytest.raises(ImageError, match="DATABASE_CHANGED"):
        b"".join(layer_chunks(METADATA, db, len(DATABASE) + 1))


def test_the_configuration_changes_only_by_the_layer_and_labels() -> None:
    config = json.loads(derived_config("sha256:" + "1" * 64, {"a": "b"}))
    base = json.loads(BASE_CONFIG)

    assert config["rootfs"]["diff_ids"] == [*BASE_DIFF_IDS, "sha256:" + "1" * 64]
    assert config["config"]["Env"] == base["config"]["Env"]
    assert config["config"]["Entrypoint"] == base["config"]["Entrypoint"]
    assert "User" not in config["config"]
    assert config["config"]["Labels"]["a"] == "b"
    assert derived_config("sha256:" + "1" * 64, {"a": "b"}) != derived_config(
        "sha256:" + "2" * 64, {"a": "b"}
    )


def _database_dir(tmp_path: Path, provenance: dict[str, Any] | None = None) -> Path:
    directory = tmp_path / "db"
    directory.mkdir()
    (directory / "trivy.db").write_bytes(DATABASE)
    (directory / "metadata.json").write_bytes(METADATA)
    document = provenance or {
        "kind": "SYNTHETIC_FIXTURE",
        "builder": trivy_image.FIXTURE_BUILDER,
        "advisories_sha256": "0" * 64,
    }
    (directory / "provenance.json").write_text(json.dumps(document))
    return directory


def test_a_prepared_database_directory_is_validated(tmp_path: Path) -> None:
    database = read_database(_database_dir(tmp_path))

    assert database.db_sha256 == hashlib.sha256(DATABASE).hexdigest()
    assert database.source.kind == "SYNTHETIC_FIXTURE"


def test_a_fetched_database_must_still_match_its_recorded_digest(tmp_path: Path) -> None:
    provenance = {
        "kind": "UPSTREAM_OCI",
        "repository": "ghcr.io/aquasecurity/trivy-db",
        "manifest_digest": "sha256:" + "0" * 64,
        "blob_digest": "sha256:" + "1" * 64,
        "trivy_db_sha256": "2" * 64,
    }
    with pytest.raises(ImageError, match="DATABASE_CHANGED"):
        read_database(_database_dir(tmp_path, provenance))


@pytest.mark.parametrize("missing", ["trivy.db", "metadata.json", "provenance.json"])
def test_a_missing_database_file_is_refused(tmp_path: Path, missing: str) -> None:
    directory = _database_dir(tmp_path)
    (directory / missing).unlink()
    with pytest.raises(ImageError, match="DATABASE_MISSING"):
        read_database(directory)


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges on Windows")
def test_a_linked_database_file_is_refused(tmp_path: Path) -> None:
    directory = _database_dir(tmp_path)
    (directory / "trivy.db").unlink()
    (tmp_path / "elsewhere").write_bytes(DATABASE)
    (directory / "trivy.db").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ImageError, match="DATABASE_INVALID"):
        read_database(directory)


# --- Verification of an image export ------------------------------------------------------------


def _tar(entries: list[tuple[str, bytes, int, bytes]]) -> bytes:
    """(name, type, mode, data) entries as an uncompressed layer."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, mode, data in entries:
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = kind, mode, 0
            if kind == tarfile.SYMTYPE:
                info.linkname = data.decode()
                data = b""
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


BASE_LAYER_A = _tar(
    [("bin/", tarfile.DIRTYPE, 0o755, b""), ("bin/sh", tarfile.REGTYPE, 0o755, b"#!")]
)
BASE_LAYER_B = _tar([("usr/local/bin/trivy", tarfile.REGTYPE, 0o755, b"trivy-binary")])
FAKE_BASE_DIFF_IDS = (sha(BASE_LAYER_A), sha(BASE_LAYER_B))


def _image_id() -> str:
    """A fresh id per fake image: a registration by one test never masks another."""
    return sha(os.urandom(16))


def _layer_from(tmp_path: Path, metadata: bytes = METADATA, database: bytes = DATABASE) -> bytes:
    db = tmp_path / "layer-trivy.db"
    db.write_bytes(database)
    return b"".join(layer_chunks(metadata, db, len(database)))


@dataclass
class FakeImage:
    lock: ImageLock
    inspect: dict[str, Any]
    export: bytes
    save_returncode: int = 0


def build_fake(
    layer: bytes,
    *,
    database: bytes = DATABASE,
    metadata: bytes = METADATA,
    base_layers: tuple[bytes, ...] = (BASE_LAYER_A, BASE_LAYER_B),
    extra_layers: tuple[bytes, ...] = (),
    config_override: bytes | None = None,
    inspect_changes: dict[str, Any] | None = None,
    mislabel_blob: bool = False,
    claimed_database: bytes | None = None,
) -> FakeImage:
    """A consistent export. ``claimed_database`` makes the lock (and the configuration
    derived from it) claim another database than the layer carries, as a forger would."""
    claimed = database if claimed_database is None else claimed_database
    layer_digest = sha(layer)
    lock = ImageLock(
        source=SYNTHETIC,
        trivy_db_sha256=hashlib.sha256(claimed).hexdigest(),
        trivy_db_size=len(claimed),
        metadata_sha256=hashlib.sha256(metadata).hexdigest(),
        metadata=parse_metadata(metadata),
        layer_digest=layer_digest,
        layer_size=len(layer),
        config_digest="",
        image_id=_image_id(),
    )
    config = derived_config(layer_digest, lock.labels(), FAKE_BASE_DIFF_IDS)
    lock = replace(lock, config_digest=sha(config))
    if config_override is not None:
        config = config_override
    # The first base layer is exported compressed (as the containerd store does).
    exported = [gzip.compress(base_layers[0], mtime=0), *base_layers[1:], layer, *extra_layers]
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": sha(config),
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": sha(blob),
                    "size": len(blob),
                }
                for blob in exported
            ],
        }
    ).encode()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": sha(manifest),
                    "size": len(manifest),
                }
            ],
        }
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for blob in [*exported, config, manifest]:
            name = sha(blob)[7:]
            if mislabel_blob and blob is layer:
                name = "0" * 64
            info = tarfile.TarInfo(f"blobs/sha256/{name}")
            info.size = len(blob)
            archive.addfile(info, io.BytesIO(blob))
        info = tarfile.TarInfo("index.json")
        info.size = len(index)
        archive.addfile(info, io.BytesIO(index))
    inspect = {
        "Id": lock.image_id,
        "Architecture": "amd64",
        "Os": "linux",
        "Config": {"Env": BASE_ENV, "Entrypoint": ["trivy"]},
        "RootFS": {"Layers": [*FAKE_BASE_DIFF_IDS, layer_digest]},
    } | (inspect_changes or {})
    return FakeImage(lock, inspect, buffer.getvalue())


class FakeProcess:
    def __init__(self, data: bytes, returncode: int) -> None:
        self.stdout = io.BytesIO(data)
        self.stderr = io.BytesIO(b"")
        self.returncode = returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        pass


class FakeDocker:
    def __init__(self, image: FakeImage | None) -> None:
        self.image = image

    def call(self, arguments: list[str], timeout: float = 30) -> subprocess.CompletedProcess[bytes]:
        found = self.image is not None and arguments[-1] == self.image.lock.image_id
        stdout = json.dumps(self.image.inspect).encode() if found and self.image else b""
        return subprocess.CompletedProcess(arguments, 0 if found else 1, stdout, b"")

    def start(self, arguments: list[str], stdin: bool = False) -> FakeProcess:
        assert self.image is not None
        assert arguments[:2] == ["image", "save"]
        return FakeProcess(self.image.export, self.image.save_returncode)


def verify(image: FakeImage, lock: ImageLock | None = None) -> Any:
    return verify_image(
        FakeDocker(image),
        lock or image.lock,  # type: ignore[arg-type]
        base_diff_ids=FAKE_BASE_DIFF_IDS,
    )


def rejected(image: FakeImage, lock: ImageLock | None = None) -> str:
    with pytest.raises(ImageError) as raised:
        verify(image, lock)
    with pytest.raises(ValueError, match="verified local image"):
        SandboxPolicy(image=image.lock.image_id)
    return raised.value.code


def test_a_genuine_image_is_verified_and_only_then_allowed(tmp_path: Path) -> None:
    image = build_fake(_layer_from(tmp_path))
    with pytest.raises(ValueError, match="verified local image"):
        SandboxPolicy(image=image.lock.image_id)

    verified = verify(image)

    assert verified.image_id == image.lock.image_id
    assert SandboxPolicy(image=image.lock.image_id).image == image.lock.image_id


def test_an_added_executable_in_the_database_layer_is_refused(tmp_path: Path) -> None:
    genuine = _layer_from(tmp_path)
    with tarfile.open(fileobj=io.BytesIO(genuine)) as archive:
        entries = [
            (
                m.name + ("/" if m.isdir() else ""),
                m.type,
                m.mode,
                archive.extractfile(m).read() if m.isfile() else b"",
            )
            for m in archive
        ]  # type: ignore[union-attr]
    trojan = _tar(
        [*entries, ("usr/local/bin/trivy", tarfile.REGTYPE, 0o755, b"#!/bin/sh\necho clean")]
    )

    assert rejected(build_fake(trojan)) == "LAYER_CONTENT_INVALID"


def test_a_truncated_database_is_refused_even_when_the_lock_matches(tmp_path: Path) -> None:
    # Regression (security review S3): Trivy opens a truncated database and reports
    # nothing. A lock built from the truncated file matches it; the structure does not.
    truncated = DATABASE[: len(DATABASE) - 4096]
    image = build_fake(_layer_from(tmp_path, database=truncated), database=truncated)

    assert rejected(image) == "DATABASE_STRUCTURE_INVALID"


def test_a_truncated_database_is_refused_when_building(tmp_path: Path) -> None:
    directory = _database_dir(tmp_path)
    (directory / "trivy.db").write_bytes(DATABASE[:8192])
    with pytest.raises(ImageError, match="DATABASE_STRUCTURE_INVALID"):
        read_database(directory)


def test_a_database_different_from_the_lock_is_refused(tmp_path: Path) -> None:
    other = fake_bolt(fill=b"other")
    # The lock and configuration claim the reviewed database; the layer carries another one.
    image = build_fake(_layer_from(tmp_path, database=other), claimed_database=DATABASE)

    assert rejected(image) == "LAYER_CONTENT_INVALID"


@pytest.mark.parametrize(
    "entries",
    [
        [
            ("opt/sentinelpipe/trivy/db/trivy.db", tarfile.REGTYPE, 0o666, DATABASE),
            ("opt/sentinelpipe/trivy/db/metadata.json", tarfile.REGTYPE, 0o444, METADATA),
        ],
        [
            ("opt/sentinelpipe/trivy/db/trivy.db", tarfile.SYMTYPE, 0o777, b"/etc/shadow"),
            ("opt/sentinelpipe/trivy/db/metadata.json", tarfile.REGTYPE, 0o444, METADATA),
        ],
    ],
    ids=["writable-database", "symlinked-database"],
)
def test_layers_of_the_wrong_shape_are_refused(entries: list[Any]) -> None:
    assert rejected(build_fake(_tar(entries))) == "LAYER_CONTENT_INVALID"


def test_modified_base_layers_are_refused(tmp_path: Path) -> None:
    patched = _tar([("usr/local/bin/trivy", tarfile.REGTYPE, 0o755, b"patched-binary")])
    image = build_fake(_layer_from(tmp_path), base_layers=(BASE_LAYER_A, patched))

    assert rejected(image) == "LAYERS_MISMATCH"


def test_an_additional_layer_is_refused(tmp_path: Path) -> None:
    extra = _tar([("etc/profile.d/x.sh", tarfile.REGTYPE, 0o644, b"export X=1")])
    image = build_fake(_layer_from(tmp_path), extra_layers=(extra,))

    assert rejected(image) == "LAYERS_MISMATCH"


@pytest.mark.parametrize(
    "changes",
    [
        {"Config": {"Env": [*BASE_ENV, "TRIVY_SKIP_FILES=**"], "Entrypoint": ["trivy"]}},
        {"Config": {"Env": BASE_ENV, "Entrypoint": ["/bin/sh"]}},
        {"Config": {"Env": BASE_ENV, "Entrypoint": ["trivy"], "User": "0"}},
        {"Config": {"Env": BASE_ENV, "Entrypoint": ["trivy"], "Volumes": {"/data": {}}}},
        {"Architecture": "arm64"},
    ],
    ids=["environment", "entrypoint", "user", "volumes", "architecture"],
)
def test_changed_image_configuration_is_refused(tmp_path: Path, changes: dict[str, Any]) -> None:
    assert rejected(build_fake(_layer_from(tmp_path), inspect_changes=changes)) == "IMAGE_INVALID"


def test_a_configuration_blob_that_differs_from_the_derivation_is_refused(tmp_path: Path) -> None:
    layer = _layer_from(tmp_path)
    forged = json.loads(derived_config(sha(layer), make_lock().labels(), FAKE_BASE_DIFF_IDS))
    forged["config"]["Env"].append("TRIVY_IGNOREFILE=/tmp/x")
    image = build_fake(layer, config_override=json.dumps(forged).encode())

    assert rejected(image) == "CONFIG_MISMATCH"


def test_a_lock_whose_configuration_digest_does_not_derive_is_refused(tmp_path: Path) -> None:
    image = build_fake(_layer_from(tmp_path))

    assert (
        rejected(image, replace(image.lock, config_digest="sha256:" + "0" * 64))
        == "CONFIG_MISMATCH"
    )


def test_export_integrity_problems_are_refused(tmp_path: Path) -> None:
    assert (
        rejected(build_fake(_layer_from(tmp_path), mislabel_blob=True)) == "EXPORT_DIGEST_MISMATCH"
    )
    failed = build_fake(_layer_from(tmp_path))
    failed.save_returncode = 1
    assert rejected(failed) == "EXPORT_FAILED"


def test_a_missing_image_is_refused(tmp_path: Path) -> None:
    lock = build_fake(_layer_from(tmp_path)).lock
    with pytest.raises(ImageError, match="IMAGE_NOT_FOUND"):
        verify_image(FakeDocker(None), lock, base_diff_ids=FAKE_BASE_DIFF_IDS)  # type: ignore[arg-type]


# --- Security review S3 (final audit) ----------------------------------------------------------


def test_a_lock_cannot_claim_other_metadata_than_the_verified_file(tmp_path: Path) -> None:
    # Regression S3-2: freshness is decided from the lock's metadata. A lock edited to a
    # recent UpdatedAt (everything else genuine) was accepted, so an expired database
    # looked FRESH. The metadata must now equal the verified metadata.json.
    image = build_fake(_layer_from(tmp_path))
    recent = datetime(2099, 1, 1, tzinfo=UTC)
    forged = replace(
        image.lock,
        metadata=replace(image.lock.metadata, updated_at=recent, next_update=recent),
    )

    assert rejected(image, forged) == "METADATA_MISMATCH"


@pytest.mark.parametrize(
    "missing",
    [
        b"npm::GitHub Security Advisory npm",
        b"pip::GitHub Security Advisory pip",
        b"maven::GitHub Security Advisory Maven",
    ],
)
def test_a_database_without_advisories_for_a_reviewed_ecosystem_is_refused(
    tmp_path: Path, missing: bytes
) -> None:
    # Regression S3-3: a structurally valid database without, say, npm advisories made
    # Trivy report every npm package clean (verified with a synthetic Maven-only database).
    database = fake_bolt(fill=BUCKETS.replace(missing, b"x" * len(missing)))
    image = build_fake(_layer_from(tmp_path, database=database), database=database)

    assert rejected(image) == "DATABASE_COVERAGE_MISSING"
    directory = _database_dir(tmp_path)
    (directory / "trivy.db").write_bytes(database)
    with pytest.raises(ImageError, match="DATABASE_COVERAGE_MISSING"):
        read_database(directory)


def test_bucket_names_split_across_read_chunks_are_found(tmp_path: Path) -> None:
    # The coverage scan reads 1 MiB chunks; a name straddling two chunks must still count.
    page = 4096
    pages = (trivy_image._CHUNK // page) + 4
    database = bytearray(fake_bolt(pages=pages, fill=b"\0"))
    offset = trivy_image._CHUNK - 10
    database[offset : offset + len(BUCKETS)] = BUCKETS
    directory = _database_dir(tmp_path)
    (directory / "trivy.db").write_bytes(bytes(database))

    assert read_database(directory).db_size == len(database)


def _resealed(database: bytes, field_offset: int, value: int) -> bytes:
    """Both meta pages with one 64-bit field changed and their checksums recomputed: a
    consistent but wrong header, as a careful forger would write it."""
    data = bytearray(database)
    for index in (0, 1):
        start = index * 4096 + 16
        struct.pack_into("<Q", data, start + field_offset, value)
        meta = bytes(data[start : start + 56])
        struct.pack_into("<Q", data, start + 56, trivy_image._fnv64a(meta))
    return bytes(data)


@pytest.mark.parametrize(
    ("field_offset", "value"),
    [(16, 6), (32, 7), (40, 7)],
    ids=["root-at-high-water-mark", "freelist-beyond-high-water-mark", "pages-beyond-file"],
)
def test_resealed_but_inconsistent_meta_pages_are_refused(field_offset: int, value: int) -> None:
    database = _resealed(DATABASE, field_offset, value)
    with pytest.raises(ImageError, match="DATABASE_STRUCTURE_INVALID"):
        check_bolt_structure(database, len(DATABASE))


def test_verification_stops_the_export_when_interrupted(tmp_path: Path) -> None:
    # Cancellation (worker shutdown) during the start-up verification kills docker save.
    image = build_fake(_layer_from(tmp_path))
    killed: list[bool] = []

    class Interrupting(FakeProcess):
        def __init__(self) -> None:
            super().__init__(b"", 0)
            self.stdout = self

        def read(self, size: int = -1) -> bytes:
            raise KeyboardInterrupt

        def kill(self) -> None:
            killed.append(True)

    class Docker(FakeDocker):
        def start(self, arguments: list[str], stdin: bool = False) -> Any:
            return Interrupting()

    with pytest.raises(KeyboardInterrupt):
        verify_image(Docker(image), image.lock, base_diff_ids=FAKE_BASE_DIFF_IDS)  # type: ignore[arg-type]
    assert killed == [True]


# --- Loading the image (GitHub Actions run #11) -------------------------------------------------


class _PosixLoad:
    """A ``docker image load`` process with CPython's POSIX ``communicate()`` semantics:
    it starts by flushing stdin, which raises on a pipe the caller already closed."""

    def __init__(self, returncode: int = 0) -> None:
        self.stdin = io.BytesIO()
        self.received = b""
        self.returncode = returncode
        self.killed = False

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        self.stdin.flush()  # ValueError: I/O operation on closed file, as on Linux
        self.received = self.stdin.getvalue()
        self.stdin.close()
        return b"Loaded image\n", b""

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


class _LoadDocker:
    def __init__(self, process: Any) -> None:
        self.process = process
        self.arguments: list[str] = []

    def start(self, arguments: list[str], stdin: bool = False) -> Any:
        self.arguments = arguments
        assert stdin
        return self.process


def test_the_image_stream_is_handed_to_docker_load_with_posix_semantics() -> None:
    # Regression for CI run #11: build_image closed stdin before communicate(), which
    # works on Windows but raises "flush of closed file" on Linux runners.
    process = _PosixLoad()
    docker = _LoadDocker(process)

    trivy_image._load(docker, lambda sink: sink.write(b"oci-layout-bytes"))  # type: ignore[arg-type]

    assert docker.arguments == ["image", "load", "--quiet"]
    assert process.received == b"oci-layout-bytes"
    assert process.stdin.closed
    assert not process.killed


def test_a_failed_load_or_writer_kills_docker_load() -> None:
    failed = _PosixLoad(returncode=1)
    with pytest.raises(ImageError, match="LOAD_FAILED"):
        trivy_image._load(_LoadDocker(failed), lambda sink: sink.write(b"x"))  # type: ignore[arg-type]

    interrupted = _PosixLoad()

    def write(sink: Any) -> None:
        raise ImageError("BASE_MISMATCH")

    with pytest.raises(ImageError, match="BASE_MISMATCH"):
        trivy_image._load(_LoadDocker(interrupted), write)  # type: ignore[arg-type]
    assert interrupted.killed


def test_the_image_stream_reaches_a_real_process() -> None:
    # A real child process stands in for docker: on the Linux CI runners this exercises
    # CPython's POSIX communicate() itself.
    class Cli:
        def start(self, arguments: list[str], stdin: bool = False) -> Any:
            script = (
                "import sys; data = sys.stdin.buffer.read(); "
                "sys.exit(0 if data == b'x' * 70000 else 3)"
            )
            return subprocess.Popen(  # noqa: S603 - fixed interpreter and script
                [sys.executable, "-I", "-c", script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

    trivy_image._load(Cli(), lambda sink: sink.write(b"x" * 70000))  # type: ignore[arg-type]


# --- The archive docker load receives (GitHub Actions run #12) ---------------------------------


def test_the_docker_archive_manifest_names_the_config_and_every_layer() -> None:
    config = "sha256:" + "c" * 64
    layers = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]

    manifest = json.loads(
        trivy_image.docker_archive_manifest("sentinelpipe-local/trivy-db:t", config, layers)
    )

    assert manifest == [
        {
            "Config": "blobs/sha256/" + "c" * 64,
            "RepoTags": ["sentinelpipe-local/trivy-db:t"],
            "Layers": ["blobs/sha256/" + "1" * 64, "blobs/sha256/" + "2" * 64],
        }
    ]


class _CapturingLoad(_PosixLoad):
    """Keeps the streamed archive (the stream is closed by communicate())."""

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        self.stdin.flush()
        self.received = self.stdin.getvalue()
        return b"", b""


class _BuildDocker:
    def __init__(self) -> None:
        self.load = _CapturingLoad()

    def start(self, arguments: list[str], stdin: bool = False) -> Any:
        assert arguments == ["image", "load", "--quiet"]
        return self.load

    def call(self, arguments: list[str], timeout: float = 30) -> subprocess.CompletedProcess[bytes]:
        # Stop after loading: this test is about the archive, not the verification.
        return subprocess.CompletedProcess(arguments, 1, b"", b"")


def test_the_archive_loads_on_the_classic_and_the_containerd_image_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression for CI run #12: the archive had only the OCI index. Docker 28's classic
    # store (GitHub Ubuntu runners) requires manifest.json and otherwise fell back to the
    # legacy format: "open .../repositories: no such file or directory". The containerd
    # store reads index.json. Both must be present and agree.
    base_layers = [gzip.compress(BASE_LAYER_A, mtime=0), BASE_LAYER_B]
    export = trivy_image._Export()
    for blob in base_layers:
        export.blobs[sha(blob)] = trivy_image._Blob(digest=sha(blob), size=len(blob), content=blob)
    base_manifest = {
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": sha(b),
                "size": len(b),
            }
            for b in base_layers
        ]
    }
    monkeypatch.setattr(trivy_image, "_base_export", lambda docker: (export, base_manifest))
    docker = _BuildDocker()

    with pytest.raises(ImageError, match="LOAD_FAILED"):
        trivy_image.build_image(docker, _database_dir(tmp_path))  # type: ignore[arg-type]

    with tarfile.open(fileobj=io.BytesIO(docker.load.received)) as archive:
        members = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}  # type: ignore[union-attr]
    assert {"oci-layout", "index.json", "manifest.json"} <= set(members)
    (entry,) = json.loads(members["manifest.json"])
    index = json.loads(members["index.json"])
    oci_manifest = json.loads(members["blobs/sha256/" + index["manifests"][0]["digest"][7:]])
    assert entry["Config"] == "blobs/sha256/" + oci_manifest["config"]["digest"][7:]
    assert entry["Layers"] == [
        "blobs/sha256/" + layer["digest"][7:] for layer in oci_manifest["layers"]
    ]
    assert all(path in members for path in [entry["Config"], *entry["Layers"]])
    assert entry["RepoTags"] == [
        "sentinelpipe-local/trivy-db:"
        + index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"]
    ]
    for path in entry["Layers"]:  # every blob is content-addressed
        assert sha(members[path]) == "sha256:" + path.rsplit("/", 1)[1]


def test_a_failed_load_reports_the_runtime_error_sanitized() -> None:
    token = "ghp_" + "R" * 36

    class Failing(_PosixLoad):
        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            super().communicate(timeout)
            return (
                b"",
                f"open /var/lib/docker/tmp/x/repositories: no such file\x1b[31m {token}".encode(),
            )

    with pytest.raises(ImageError) as raised:
        trivy_image._load(_LoadDocker(Failing(returncode=1)), lambda sink: sink.write(b"x"))  # type: ignore[arg-type]

    assert str(raised.value) == "LOAD_FAILED"
    # The shared sanitizer also redacts long path-like runs; the error itself survives.
    assert "no such file" in raised.value.detail
    assert token not in raised.value.detail
    assert "\x1b" not in raised.value.detail

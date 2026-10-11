"""The Trivy scanner image with an embedded, verified vulnerability database (ADR-0012).

Trivy needs a vulnerability database. The sandbox has no network and no mounts, and the
database (about 1.4 GB uncompressed) is far too large for the bounded stdin channel, so it
is delivered as **one read-only image layer** on top of the pinned upstream Trivy image.

**Construction** (:func:`build_image`, run by an operator or CI, never by a scan):

1. The database directory holds ``trivy.db``, ``metadata.json`` and ``provenance.json``,
   produced by ``scripts/trivy/fetch-trivy-db.py`` (the upstream OCI artifact, retrieved
   by manifest digest and verified) or ``scripts/trivy/build-fixture-db.sh`` (synthetic
   test data). Both are validated here again.
2. The database layer is a **deterministic** tar built by this module (fixed names, modes,
   owner and timestamps): directories ``opt/sentinelpipe/trivy/db/`` and exactly the two
   database files, read-only.
3. The image configuration is the **vendored, pinned** base configuration
   (``trivy-base-config.json``, the config blob of the pinned image's linux/amd64
   manifest) with that layer's digest appended to ``rootfs.diff_ids``, one history entry
   and informational labels. The configuration digest is therefore a pure function of
   the pinned base and the database layer.
4. The base layers are taken from ``docker save`` of the base image (pulled by digest).
   Before use, the exported configuration must be byte-identical to the pinned one and
   every layer's uncompressed digest must equal the pinned ``diff_id``.
5. The resulting OCI layout is streamed into ``docker load``; nothing is downloaded and
   no Dockerfile or build step runs.

**Verification** (:func:`verify_image`, run by the worker before it accepts the image,
and by :func:`build_image` itself). A lock file only *names* an image; it is never
trusted. The worker:

* validates the lock and recomputes the expected configuration from the pinned base and
  the lock's layer digest. The lock's configuration digest must match;
* inspects the image: architecture, environment, entrypoint and the ordered ``diff_ids``
  must be exactly the pinned base plus one layer;
* exports the image (``docker save``) and checks the export itself, so that nothing rests
  on labels or names: the configuration blob must have the expected digest; every layer's
  uncompressed content must match its ``diff_id``; the database layer must contain
  exactly the expected entries, with modes, and files whose SHA-256 match the lock;
  ``metadata.json`` must be valid schema version 2 and match the lock;
* only then registers the image ID as a verified local sandbox image
  (:func:`~sentinel_worker.sandbox.policy.register_verified_image`).

An arbitrary local image therefore cannot be accepted through configuration: any change
to the base layers, the configuration (environment, entrypoint, user) or the content of
the added layer changes a digest that is checked against content. What configuration
*does* select is which database content is used; that content is data whose upstream
provenance is established when it is fetched (see ADR-0012 for the residual risk).
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import stat
import struct
import tarfile
import threading
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import IO, Any

from sentinel_worker.sandbox.docker import DockerCli, sanitize
from sentinel_worker.sandbox.policy import TRIVY_BASE_IMAGE, register_verified_image

#: Digest of the linux/amd64 image manifest in the pinned Trivy index (provenance chain:
#: index digest in TRIVY_BASE_IMAGE -> this manifest -> BASE_CONFIG_DIGEST).
BASE_MANIFEST_DIGEST = "sha256:9db099105405c648166e6b94155eb32f8da12673cf1f455207f7385cc9a77283"
BASE_CONFIG_DIGEST = "sha256:6d93f1ec925b37c5ce785e416b86cba056e10c8c2914a59a8ea7be18115d6764"
BASE_CONFIG = resources.files(__package__).joinpath("trivy-base-config.json").read_bytes()
#: Trivy's database schema version supported by v0.75.0 (trivy-db SchemaVersion).
DB_SCHEMA_VERSION = 2
#: Inside the image: Trivy's cache directory and its database directory.
CACHE_DIR = "/opt/sentinelpipe/trivy"
DB_DIR = f"{CACHE_DIR}/db"
DB_FILE = "trivy.db"
METADATA_FILE = "metadata.json"
PROVENANCE_FILE = "provenance.json"
LOCK_SCHEMA = "sentinelpipe.trivy-image-lock.v1"
UPSTREAM_REPOSITORY = "ghcr.io/aquasecurity/trivy-db"
FIXTURE_BUILDER = "github.com/aquasecurity/trivy-db/cmd/trivy-db@v0.0.0-20261001090913-650c4091f951"
LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"
MAX_DB_BYTES = 4 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 4096
MAX_SMALL_BLOB_BYTES = 1024 * 1024
#: Bytes of trivy.db kept for the structural check (both bbolt meta pages at any page size).
BOLT_HEAD_BYTES = 2 * 65536
_BOLT_MAGIC = 0xED0CDAED
_BOLT_VERSION = 2
_BOLT_NO_FREELIST = 0xFFFFFFFFFFFFFFFF
#: Advisory buckets the reviewed ecosystems need (trivy-db GHSA data sources). A database
#: without one of them would report every package of that ecosystem as clean.
REQUIRED_BUCKETS = (
    b"maven::GitHub Security Advisory Maven",
    b"npm::GitHub Security Advisory npm",
    b"pip::GitHub Security Advisory pip",
)
_SAVE_TIMEOUT = 900.0
_CHUNK = 1024 * 1024

#: The database layer: directories (mode) then files (mode), in this order.
_LAYER_DIRECTORIES = (
    ("opt/", 0o755),
    ("opt/sentinelpipe/", 0o555),
    ("opt/sentinelpipe/trivy/", 0o555),
    ("opt/sentinelpipe/trivy/db/", 0o555),
)
_LAYER_FILES = (
    f"opt/sentinelpipe/trivy/db/{METADATA_FILE}",
    f"opt/sentinelpipe/trivy/db/{DB_FILE}",
)
_FILE_MODE = 0o444

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_TIME = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{1,9})?Z\Z")
_TAG = re.compile(r"[a-z0-9]{1,64}\Z")


class ImageError(Exception):
    """The image, its database or its lock cannot be trusted. ``code`` is sanitized.
    ``detail`` is an optional, sanitized and bounded excerpt of a container runtime error
    for operator tooling (``trivy-image``); it is never part of ``str(exc)``."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ImageError(code)


if "sha256:" + hashlib.sha256(BASE_CONFIG).hexdigest() != BASE_CONFIG_DIGEST:
    raise ImageError("BASE_CONFIG_NOT_PINNED")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in items}) != len(items):
            raise ValueError("duplicate keys")
        return dict(items)

    def constant(_: str) -> None:
        raise ValueError("non-standard constant")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


def _base_config() -> dict[str, Any]:
    config = _strict_json(BASE_CONFIG)
    if not isinstance(config, dict):  # pragma: no cover - pinned bytes
        raise ImageError("BASE_CONFIG_INVALID")
    return config


BASE_DIFF_IDS: tuple[str, ...] = tuple(_base_config()["rootfs"]["diff_ids"])


# --- database metadata and provenance --------------------------------------------------


def parse_time(value: Any) -> datetime:
    """An RFC 3339 UTC timestamp as Go writes it (up to nanoseconds; truncated to
    microseconds)."""
    match = _TIME.match(value) if isinstance(value, str) else None
    if match is None:
        raise ImageError("METADATA_INVALID")
    fraction = (match.group(2) or ".0")[1:7].ljust(6, "0")
    try:
        return datetime.fromisoformat(f"{match.group(1)}.{fraction}+00:00")
    except ValueError:
        raise ImageError("METADATA_INVALID") from None


@dataclass(frozen=True, slots=True)
class DatabaseMetadata:
    version: int
    updated_at: datetime
    next_update: datetime

    def to_lock(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "updated_at": _format_time(self.updated_at),
            "next_update": _format_time(self.next_update),
        }


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_metadata(raw: bytes) -> DatabaseMetadata:
    """Trivy's ``metadata.json``. Only schema version 2 (Trivy v0.75.0) is accepted."""
    _require(0 < len(raw) <= MAX_METADATA_BYTES, "METADATA_INVALID")
    document = _strict_json(raw)
    if not isinstance(document, dict):
        raise ImageError("METADATA_INVALID")
    _require(
        {"Version", "UpdatedAt", "NextUpdate"}
        <= set(document)
        <= {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"},
        "METADATA_INVALID",
    )
    version = document["Version"]
    _require(type(version) is int, "METADATA_INVALID")
    _require(version == DB_SCHEMA_VERSION, "SCHEMA_VERSION_UNSUPPORTED")
    updated_at = parse_time(document["UpdatedAt"])
    next_update = parse_time(document["NextUpdate"])
    _require(next_update >= updated_at, "METADATA_INVALID")
    return DatabaseMetadata(version, updated_at, next_update)


@dataclass(frozen=True, slots=True)
class DatabaseSource:
    """Where the database came from, as recorded by the trusted preparation step."""

    kind: str
    """UPSTREAM_OCI (the official Trivy DB artifact) or SYNTHETIC_FIXTURE (tests)."""
    manifest_digest: str | None = None
    blob_digest: str | None = None
    advisories_sha256: str | None = None

    def to_document(self) -> dict[str, Any]:
        if self.kind == "UPSTREAM_OCI":
            return {
                "kind": self.kind,
                "repository": UPSTREAM_REPOSITORY,
                "manifest_digest": self.manifest_digest,
                "blob_digest": self.blob_digest,
            }
        return {
            "kind": self.kind,
            "builder": FIXTURE_BUILDER,
            "advisories_sha256": self.advisories_sha256,
        }


def parse_source(document: Any) -> DatabaseSource:
    _require(isinstance(document, dict), "PROVENANCE_INVALID")
    kind = document.get("kind")
    if kind == "UPSTREAM_OCI":
        _require(
            set(document) == {"kind", "repository", "manifest_digest", "blob_digest"},
            "PROVENANCE_INVALID",
        )
        _require(document["repository"] == UPSTREAM_REPOSITORY, "PROVENANCE_INVALID")
        manifest, blob = document["manifest_digest"], document["blob_digest"]
        _require(
            isinstance(manifest, str)
            and bool(_DIGEST.match(manifest))
            and isinstance(blob, str)
            and bool(_DIGEST.match(blob)),
            "PROVENANCE_INVALID",
        )
        return DatabaseSource(kind, manifest_digest=manifest, blob_digest=blob)
    if kind == "SYNTHETIC_FIXTURE":
        _require(set(document) == {"kind", "builder", "advisories_sha256"}, "PROVENANCE_INVALID")
        _require(document["builder"] == FIXTURE_BUILDER, "PROVENANCE_INVALID")
        advisories = document["advisories_sha256"]
        _require(isinstance(advisories, str) and bool(_HEX.match(advisories)), "PROVENANCE_INVALID")
        return DatabaseSource(kind, advisories_sha256=advisories)
    raise ImageError("PROVENANCE_INVALID")


# --- the lock ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImageLock:
    """What the trusted preparation step built. Verified against content before use."""

    source: DatabaseSource
    trivy_db_sha256: str
    trivy_db_size: int
    metadata_sha256: str
    metadata: DatabaseMetadata
    layer_digest: str
    layer_size: int
    config_digest: str
    image_id: str

    def labels(self) -> dict[str, str]:
        return _labels(self.source, self.trivy_db_sha256, self.metadata_sha256)

    def to_bytes(self) -> bytes:
        return (
            _canonical(
                {
                    "schema": LOCK_SCHEMA,
                    "base_image": TRIVY_BASE_IMAGE,
                    "base_config_digest": BASE_CONFIG_DIGEST,
                    "database": {
                        "source": self.source.to_document(),
                        "trivy_db_sha256": self.trivy_db_sha256,
                        "trivy_db_size": self.trivy_db_size,
                        "metadata_sha256": self.metadata_sha256,
                        "metadata": self.metadata.to_lock(),
                    },
                    "layer": {"digest": self.layer_digest, "size": self.layer_size},
                    "image": {"config_digest": self.config_digest, "id": self.image_id},
                }
            )
            + b"\n"
        )


def parse_lock(raw: bytes) -> ImageLock:
    """A strictly validated lock. It is still unverified: see :func:`verify_image`."""
    _require(0 < len(raw) <= 64 * 1024, "LOCK_INVALID")
    document = _strict_json(raw)
    if not isinstance(document, dict):
        raise ImageError("LOCK_INVALID")
    _require(
        set(document)
        == {"schema", "base_image", "base_config_digest", "database", "layer", "image"},
        "LOCK_INVALID",
    )
    _require(document["schema"] == LOCK_SCHEMA, "LOCK_INVALID")
    _require(document["base_image"] == TRIVY_BASE_IMAGE, "LOCK_BASE_MISMATCH")
    _require(document["base_config_digest"] == BASE_CONFIG_DIGEST, "LOCK_BASE_MISMATCH")
    database, layer, image = document["database"], document["layer"], document["image"]
    _require(
        isinstance(database, dict)
        and set(database)
        == {"source", "trivy_db_sha256", "trivy_db_size", "metadata_sha256", "metadata"},
        "LOCK_INVALID",
    )
    _require(isinstance(layer, dict) and set(layer) == {"digest", "size"}, "LOCK_INVALID")
    _require(isinstance(image, dict) and set(image) == {"config_digest", "id"}, "LOCK_INVALID")
    for value in (database["trivy_db_sha256"], database["metadata_sha256"]):
        _require(isinstance(value, str) and bool(_HEX.match(value)), "LOCK_INVALID")
    for value in (layer["digest"], image["config_digest"], image["id"]):
        _require(isinstance(value, str) and bool(_DIGEST.match(value)), "LOCK_INVALID")
    for value, maximum in (
        (database["trivy_db_size"], MAX_DB_BYTES),
        (layer["size"], 2 * MAX_DB_BYTES),
    ):
        _require(type(value) is int and 0 < value <= maximum, "LOCK_INVALID")
    metadata = database["metadata"]
    _require(
        isinstance(metadata, dict) and set(metadata) == {"version", "updated_at", "next_update"},
        "LOCK_INVALID",
    )
    _require(metadata["version"] == DB_SCHEMA_VERSION, "SCHEMA_VERSION_UNSUPPORTED")
    return ImageLock(
        source=parse_source(database["source"]),
        trivy_db_sha256=database["trivy_db_sha256"],
        trivy_db_size=database["trivy_db_size"],
        metadata_sha256=database["metadata_sha256"],
        metadata=DatabaseMetadata(
            DB_SCHEMA_VERSION,
            parse_time(metadata["updated_at"]),
            parse_time(metadata["next_update"]),
        ),
        layer_digest=layer["digest"],
        layer_size=layer["size"],
        config_digest=image["config_digest"],
        image_id=image["id"],
    )


# --- database structure --------------------------------------------------------------------


def _fnv64a(data: bytes) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def check_bolt_structure(head: bytes, size: int) -> None:
    """Structural check of a bbolt file (go.etcd.io/bbolt v1.5.0, the version Trivy v0.75.0
    uses), from its first bytes and its size.

    Both meta pages (page 0 and page 1, at offset 16 after the page header) must carry the
    bbolt magic and version 2, a valid FNV-64a checksum and the same page size; the root
    bucket and freelist must lie below the high-water mark, and the file must hold every
    page up to the high-water mark of the newer meta. A truncated database fails here.
    Without this check Trivy can open a truncated database and report nothing (a false
    clean, verified with the pinned version). It is not a full consistency check: damage
    inside data pages is caught only by the digests (ADR-0012)."""
    if len(head) < 4096:
        raise ImageError("DATABASE_STRUCTURE_INVALID")
    page_size = struct.unpack_from("<I", head, 16 + 8)[0]
    if page_size < 1024 or page_size > 65536 or page_size & (page_size - 1):
        raise ImageError("DATABASE_STRUCTURE_INVALID")
    metas = []
    for index in (0, 1):
        offset = index * page_size + 16
        if len(head) < offset + 64:
            raise ImageError("DATABASE_STRUCTURE_INVALID")
        magic, version, meta_page_size, _, root, _, freelist, pgid, txid, checksum = (
            struct.unpack_from("<IIIIQQQQQQ", head, offset)
        )
        if (
            magic != _BOLT_MAGIC
            or version != _BOLT_VERSION
            or meta_page_size != page_size
            or checksum != _fnv64a(head[offset : offset + 56])
            or root >= pgid
            or (freelist >= pgid and freelist != _BOLT_NO_FREELIST)
        ):
            raise ImageError("DATABASE_STRUCTURE_INVALID")
        metas.append((txid, pgid))
    _, high_water_mark = max(metas)
    if high_water_mark * page_size > size:
        raise ImageError("DATABASE_STRUCTURE_INVALID")


class _BucketScanner:
    """Finds :data:`REQUIRED_BUCKETS` in a byte stream fed in chunks (with overlap)."""

    _OVERLAP = max(len(bucket) for bucket in REQUIRED_BUCKETS)

    def __init__(self) -> None:
        self.found: set[bytes] = set()
        self._tail = b""

    def feed(self, chunk: bytes) -> None:
        if len(self.found) == len(REQUIRED_BUCKETS):
            return
        window = self._tail + chunk
        for bucket in REQUIRED_BUCKETS:
            if bucket not in self.found and bucket in window:
                self.found.add(bucket)
        self._tail = window[-self._OVERLAP :]

    def check(self) -> None:
        """A presence check, not a completeness proof: bucket names are bbolt keys stored
        verbatim. Missing advisory data for a reviewed ecosystem fails closed."""
        if len(self.found) != len(REQUIRED_BUCKETS):
            raise ImageError("DATABASE_COVERAGE_MISSING")


# --- deterministic construction --------------------------------------------------------


def _labels(source: DatabaseSource, db_sha256: str, metadata_sha256: str) -> dict[str, str]:
    """Informational labels (part of the configuration digest; never trusted alone)."""
    labels = {
        "dev.sentinelpipe.trivy-db.source": source.kind,
        "dev.sentinelpipe.trivy-db.trivy-db-sha256": db_sha256,
        "dev.sentinelpipe.trivy-db.metadata-sha256": metadata_sha256,
    }
    if source.manifest_digest is not None:
        labels["dev.sentinelpipe.trivy-db.manifest-digest"] = source.manifest_digest
    return labels


def derived_config(
    layer_digest: str, labels: Mapping[str, str], base_diff_ids: Sequence[str] = BASE_DIFF_IDS
) -> bytes:
    """The image configuration: the pinned base plus the database layer (canonical).
    ``base_diff_ids`` exists for tests with synthetic base layers."""
    config = _base_config()
    config["config"]["Labels"] = {**config["config"].get("Labels", {}), **labels}
    config["rootfs"]["diff_ids"] = [*base_diff_ids, layer_digest]
    config["history"] = [
        *config["history"],
        {
            "created": config["created"],
            "created_by": "sentinelpipe: add the verified Trivy vulnerability database (read-only)",
            "comment": "sentinelpipe.trivy-image.v1",
        },
    ]
    return _canonical(config)


def _header(name: str, kind: bytes, mode: int, size: int) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.size = size
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info.tobuf(format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict")


def _padding(size: int) -> bytes:
    return b"\0" * (-size % tarfile.BLOCKSIZE)


def layer_chunks(metadata: bytes, db_path: Path, db_size: int) -> Iterator[bytes]:
    """The deterministic database layer, as a byte stream. The database file must keep
    its size (and, as verified later, its content) while it is streamed."""
    for name, mode in _LAYER_DIRECTORIES:
        yield _header(name, tarfile.DIRTYPE, mode, 0)
    yield _header(_LAYER_FILES[0], tarfile.REGTYPE, _FILE_MODE, len(metadata))
    yield metadata + _padding(len(metadata))
    yield _header(_LAYER_FILES[1], tarfile.REGTYPE, _FILE_MODE, db_size)
    streamed = 0
    with db_path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            streamed += len(chunk)
            if streamed > db_size:
                raise ImageError("DATABASE_CHANGED")
            yield chunk
    if streamed != db_size:
        raise ImageError("DATABASE_CHANGED")
    yield _padding(db_size) + b"\0" * (2 * tarfile.BLOCKSIZE)


class _ChunkReader(io.RawIOBase):
    """A readable file over an iterator of byte chunks."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)
        self._buffer = b""

    def readable(self) -> bool:
        return True

    def readinto(self, target: Any) -> int:
        while not self._buffer:
            chunk = next(self._chunks, None)
            if chunk is None:
                return 0
            self._buffer = chunk
        size = min(len(target), len(self._buffer))
        target[:size] = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return size


@dataclass(frozen=True, slots=True)
class _Database:
    source: DatabaseSource
    metadata_raw: bytes
    metadata: DatabaseMetadata
    db_path: Path
    db_size: int
    db_sha256: str


def read_database(directory: Path) -> _Database:
    """Validates a prepared database directory (no links, bounded, schema 2)."""

    def regular(name: str, maximum: int) -> Path:
        path = directory / name
        try:
            info = path.lstat()
        except OSError:
            raise ImageError("DATABASE_MISSING") from None
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "DATABASE_INVALID")
        _require(0 < info.st_size <= maximum, "DATABASE_INVALID")
        return path

    provenance = _strict_json(regular(PROVENANCE_FILE, 64 * 1024).read_bytes())
    metadata_raw = regular(METADATA_FILE, MAX_METADATA_BYTES).read_bytes()
    metadata = parse_metadata(metadata_raw)
    db_path = regular(DB_FILE, MAX_DB_BYTES)
    db_size = db_path.stat().st_size
    digest = hashlib.sha256()
    head = b""
    buckets = _BucketScanner()
    with db_path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            if len(head) < BOLT_HEAD_BYTES:
                head += chunk[: BOLT_HEAD_BYTES - len(head)]
            digest.update(chunk)
            buckets.feed(chunk)
    _require(db_path.stat().st_size == db_size, "DATABASE_CHANGED")
    check_bolt_structure(head, db_size)
    buckets.check()
    if isinstance(provenance, dict) and "trivy_db_sha256" in provenance:
        # The fetch script records the digest it extracted; it must still match.
        _require(provenance.pop("trivy_db_sha256") == digest.hexdigest(), "DATABASE_CHANGED")
    return _Database(
        parse_source(provenance), metadata_raw, metadata, db_path, db_size, digest.hexdigest()
    )


def _layer_identity(database: _Database) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in layer_chunks(database.metadata_raw, database.db_path, database.db_size):
        digest.update(chunk)
        size += len(chunk)
    return "sha256:" + digest.hexdigest(), size


# --- docker save parsing ------------------------------------------------------------------


class _HashingReader(io.RawIOBase):
    """Reads through ``source`` and hashes everything read."""

    def __init__(self, source: IO[bytes]) -> None:
        self._source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def readable(self) -> bool:
        return True

    def readinto(self, target: Any) -> int:
        data = self._source.read(len(target))
        if not data:
            return 0
        self.digest.update(data)
        self.size += len(data)
        target[: len(data)] = data
        return len(data)


@dataclass(slots=True)
class _Blob:
    digest: str
    size: int
    uncompressed_digest: str | None = None
    content: bytes | None = None
    layer: dict[str, Any] | None = None
    heads: dict[str, bytes] = field(default_factory=dict)
    buckets: dict[str, _BucketScanner] = field(default_factory=dict)


@dataclass(slots=True)
class _Export:
    blobs: dict[str, _Blob] = field(default_factory=dict)
    index: bytes | None = None


def _drain_hash(
    stream: IO[bytes], keep: int = 0, buckets: _BucketScanner | None = None
) -> tuple[str, int, bytes]:
    """(sha256 digest, size, the first ``keep`` bytes) of a stream; feeds ``buckets``."""
    digest = hashlib.sha256()
    size = 0
    head = b""
    while chunk := stream.read(_CHUNK):
        if len(head) < keep:
            head += chunk[: keep - len(head)]
        digest.update(chunk)
        size += len(chunk)
        if buckets is not None:
            buckets.feed(chunk)
    return "sha256:" + digest.hexdigest(), size, head


def _inspect_layer(
    stream: IO[bytes], heads: dict[str, bytes], buckets: dict[str, _BucketScanner]
) -> dict[str, Any]:
    """Entries of an (uncompressed) layer tar: name -> (type, mode, size, sha256 or None,
    uid, gid, link). Hashes file content and keeps the first bytes of each file in
    ``heads``; never extracts. Raises ImageError on anything unexpected."""
    entries: dict[str, Any] = {}
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                _require(len(entries) < 16 and member.name not in entries, "LAYER_CONTENT_INVALID")
                content_sha256 = None
                if member.isfile():
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise ImageError("LAYER_CONTENT_INVALID")
                    buckets[member.name] = _BucketScanner()
                    digest, _, heads[member.name] = _drain_hash(
                        handle, BOLT_HEAD_BYTES, buckets[member.name]
                    )
                    content_sha256 = digest[len("sha256:") :]
                entries[member.name] = (
                    member.type,
                    member.mode,
                    member.size,
                    content_sha256,
                    member.uid,
                    member.gid,
                    member.linkname,
                )
            # Consume the end-of-archive blocks so the caller's digest covers them.
            while stream.read(_CHUNK):
                pass
    except (tarfile.TarError, OSError, EOFError):
        raise ImageError("LAYER_CONTENT_INVALID") from None
    return entries


def _read_blob(member_stream: IO[bytes], size: int, layer_size: int, keep: bool) -> _Blob:
    reader = _HashingReader(member_stream)
    buffered = io.BufferedReader(reader, buffer_size=_CHUNK)
    head = buffered.peek(2)[:2]
    blob = _Blob(digest="", size=0)
    if size == layer_size and head != b"\x1f\x8b":
        # Candidate database layer (uncompressed, any size): inspect while hashing. A
        # blob that is not a valid layer of the expected shape fails the verification.
        blob.layer = _inspect_layer(buffered, blob.heads, blob.buckets)
    elif keep or size <= MAX_SMALL_BLOB_BYTES:
        blob.content = buffered.read()
    elif head == b"\x1f\x8b":
        try:
            blob.uncompressed_digest = _drain_hash(gzip.GzipFile(fileobj=buffered))[0]
        except (OSError, EOFError, zlib.error):
            raise ImageError("EXPORT_INVALID") from None
    while buffered.read(_CHUNK):
        pass
    blob.digest = "sha256:" + reader.digest.hexdigest()
    blob.size = reader.size
    if blob.uncompressed_digest is None and blob.content is None:
        blob.uncompressed_digest = blob.digest
    return blob


def _parse_export(stream: IO[bytes], layer_size: int, keep: bool = False) -> _Export:
    """Streams a ``docker save`` (OCI layout) archive, hashing every blob. ``keep`` keeps
    every blob's bytes (only for the small base image, when building)."""
    export = _Export()
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                if member.isdir():
                    continue
                _require(member.isfile(), "EXPORT_INVALID")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ImageError("EXPORT_INVALID")
                if member.name.startswith("blobs/sha256/"):
                    _require(len(export.blobs) < 64, "EXPORT_INVALID")
                    blob = _read_blob(handle, member.size, layer_size, keep)
                    _require(
                        blob.digest == "sha256:" + member.name[len("blobs/sha256/") :],
                        "EXPORT_DIGEST_MISMATCH",
                    )
                    if blob.content is not None:
                        blob.uncompressed_digest = _small_uncompressed(blob.content)
                    export.blobs[blob.digest] = blob
                elif member.name == "index.json":
                    _require(member.size <= MAX_SMALL_BLOB_BYTES, "EXPORT_INVALID")
                    export.index = handle.read()
                else:
                    while handle.read(_CHUNK):
                        pass
    except tarfile.TarError:
        raise ImageError("EXPORT_INVALID") from None
    return export


def _small_uncompressed(content: bytes) -> str:
    if content[:2] == b"\x1f\x8b":
        try:
            return "sha256:" + hashlib.sha256(gzip.decompress(content)).hexdigest()
        except (OSError, EOFError, zlib.error):
            raise ImageError("EXPORT_INVALID") from None
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _manifest_from_export(export: _Export) -> dict[str, Any]:
    """The single image manifest an export describes (descending into an index)."""
    if export.index is None:
        raise ImageError("EXPORT_INVALID")
    document = _strict_json(export.index)
    for _ in range(3):
        if not isinstance(document, dict):
            raise ImageError("EXPORT_INVALID")
        if "layers" in document:
            return document
        manifests = document.get("manifests")
        if not isinstance(manifests, list):
            raise ImageError("EXPORT_INVALID")
        candidates = [
            entry
            for entry in manifests
            if isinstance(entry, dict)
            and str(entry.get("mediaType", "")).endswith(
                ("manifest.v1+json", "manifest.v2+json", "index.v1+json", "list.v2+json")
            )
            and "artifactType" not in entry
            and entry.get("platform", {"architecture": "amd64", "os": "linux"})
            == {"architecture": "amd64", "os": "linux"}
        ]
        _require(len(candidates) == 1, "EXPORT_INVALID")
        blob = export.blobs.get(candidates[0].get("digest", ""))
        if blob is None or blob.content is None:
            raise ImageError("EXPORT_INVALID")
        document = _strict_json(blob.content)
    raise ImageError("EXPORT_INVALID")


def _export(
    docker: DockerCli, reference: str, layer_size: int, keep: bool = False
) -> tuple[_Export, dict[str, Any]]:
    process = docker.start(["image", "save", reference])
    stdout, errors = process.stdout, process.stderr
    if stdout is None or errors is None:
        raise ImageError("EXPORT_FAILED")
    stderr = bytearray()

    def drain() -> None:
        with contextlib.suppress(OSError, ValueError):
            while chunk := errors.read(4096):
                if len(stderr) < 4096:
                    stderr.extend(chunk[: 4096 - len(stderr)])

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        export = _parse_export(stdout, layer_size, keep)
        while stdout.read(_CHUNK):
            pass
        returncode = process.wait(timeout=_SAVE_TIMEOUT)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        reader.join(timeout=5)
    _require(returncode == 0, "EXPORT_FAILED")
    return export, _manifest_from_export(export)


def _check_layers(export: _Export, manifest: dict[str, Any], diff_ids: Sequence[str]) -> None:
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != len(diff_ids):
        raise ImageError("LAYERS_MISMATCH")
    for descriptor, diff_id in zip(layers, diff_ids, strict=True):
        _require(isinstance(descriptor, dict), "EXPORT_INVALID")
        blob = export.blobs.get(descriptor.get("digest", ""))
        if blob is None:
            raise ImageError("EXPORT_INVALID")
        _require(descriptor.get("size") == blob.size, "EXPORT_INVALID")
        _require(blob.uncompressed_digest == diff_id, "LAYERS_MISMATCH")


# --- verification ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VerifiedImage:
    """A Trivy image whose content was verified against the pinned base and the lock."""

    image_id: str
    lock: ImageLock


def expected_layer_entries(lock: ImageLock) -> dict[str, Any]:
    entries: dict[str, Any] = {
        name.rstrip("/"): (tarfile.DIRTYPE, mode, 0, None, 0, 0, "")
        for name, mode in _LAYER_DIRECTORIES
    }
    entries[_LAYER_FILES[0]] = (tarfile.REGTYPE, _FILE_MODE, None, lock.metadata_sha256, 0, 0, "")
    entries[_LAYER_FILES[1]] = (
        tarfile.REGTYPE,
        _FILE_MODE,
        lock.trivy_db_size,
        lock.trivy_db_sha256,
        0,
        0,
        "",
    )
    return entries


def _layer_matches(found: Mapping[str, Any], lock: ImageLock) -> bool:
    expected = expected_layer_entries(lock)
    if set(found) != set(expected):
        return False
    for name, want in expected.items():
        have = found[name]
        if want[2] is None:  # metadata size is covered by its digest
            want = (*want[:2], have[2], *want[3:])
        if have != want:
            return False
    return True


def verify_image(
    docker: DockerCli,
    lock: ImageLock,
    *,
    base_diff_ids: Sequence[str] = BASE_DIFF_IDS,
    register: bool = True,
) -> VerifiedImage:
    """Verifies the image the lock names, by content (see the module documentation).
    Raises :class:`ImageError`; registers the image for sandbox use on success."""
    expected_config = derived_config(lock.layer_digest, lock.labels(), base_diff_ids)
    config_digest = "sha256:" + hashlib.sha256(expected_config).hexdigest()
    _require(config_digest == lock.config_digest, "CONFIG_MISMATCH")
    inspected = docker.call(["image", "inspect", "--format", "{{json .}}", lock.image_id])
    _require(inspected.returncode == 0, "IMAGE_NOT_FOUND")
    details = _strict_json(inspected.stdout.strip())
    if not isinstance(details, dict):
        raise ImageError("IMAGE_INVALID")
    config = details.get("Config") or {}
    base = _base_config()
    _require(details.get("Id") == lock.image_id, "IMAGE_INVALID")
    _require(
        details.get("Architecture") == "amd64" and details.get("Os") == "linux", "IMAGE_INVALID"
    )
    _require(config.get("Env") == base["config"]["Env"], "IMAGE_INVALID")
    _require(config.get("Entrypoint") == base["config"]["Entrypoint"], "IMAGE_INVALID")
    _require(not config.get("User") and not config.get("Volumes"), "IMAGE_INVALID")
    diff_ids = [*base_diff_ids, lock.layer_digest]
    _require((details.get("RootFS") or {}).get("Layers") == diff_ids, "LAYERS_MISMATCH")
    export, manifest = _export(docker, lock.image_id, lock.layer_size)
    descriptor = manifest.get("config")
    if not isinstance(descriptor, dict):
        raise ImageError("EXPORT_INVALID")
    _require(descriptor.get("digest") == config_digest, "CONFIG_MISMATCH")
    config_blob = export.blobs.get(config_digest)
    _require(config_blob is not None and config_blob.content == expected_config, "CONFIG_MISMATCH")
    _check_layers(export, manifest, diff_ids)
    database_layer = export.blobs[manifest["layers"][-1]["digest"]]
    if database_layer.layer is None:
        raise ImageError("LAYER_CONTENT_INVALID")
    _require(_layer_matches(database_layer.layer, lock), "LAYER_CONTENT_INVALID")
    check_bolt_structure(database_layer.heads.get(_LAYER_FILES[1], b""), lock.trivy_db_size)
    database_layer.buckets.get(_LAYER_FILES[1], _BucketScanner()).check()
    # The lock's metadata decides freshness: it must be exactly the verified metadata.json
    # (security review S3-2: a lock edited to a recent UpdatedAt was otherwise accepted).
    _require(
        parse_metadata(database_layer.heads.get(_LAYER_FILES[0], b"")) == lock.metadata,
        "METADATA_MISMATCH",
    )
    if register:
        register_verified_image(lock.image_id)
    return VerifiedImage(lock.image_id, lock)


def load_and_verify(docker: DockerCli, lock_path: str | os.PathLike[str]) -> VerifiedImage:
    try:
        raw = Path(lock_path).read_bytes()
    except OSError:
        raise ImageError("LOCK_UNREADABLE") from None
    return verify_image(docker, parse_lock(raw))


# --- building ----------------------------------------------------------------------------


def _base_export(docker: DockerCli) -> tuple[_Export, dict[str, Any]]:
    """The pinned base image's exported blobs, verified against the pinned config."""
    export, manifest = _export(docker, TRIVY_BASE_IMAGE, layer_size=-1, keep=True)
    descriptor = manifest.get("config")
    _require(
        isinstance(descriptor, dict) and descriptor.get("digest") == BASE_CONFIG_DIGEST,
        "BASE_MISMATCH",
    )
    blob = export.blobs.get(BASE_CONFIG_DIGEST)
    _require(blob is not None and blob.content == BASE_CONFIG, "BASE_MISMATCH")
    _check_layers(export, manifest, BASE_DIFF_IDS)
    return export, manifest


def _write_member(archive: tarfile.TarFile, name: str, size: int, data: IO[bytes]) -> None:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o444
    info.mtime = 0
    archive.addfile(info, data)


def _load(docker: DockerCli, write: Callable[[IO[bytes]], None]) -> None:
    """Streams an OCI layout into ``docker image load`` through ``write(stdin)``.

    The pipe is left open for ``communicate()``, which flushes and closes it itself.
    Closing it first worked on Windows but fails on Linux, where CPython's POSIX
    ``communicate()`` starts by flushing stdin: "ValueError: flush of closed file"
    (GitHub Actions run #11)."""
    process = docker.start(["image", "load", "--quiet"], stdin=True)
    sink = process.stdin
    if sink is None:
        raise ImageError("LOAD_FAILED")
    try:
        write(sink)
        _, errors = process.communicate(timeout=_SAVE_TIMEOUT)
    except BaseException:
        process.kill()
        process.wait()
        raise
    if process.returncode != 0:
        raise ImageError("LOAD_FAILED", sanitize(errors or b""))


def docker_archive_manifest(name: str, config_digest: str, layers: Sequence[str]) -> bytes:
    """The Docker archive ``manifest.json`` of the loaded image. Docker's classic image
    store (the default on Docker Engine 28, as on the GitHub Ubuntu runners) loads only
    archives with this file; without it, it falls back to the pre-1.10 format and fails
    ("open .../repositories: no such file or directory", CI run #12). The containerd image
    store reads ``index.json``. ``docker save`` writes both, and so does the builder."""
    return _canonical(
        [
            {
                "Config": f"blobs/sha256/{config_digest[len('sha256:') :]}",
                "RepoTags": [name],
                "Layers": [f"blobs/sha256/{digest[len('sha256:') :]}" for digest in layers],
            }
        ]
    )


def build_image(docker: DockerCli, directory: Path) -> ImageLock:
    """Builds, loads and verifies the image for a prepared database directory and returns
    its lock. Requires the pinned base image locally (``docker pull`` by digest)."""
    database = read_database(directory)
    layer_digest, layer_size = _layer_identity(database)
    labels = _labels(
        database.source, database.db_sha256, hashlib.sha256(database.metadata_raw).hexdigest()
    )
    config = derived_config(layer_digest, labels)
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    base_export, base_manifest = _base_export(docker)
    manifest = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {"mediaType": layer["mediaType"], "digest": layer["digest"], "size": layer["size"]}
                for layer in base_manifest["layers"]
            ]
            + [{"mediaType": LAYER_MEDIA_TYPE, "digest": layer_digest, "size": layer_size}],
        }
    )
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    tag = config_digest[len("sha256:") :][:16]
    _require(bool(_TAG.match(tag)), "BUILD_FAILED")
    name = f"sentinelpipe-local/trivy-db:{tag}"
    index = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest_digest,
                    "size": len(manifest),
                    "annotations": {
                        "io.containerd.image.name": f"docker.io/{name}",
                        "org.opencontainers.image.ref.name": tag,
                    },
                }
            ],
        }
    )

    def write(sink: IO[bytes]) -> None:
        with tarfile.open(fileobj=sink, mode="w|", format=tarfile.USTAR_FORMAT) as out:
            layout = b'{"imageLayoutVersion":"1.0.0"}'
            _write_member(out, "oci-layout", len(layout), io.BytesIO(layout))
            for descriptor in base_manifest["layers"]:
                content = base_export.blobs[descriptor["digest"]].content
                if content is None:
                    raise ImageError("BASE_MISMATCH")
                _write_member(
                    out,
                    f"blobs/sha256/{descriptor['digest'][7:]}",
                    len(content),
                    io.BytesIO(content),
                )
            _write_member(
                out,
                f"blobs/sha256/{layer_digest[7:]}",
                layer_size,
                io.BufferedReader(
                    _ChunkReader(
                        layer_chunks(database.metadata_raw, database.db_path, database.db_size)
                    )
                ),
            )
            _write_member(out, f"blobs/sha256/{config_digest[7:]}", len(config), io.BytesIO(config))
            _write_member(
                out, f"blobs/sha256/{manifest_digest[7:]}", len(manifest), io.BytesIO(manifest)
            )
            _write_member(out, "index.json", len(index), io.BytesIO(index))
            archive_manifest = docker_archive_manifest(
                name,
                config_digest,
                [layer["digest"] for layer in base_manifest["layers"]] + [layer_digest],
            )
            _write_member(out, "manifest.json", len(archive_manifest), io.BytesIO(archive_manifest))

    _load(docker, write)
    inspected = docker.call(["image", "inspect", "--format", "{{.Id}}", name])
    _require(inspected.returncode == 0, "LOAD_FAILED")
    image_id = inspected.stdout.decode("ascii", "replace").strip()
    _require(bool(_DIGEST.match(image_id)), "LOAD_FAILED")
    lock = ImageLock(
        source=database.source,
        trivy_db_sha256=database.db_sha256,
        trivy_db_size=database.db_size,
        metadata_sha256=hashlib.sha256(database.metadata_raw).hexdigest(),
        metadata=database.metadata,
        layer_digest=layer_digest,
        layer_size=layer_size,
        config_digest=config_digest,
        image_id=image_id,
    )
    verify_image(docker, lock, register=False)
    return lock

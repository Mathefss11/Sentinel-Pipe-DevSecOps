#!/usr/bin/env python3
"""Fetches the upstream Trivy vulnerability database by pinned digest (ADR-0012).

    python -I scripts/trivy/fetch-trivy-db.py resolve
    python -I scripts/trivy/fetch-trivy-db.py fetch --manifest-digest sha256:<hex> --output DIR

This is the trusted preparation step; it runs with network access and never inside a
scanner sandbox. The worker never downloads anything.

``resolve`` prints the digest that the mutable tag ``ghcr.io/aquasecurity/trivy-db:2``
points at *now*, for an operator to review, and whether Aqua Security's second
distribution point (``mirror.gcr.io/aquasec/trivy-db:2``, operated on other
infrastructure) serves the same database blob. Nothing is written.

``fetch`` retrieves exactly the reviewed artifact:

1. the OCI manifest **by digest**; its bytes must hash to that digest;
2. the manifest must be the Trivy DB artifact: one layer of media type
   ``application/vnd.aquasec.trivy.db.layer.v1.tar+gzip`` within a size bound;
3. the layer blob **by digest**, streamed to disk; its SHA-256 and size must match the
   manifest;
4. the archive must contain exactly ``trivy.db`` and ``metadata.json`` as regular files
   (no links, no paths, bounded sizes); nothing else is extracted;
5. ``metadata.json`` must declare schema version 2 (Trivy v0.75.0);
6. ``provenance.json`` records the repository, manifest digest, blob digest and the
   SHA-256 of the extracted ``trivy.db``.

Before downloading, ``fetch`` requires the mirror to serve the **same blob digest**
(corroboration by an independently operated registry). Corroboration is not publisher
authentication: no signature exists for the database (verified on 2026-10-11). Use
``--skip-corroboration`` only when the mirror lags behind, and record why.

Network hygiene: HTTPS only, at most three redirects, and the registry token is never
sent to another host on a redirect (the blob store is a different host).

Then build the image with ``sentinel-worker trivy-image build --db-dir DIR --lock-out ...``.
The Trivy DB is distributed by Aqua Security and aggregates advisory sources under their
own terms; it is not redistributed by this repository (see the runbook).

Standard library only. Anonymous, read-only registry access (no credentials).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REGISTRY = "ghcr.io"
REPOSITORY = "aquasecurity/trivy-db"
MIRROR = "mirror.gcr.io"
MIRROR_REPOSITORY = "aquasec/trivy-db"
MAX_REDIRECTS = 3
TAG = "2"
LAYER_MEDIA_TYPE = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_BLOB_BYTES = 512 * 1024 * 1024
MAX_DB_BYTES = 4 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 4096
SCHEMA_VERSION = 2
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TIMEOUT = 60


class FetchError(Exception):
    pass


class SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Redirects only to HTTPS, at most MAX_REDIRECTS times, and never carries the
    ``Authorization`` header to another host. (urllib's default keeps every header,
    including the token, on any redirect, even to plain HTTP: security review S3-6.)"""

    max_redirections = MAX_REDIRECTS

    def redirect_request(  # type: ignore[override]
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or not target.hostname:
            raise FetchError("refusing a redirect that is not https")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and target.hostname != urllib.parse.urlsplit(req.full_url).hostname:
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(SafeRedirects)


def _open(request: urllib.request.Request | str) -> Any:
    return _OPENER.open(request, timeout=_TIMEOUT)


def _token() -> str:
    url = f"https://{REGISTRY}/token?scope=repository:{REPOSITORY}:pull"
    with _open(url) as response:
        document = json.loads(response.read(64 * 1024))
    token = document.get("token")
    if not isinstance(token, str) or not token:
        raise FetchError("registry token unavailable")
    return token


def _request(path: str, token: str, accept: str | None = None) -> Any:
    request = urllib.request.Request(
        f"https://{REGISTRY}/v2/{REPOSITORY}/{path}",
        headers={"Authorization": f"Bearer {token}", **({"Accept": accept} if accept else {})},
    )
    return _open(request)


def _manifest(reference: str, token: str) -> tuple[bytes, str]:
    with _request(f"manifests/{reference}", token, MANIFEST_MEDIA_TYPE) as response:
        raw = response.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise FetchError("manifest too large")
    return raw, "sha256:" + hashlib.sha256(raw).hexdigest()


def _layer(raw: bytes) -> tuple[str, int]:
    document = json.loads(raw)
    layers = document.get("layers")
    if (
        document.get("mediaType") != MANIFEST_MEDIA_TYPE
        or not isinstance(layers, list)
        or len(layers) != 1
    ):
        raise FetchError("not a single-layer OCI manifest")
    layer = layers[0]
    digest, size = layer.get("digest"), layer.get("size")
    if layer.get("mediaType") != LAYER_MEDIA_TYPE:
        raise FetchError("unexpected layer media type")
    if not isinstance(digest, str) or not _DIGEST.match(digest):
        raise FetchError("invalid layer digest")
    if type(size) is not int or not 0 < size <= MAX_BLOB_BYTES:
        raise FetchError("layer size out of bounds")
    return digest, size


def _metadata(raw: bytes) -> dict[str, Any]:
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("Version") != SCHEMA_VERSION:
        raise FetchError("unsupported database schema version")
    for key in ("UpdatedAt", "NextUpdate"):
        if not isinstance(document.get(key), str):
            raise FetchError("invalid database metadata")
    return document


def resolve() -> int:
    token = _token()
    raw, digest = _manifest(TAG, token)
    blob_digest, size = _layer(raw)
    created = json.loads(raw).get("annotations", {}).get("org.opencontainers.image.created")
    mirror = mirror_blob()
    print(json.dumps({"repository": f"{REGISTRY}/{REPOSITORY}", "tag": TAG,
                      "manifest_digest": digest, "blob_digest": blob_digest,
                      "blob_size": size, "created": created,
                      "mirror": f"{MIRROR}/{MIRROR_REPOSITORY}:{TAG}", "mirror_blob_digest": mirror,
                      "corroborated": mirror == blob_digest}, indent=2))  # fmt: skip
    return 0


def mirror_blob() -> str:
    """The blob digest the mirror's tag serves now (anonymous, independent of ghcr.io)."""
    request = urllib.request.Request(
        f"https://{MIRROR}/v2/{MIRROR_REPOSITORY}/manifests/{TAG}",
        headers={"Accept": MANIFEST_MEDIA_TYPE},
    )
    with _open(request) as response:
        raw = response.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise FetchError("mirror manifest too large")
    return _layer(raw)[0]


def fetch(manifest_digest: str, output: Path, corroborate: bool = True) -> int:
    if not _DIGEST.match(manifest_digest):
        raise FetchError("--manifest-digest must be sha256:<64 hex>")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FetchError("the output directory must be empty")
    token = _token()
    raw, digest = _manifest(manifest_digest, token)
    if digest != manifest_digest:
        raise FetchError("manifest digest mismatch")
    blob_digest, blob_size = _layer(raw)
    if corroborate and mirror_blob() != blob_digest:
        raise FetchError(
            "not corroborated: the mirror serves another blob (it may lag; retry later, or "
            "pass --skip-corroboration and record why)"
        )
    if not corroborate:
        print("warning: mirror corroboration skipped", file=sys.stderr)
    with tempfile.TemporaryDirectory(dir=output.parent) as work:
        archive_path = Path(work) / "db.tar.gz"
        hasher, received = hashlib.sha256(), 0
        with _request(f"blobs/{blob_digest}", token) as response, archive_path.open("wb") as out:
            while chunk := response.read(1024 * 1024):
                received += len(chunk)
                if received > blob_size:
                    raise FetchError("blob larger than declared")
                hasher.update(chunk)
                out.write(chunk)
        if received != blob_size or "sha256:" + hasher.hexdigest() != blob_digest:
            raise FetchError("blob digest mismatch")
        expected = {"trivy.db": MAX_DB_BYTES, "metadata.json": MAX_METADATA_BYTES}
        seen: set[str] = set()
        db_hasher = hashlib.sha256()
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                if member.name not in expected or member.name in seen or not member.isfile():
                    raise FetchError("unexpected archive entry")
                if not 0 < member.size <= expected[member.name]:
                    raise FetchError("archive entry size out of bounds")
                seen.add(member.name)
                source = archive.extractfile(member)
                if source is None:
                    raise FetchError("unreadable archive entry")
                target = output / member.name
                with source, target.open("xb") as out:
                    while chunk := source.read(1024 * 1024):
                        if member.name == "trivy.db":
                            db_hasher.update(chunk)
                        out.write(chunk)
        if seen != set(expected):
            raise FetchError("archive incomplete")
    metadata = _metadata((output / "metadata.json").read_bytes())
    provenance = {
        "kind": "UPSTREAM_OCI",
        "repository": f"{REGISTRY}/{REPOSITORY}",
        "manifest_digest": manifest_digest,
        "blob_digest": blob_digest,
        "trivy_db_sha256": db_hasher.hexdigest(),
    }
    (output / "provenance.json").write_text(json.dumps(provenance, sort_keys=True) + "\n")
    print(
        json.dumps({"fetched": True, "updated_at": metadata["UpdatedAt"], **provenance}, indent=2)
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("resolve", help="Print the digest the tag points at now (review it).")
    fetch_parser = commands.add_parser("fetch", help="Fetch and verify one pinned artifact.")
    fetch_parser.add_argument("--manifest-digest", required=True)
    fetch_parser.add_argument("--output", required=True, type=Path)
    fetch_parser.add_argument(
        "--skip-corroboration",
        action="store_true",
        help="Do not require the mirror to serve the same blob (record why).",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "resolve":
            return resolve()
        return fetch(args.manifest_digest, args.output, corroborate=not args.skip_corroboration)
    except (FetchError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.umask(0o022)
    sys.exit(main())

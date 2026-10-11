#!/usr/bin/env python3
"""Manual, audited refresh of the Trivy vulnerability database image (ADR-0012).

    python -I scripts/trivy/fetch-trivy-db.py resolve        # review the digest first
    <worker python> scripts/trivy/refresh-trivy-db.py \\
        --manifest-digest sha256:<reviewed> --work-root C:\\trivy \\
        --operator "<name>" --reason "<ticket or reason>" \\
        [--previous-lock C:\\trivy\\trivy-<old>.lock]

Run it with the Python environment where ``sentinel-worker`` is installed. It is an
operator action on a trusted preparation host; it never runs in a scanner sandbox, never
runs unattended and never changes a running worker. It:

1. refuses to reuse or overwrite an existing database directory or lock;
2. fetches exactly the reviewed artifact with ``fetch-trivy-db.py`` (manifest and blob by
   digest, mirror corroboration unless explicitly skipped, schema 2);
3. builds the image and its lock with ``sentinel-worker trivy-image build`` (which ends
   with the full content verification), then verifies it again from the written lock;
4. appends one JSON record to ``<work-root>/refresh-audit.jsonl``: time (UTC), operator,
   reason, artifact digests, database ``UpdatedAt``, lock path and SHA-256, image id,
   whether corroboration was skipped (and why), and the previous lock's SHA-256.

The previous image and lock are left untouched. Switch workers to the new lock only after
this command succeeds (set ``SENTINEL_WORKER_TRIVY_IMAGE_LOCK`` and restart them; each
worker verifies the image again at start), and remove old images only once no worker
uses them. Have a second person review the audit record and the digests before the
switch (see docs/runbooks/trivy.md).

Standard library only, besides the two tools it calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FETCH = HERE / "fetch-trivy-db.py"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TEXT = re.compile(r"[^\x00-\x1f\x7f-\x9f]{1,200}\Z")
AUDIT_LOG = "refresh-audit.jsonl"


class RefreshError(Exception):
    pass


def _run(command: Sequence[str]) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed tools, argument vector, no shell
        list(command), capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        tool = Path(command[1]).name if len(command) > 1 else command[0]
        detail = completed.stderr.strip()[-500:] or completed.stdout.strip()[-500:]
        raise RefreshError(f"{tool} failed: {detail}")
    return completed.stdout


def _report(output: str) -> dict[str, Any]:
    """The JSON object a tool printed last (tools print one JSON document)."""
    start = output.find("{")
    document = json.loads(output[start:]) if start >= 0 else None
    if not isinstance(document, dict):
        raise RefreshError("unexpected tool output")
    return document


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refresh(
    manifest_digest: str,
    work_root: Path,
    operator: str,
    reason: str,
    previous_lock: Path | None = None,
    skip_corroboration: str | None = None,
    run: Callable[[Sequence[str]], str] = _run,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """Fetch, build, verify and audit one reviewed database. Returns the audit record."""
    if not _DIGEST.match(manifest_digest):
        raise RefreshError("--manifest-digest must be sha256:<64 hex>")
    for value, name in ((operator, "--operator"), (reason, "--reason")):
        if not _TEXT.match(value) or not value.strip():
            raise RefreshError(f"{name} must be 1-200 printable characters")
    if skip_corroboration is not None and not _TEXT.match(skip_corroboration):
        raise RefreshError("--skip-corroboration needs a printable reason")
    short = manifest_digest[len("sha256:") :][:16]
    db_dir = work_root / f"db-{short}"
    lock = work_root / f"trivy-{short}.lock"
    if db_dir.exists() or lock.exists():
        raise RefreshError("this database was already prepared; review the existing lock")
    previous = None
    if previous_lock is not None:
        previous = _sha256(previous_lock)
    work_root.mkdir(parents=True, exist_ok=True)

    fetch = [sys.executable, "-I", str(FETCH), "fetch", "--manifest-digest", manifest_digest,
             "--output", str(db_dir)]  # fmt: skip
    if skip_corroboration is not None:
        fetch.append("--skip-corroboration")
    fetched = _report(run(fetch))
    worker = [sys.executable, "-m", "sentinel_worker", "trivy-image"]
    built = _report(run([*worker, "build", "--db-dir", str(db_dir), "--lock-out", str(lock)]))
    verified = _report(run([*worker, "verify", "--lock", str(lock)]))
    if not verified.get("verified") or verified.get("image_id") != built.get("image_id"):
        raise RefreshError("the new image did not verify")
    lock_document = json.loads(lock.read_bytes())
    record = {
        "time": now().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operator": operator,
        "reason": reason,
        "manifest_digest": manifest_digest,
        "blob_digest": fetched.get("blob_digest"),
        "trivy_db_sha256": lock_document["database"]["trivy_db_sha256"],
        "updated_at": lock_document["database"]["metadata"]["updated_at"],
        "lock": str(lock),
        "lock_sha256": _sha256(lock),
        "image_id": built.get("image_id"),
        "config_digest": lock_document["image"]["config_digest"],
        "corroboration_skipped": skip_corroboration,
        "previous_lock_sha256": previous,
    }
    with (work_root / AUDIT_LOG).open("a", encoding="utf-8") as audit:
        audit.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--previous-lock", type=Path)
    parser.add_argument(
        "--skip-corroboration", metavar="WHY", help="Only when the mirror lags; recorded."
    )
    args = parser.parse_args(argv)
    try:
        record = refresh(args.manifest_digest, args.work_root, args.operator, args.reason,
                         args.previous_lock, args.skip_corroboration)  # fmt: skip
    except (RefreshError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(record, indent=2))
    print(
        "next: have the record reviewed, then point SENTINEL_WORKER_TRIVY_IMAGE_LOCK at "
        f"{record['lock']} and restart the Trivy workers (they verify the image at start).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

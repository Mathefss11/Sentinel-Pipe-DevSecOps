"""Normalized findings and the ``findings.v1`` evidence document (ADR-0010).

Every scanner adapter turns its native report into :class:`Finding` values and the worker
serializes them with :func:`build_document`:

* **Paths:** findings carry only the *safe* path (:mod:`.paths`): components that look
  like or were detected as secrets are replaced by labels. Raw paths are never persisted.
* **Fingerprint:** SHA-256 of the canonical JSON array ``["sentinelpipe.finding.v1",
  scanner, rule_id, target, safe path, start_line, end_line, start_column, end_column]``.
  It is deterministic for identical input and contains no secret value and no raw path.
  It is location-based, so it changes when the finding moves; cross-commit correlation
  is M4 work.
* **Deduplication:** findings with the same fingerprint in one run are merged into one,
  with ``occurrences`` counting them.
* **Identity:** ``id`` is a UUIDv5 of the job id and the fingerprint, so rebuilding the same
  job's document yields the same bytes.
* **Order:** by path, start line, start column, rule id and fingerprint.
* **Canonical bytes:** UTF-8/ASCII, sorted keys, no whitespace (as ``job-result.v1``).

The document is validated against the bundled schema and bounded (1000 findings, 1 MiB).
Exceeding a bound raises :class:`FindingsLimitError`; findings are never dropped silently.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sentinel_worker.execution.evidence import MAX_ARTIFACT_BYTES
from sentinel_worker.execution.leases import JobLease
from sentinel_worker.execution.results import canonical_json
from sentinel_worker.messaging import contracts
from sentinel_worker.repository.snapshot import (
    INCOMPLETE_COVERAGE,
    RepositorySnapshot,
    SkipReason,
)

SCHEMA_VERSION = 1
MAX_FINDINGS = 1000
FINGERPRINT_DOMAIN = "sentinelpipe.finding.v1"
#: Namespace of finding ids (UUIDv5 over ``"<job id>/<fingerprint>"``).
FINDING_NAMESPACE = uuid.UUID("5b0f6d1e-2c3a-5e4f-9a8b-7c6d5e4f3a2b")

_SECRET_LIKE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


class FindingsLimitError(Exception):
    """The findings exceed the supported bounds (count or document size)."""


@dataclass(frozen=True, slots=True)
class Scanner:
    name: str
    version: str
    image: str


FILE_CONTENT = "FILE_CONTENT"
FILE_PATH = "FILE_PATH"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    category: str
    description: str | None
    path: str
    """The safe path (see :mod:`.paths`), never the raw path of a redacted name."""
    start_line: int | None
    end_line: int | None
    start_column: int | None
    end_column: int | None
    target: str = FILE_CONTENT
    """FILE_CONTENT (lines and columns in the file) or FILE_PATH (the file's name)."""
    path_redacted: bool = False
    severity: str | None = None
    confidence: str | None = None

    def fingerprint(self, scanner: Scanner) -> str:
        identity = [
            FINGERPRINT_DOMAIN,
            scanner.name,
            self.rule_id,
            self.target,
            self.path,
            self.start_line,
            self.end_line,
            self.start_column,
            self.end_column,
        ]
        return hashlib.sha256(canonical_json_value(identity)).hexdigest()


def canonical_json_value(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def safe_text(value: str, limit: int) -> str:
    """Defense in depth for scanner-provided prose (descriptions): control characters
    removed, long token-like runs redacted, length bounded."""
    text = _CONTROL.sub(" ", value)
    text = _SECRET_LIKE.sub("[redacted]", text)
    return " ".join(text.split())[:limit]


def build_document(
    scanner: Scanner,
    lease: JobLease,
    snapshot: RepositorySnapshot,
    findings: Iterable[Finding],
    exit_code: int,
    raw_report_sha256: str,
    limitations: Iterable[str],
    paths_redacted: int = 0,
) -> bytes:
    """Canonical findings.v1 bytes. Raises :class:`FindingsLimitError` when the findings
    exceed the bounds, :class:`ValueError` if the document would violate the schema."""
    merged: dict[str, tuple[Finding, int]] = {}
    for finding in findings:
        key = finding.fingerprint(scanner)
        previous = merged.get(key)
        merged[key] = (finding, previous[1] + 1 if previous else 1)
    if len(merged) > MAX_FINDINGS:
        raise FindingsLimitError("too many findings")
    ordered = sorted(
        merged.items(),
        key=lambda item: (
            item[1][0].path,
            item[1][0].target,
            item[1][0].start_line or 0,
            item[1][0].start_column or 0,
            item[1][0].rule_id,
            item[0],
        ),
    )
    skipped = {reason.value: snapshot.skipped.get(reason, 0) for reason in SkipReason}
    all_limitations = set(limitations)
    if not snapshot.complete:
        all_limitations.add("FILES_SKIPPED")
    if not snapshot.files:
        # Nothing was scanned: never to be read as a clean repository.
        all_limitations.add("EMPTY_INPUT")
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scanner": {"name": scanner.name, "version": scanner.version, "image": scanner.image},
        "context": {
            "organization_id": str(lease.organization_id),
            "project_id": str(lease.project_id),
            "scan_id": str(lease.scan_id),
            "job_id": str(lease.job_id),
            "commit_sha": lease.commit_sha,
        },
        "input": {
            "kind": snapshot.kind,
            "commit_verified": False,
            "content_sha256": snapshot.content_sha256,
            "files_scanned": len(snapshot.files),
            "bytes_scanned": snapshot.total_bytes,
            "paths_redacted": paths_redacted,
            "skipped": skipped,
        },
        "coverage": {
            "complete": not any(skipped[reason.value] for reason in INCOMPLETE_COVERAGE),
            "limitations": sorted(all_limitations),
        },
        "execution": {
            "status": "FINDINGS_DETECTED" if merged else "NO_FINDINGS",
            "exit_code": exit_code,
            "raw_report_sha256": raw_report_sha256,
        },
        "finding_count": len(merged),
        "findings": [
            {
                "id": str(uuid.uuid5(FINDING_NAMESPACE, f"{lease.job_id}/{fingerprint}")),
                "fingerprint": fingerprint,
                "scanner": {"name": scanner.name, "version": scanner.version},
                "rule_id": finding.rule_id,
                "category": finding.category,
                "description": finding.description,
                "location": {
                    "target": finding.target,
                    "path": finding.path,
                    "path_redacted": finding.path_redacted,
                    "start_line": finding.start_line,
                    "end_line": finding.end_line,
                    "start_column": finding.start_column,
                    "end_column": finding.end_column,
                },
                "severity": finding.severity,
                "confidence": finding.confidence,
                # Secret findings never carry any excerpt of the detected value.
                "evidence": {"redacted": True, "excerpt": None},
                "remediation": None,
                "status": "OPEN",
                "occurrences": count,
            }
            for fingerprint, (finding, count) in ordered
        ],
    }
    validator = contracts.validator(contracts.FINDINGS_SCHEMA)
    if next(validator.iter_errors(document), None) is not None:
        raise ValueError("findings document does not conform to findings.v1")
    encoded = canonical_json(document)
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise FindingsLimitError("findings document too large")
    return encoded

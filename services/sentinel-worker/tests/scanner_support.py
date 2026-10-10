# ruff: noqa: S108 - /tmp paths are inside the sandbox, as Gitleaks reports them
"""Helpers for the repository snapshot and scanner tests.

Synthetic credentials are generated at run time, so no credential-shaped literal exists in
the source tree. They are random, not real credentials.
"""

from __future__ import annotations

import base64
import json
import random
import string
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinel_worker.execution.leases import JobLease, Repository
from sentinel_worker.sandbox.docker import SandboxRun, SandboxStatus

OWNER = "acme"


def synthetic_github_token(seed: int) -> str:
    """A random string in the shape of a GitHub personal access token (``github-pat``)."""
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not crypto
    return (
        "ghp" + "_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))
    )


def synthetic_aws_key(seed: int) -> str:
    """A random string in the shape of an AWS access key id (``aws-access-token``)."""
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not crypto
    return "AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))


def make_repository(root: Path, name: str, files: Mapping[str, str | bytes]) -> Path:
    """Writes ``<root>/acme/<name>/<files>`` and returns the repository directory."""
    repository = root / OWNER / name
    repository.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    return repository


def lease(name: str = "repo", scanner_type: str = "GITLEAKS", owner: str = OWNER) -> JobLease:
    now = datetime.now(UTC)
    return JobLease(
        job_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        commit_sha="a" * 40,
        branch="main",
        repository=Repository("GITHUB", owner, name),
        scanner_type=scanner_type,
        attempt=1,
        max_attempts=3,
        epoch=1,
        token="ab" * 32,
        expires_at=now + timedelta(seconds=60),
        lease_duration_seconds=60,
        deadline_at=now + timedelta(minutes=15),
    )


def report_entry(path: str, **overrides: Any) -> dict[str, Any]:
    """One entry of a Gitleaks 8.30.1 JSON report for ``dir`` mode, as observed."""
    entry: dict[str, Any] = {
        "RuleID": "github-pat",
        "Description": "Uncovered a GitHub Personal Access Token.",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 10,
        "EndColumn": 49,
        "Match": "REDACTED",
        "Secret": "REDACTED",
        "File": f"/tmp/input/repo/{path}",
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 4.5,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        "Tags": [],
        "Fingerprint": f"/tmp/input/repo/{path}:github-pat:1",
    }
    entry.update(overrides)
    return entry


def envelope(
    report: bytes,
    paths_report: bytes = b"[]",
    name: str = "gitleaks-report.json",
    paths_name: str = "gitleaks-paths-report.json",
) -> bytes:
    """sandbox-output.v1 as the Gitleaks script emits it: the content and paths reports."""
    artifacts = [(name, report), (paths_name, paths_report)]
    return json.dumps(
        {
            "schema_version": 1,
            "artifacts": [
                {
                    "name": artifact_name,
                    "media_type": "application/json",
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
                for artifact_name, content in artifacts
            ],
        }
    ).encode("utf-8")


def paths_entry(line: int, start: int, end: int, **overrides: Any) -> dict[str, Any]:
    """An entry of the paths report (Gitleaks run over meta/paths.txt)."""
    fields: dict[str, Any] = {
        "File": "/tmp/input/meta/paths.txt",
        "StartLine": line,
        "EndLine": line,
        "StartColumn": start,
        "EndColumn": end,
    }
    return report_entry("x", **(fields | overrides))


def exited(exit_code: int | None, stdout: bytes = b"") -> SandboxRun:
    return SandboxRun(SandboxStatus.EXITED, exit_code, stdout, "", 0.5, 4, 1024, True)

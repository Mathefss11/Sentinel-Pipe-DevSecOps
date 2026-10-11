# ruff: noqa: S108 - /tmp paths are inside the sandbox, as Semgrep reports them
"""Regression tests for the Slice 2 (Semgrep) security review.

A1  unverifiable encodings (UTF-16/32, NUL bytes) are never counted as analyzed;
A2  Python syntax errors Semgrep recovers from silently are reported by the independent
    check; per-reason coverage;
A3  directories named like scanner control files make coverage incomplete instead of
    failing the scan (both adapters);
A4  invisible format characters in names are redacted;
A5  a Gitleaks-only worker never loads the Semgrep module.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import pytest

from scanner_support import exited, lease
from semgrep_support import envelope, report, result
from sentinel_worker.messaging import contracts
from sentinel_worker.repository.snapshot import RepositorySnapshot, SkipReason, SnapshotFile
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.gitleaks import GitleaksAdapter
from sentinel_worker.scanners.paths import safe_paths, suspicious
from sentinel_worker.scanners.semgrep import SemgrepAdapter

ADAPTER = SemgrepAdapter()


def snapshot(files: dict[str, bytes]) -> RepositorySnapshot:
    return RepositorySnapshot(
        files=tuple(SnapshotFile(path, files[path]) for path in sorted(files)), skipped={}
    )


def interpret(snap: RepositorySnapshot, stdout: bytes, code: int = 0) -> dict[str, Any]:
    (artifact,) = ADAPTER.interpret(exited(code, stdout), snap, lease())
    document: dict[str, Any] = json.loads(artifact.content)
    assert list(contracts.validator(contracts.FINDINGS_SCHEMA).iter_errors(document)) == []
    return document


# --- A1: encodings Semgrep cannot analyze -------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "eval(x)\n".encode("utf-16"),
        "eval(x)\n".encode("utf-16-le"),
        "eval(x)\n".encode("utf-16-be"),
        "eval(x)\n".encode("utf-32"),
        b"eval(x)\x00\n",
        b"\xff\xfe" + "中文".encode("utf-16-le"),  # BOM, no NUL byte
    ],
    ids=["utf16-bom", "utf16-le", "utf16-be", "utf32", "nul-byte", "bom-without-nul"],
)
def test_unverifiable_encodings_are_never_counted_as_analyzed(content: bytes) -> None:
    snap = snapshot({"a.js": content, "b.py": b"print(1)\n"})

    document = interpret(snap, envelope(report(scanned=["a.js", "b.py"])))

    coverage = document["coverage"]
    assert coverage["complete"] is False
    assert coverage["files_analyzed"] == 1
    assert coverage["not_analyzed_reasons"]["unverifiable_encoding"] == 1
    assert "FILES_NOT_ANALYZED" in coverage["limitations"]


def test_latin1_and_utf8_bom_sources_remain_analyzable() -> None:
    snap = snapshot({"a.py": b"# caf\xe9\nprint(1)\n", "b.py": b"\xef\xbb\xbfprint(1)\n"})

    document = interpret(snap, envelope(report(scanned=["a.py", "b.py"])))

    assert document["coverage"]["files_analyzed"] == 2
    assert document["coverage"]["complete"] is True


# --- A2: parse errors, independent Python check, reasons -----------------------------


def test_python_syntax_check_failures_make_files_not_analyzed_but_keep_findings() -> None:
    snap = snapshot({"bad.py": b"def f(:\n    eval(x)\n", "ok.py": b"print(1)\n"})
    stdout = envelope(
        report([result("bad.py", line=2)], scanned=["bad.py", "ok.py"]), python_failed=["bad.py"]
    )

    document = interpret(snap, stdout, code=41)

    assert document["finding_count"] == 1  # what Semgrep did find is still reported
    reasons = document["coverage"]["not_analyzed_reasons"]
    assert reasons["parse_error"] == 1
    assert document["coverage"]["complete"] is False


def test_per_file_errors_are_classified_by_reason() -> None:
    snap = snapshot({"a.js": b"x", "b.py": b"x", "c.ts": b"x", "d.java": b"x"})
    errors = [
        {"code": 3, "level": "warn", "type": "Timeout", "path": "/tmp/input/repo/a.js"},
        {"code": 3, "level": "warn", "type": "Out of memory", "path": "/tmp/input/repo/b.py"},
        {"code": 3, "level": "warn", "type": ["PartialParsing", []],
         "path": "/tmp/input/repo/c.ts"},
    ]  # fmt: skip

    document = interpret(snap, envelope(report(scanned=["a.js", "b.py", "c.ts"], errors=errors)))

    assert document["coverage"]["not_analyzed_reasons"] == {
        "scanner_skipped": 1,  # d.java was never scanned
        "parse_error": 1,
        "resource_limit": 2,
        "unverifiable_encoding": 0,
    }
    assert document["coverage"]["files_not_analyzed"] == 4


def test_every_semgrep_document_states_that_parse_completeness_is_unverified() -> None:
    document = interpret(snapshot({"a.py": b"print(1)\n"}), envelope(report(scanned=["a.py"])))

    assert "PARSE_COMPLETENESS_UNVERIFIED" in document["coverage"]["limitations"]


@pytest.mark.parametrize(
    ("check", "code"),
    [
        (b"not json", "INVALID_REPORT"),
        (b'{"failed": [], "extra": 1}', "INVALID_REPORT"),
        (b'{"failed": "a.py"}', "INVALID_REPORT"),
        (b'{"failed": ["missing.py"]}', "UNKNOWN_PATH"),
        (b'{"failed": ["a.js"]}', "UNKNOWN_PATH"),
        (b'{"failed": ["../etc/passwd"]}', "UNKNOWN_PATH"),
    ],
    ids=["json", "extra-key", "type", "foreign-path", "not-python", "traversal"],
)
def test_the_python_check_artifact_is_validated(check: bytes, code: str) -> None:
    snap = snapshot({"a.py": b"x", "a.js": b"x"})

    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(
            exited(0, envelope(report(scanned=["a.py", "a.js"]), python_check=check)), snap, lease()
        )

    assert raised.value.code == code
    assert raised.value.__context__ is None


def test_a_missing_python_check_artifact_is_invalid_output() -> None:
    import base64

    only_report = json.dumps(
        {
            "schema_version": 1,
            "artifacts": [
                {
                    "name": "semgrep-report.json",
                    "media_type": "application/json",
                    "content_base64": base64.b64encode(report()).decode(),
                }
            ],
        }
    ).encode()

    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(exited(0, only_report), snapshot({"a.py": b"x"}), lease())

    assert raised.value.code == "INVALID_OUTPUT"


def test_the_script_checks_python_syntax_in_the_sandbox_without_executing_code() -> None:
    script = ADAPTER.command(snapshot({"a.py": b"x"}))[2]

    assert "ast.parse(" in script
    assert "env -i PATH=/usr/local/bin:/usr/bin:/bin python3 -I -S /tmp/pycheck.py" in script
    for forbidden in ("exec(", "eval(", "compile(", "import_module", "__import__", "runpy"):
        assert forbidden not in script, forbidden


# --- A3: directories named like scanner control files --------------------------------


def test_semgrepignore_directories_are_skipped_as_unsupported_names() -> None:
    snap = snapshot({".semgrepignore/x.py": b"x", "a/.semgrepignore/y.py": b"x", "ok.py": b"x"})

    prepared = ADAPTER.prepare(snap)

    assert prepared.ordered_paths == ("ok.py",)
    assert prepared.skipped == {SkipReason.UNSUPPORTED_NAME: 2}
    assert prepared.complete is False


def test_a_root_gitleaksignore_directory_is_skipped_as_unsupported_names() -> None:
    snap = RepositorySnapshot(
        files=tuple(
            SnapshotFile(p, b"x")
            for p in sorted([".gitleaksignore/a.txt", "sub/.gitleaksignore/b.txt", "ok.txt"])
        ),
        skipped={},
    )

    prepared = GitleaksAdapter().prepare(snap)

    # Gitleaks loads only the root ignore path; nested directories are ordinary content.
    assert prepared.ordered_paths == ("ok.txt", "sub/.gitleaksignore/b.txt")
    assert prepared.skipped == {SkipReason.UNSUPPORTED_NAME: 1}


# --- A4: invisible format characters --------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["key​part​part.txt", "invoice‮gnp.exe", "a⁠b", "﻿token.txt", "x­y"],
    ids=["zero-width-space", "rtl-override", "word-joiner", "bom", "soft-hyphen"],
)
def test_names_with_invisible_format_characters_are_redacted(name: str) -> None:
    assert suspicious(name)
    safe = safe_paths([f"dir/{name}"])[f"dir/{name}"]
    assert safe.redacted
    assert name not in safe.value


def test_ordinary_unicode_names_are_not_redacted() -> None:
    for name in ("ünï cødé.txt", "日本語.md", "файл.py", "naïve-café.js"):
        assert not suspicious(name), name


# --- A5: adapter isolation -------------------------------------------------------------


def test_a_gitleaks_only_worker_never_imports_the_semgrep_module() -> None:
    probe = """
import sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name == "sentinel_worker.scanners.semgrep":
            raise ImportError("blocked for the test")
        return None
sys.meta_path.insert(0, Block())
from sentinel_worker import cli
from sentinel_worker.config import Environment
from sentinel_worker.execution.settings import ExecutionSettings
import tempfile
env = {"SENTINEL_WORKER_DB_USERNAME": "w", "SENTINEL_WORKER_DB_PASSWORD": "pw",
       "SENTINEL_WORKER_GITLEAKS_ENABLED": "true",
       "SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": tempfile.mkdtemp(),
       "SENTINEL_WORKER_DOCKER_CLI": sys.executable}
settings = ExecutionSettings.from_env(Environment.CI, env)
adapter = cli._adapter("gitleaks")
assert settings.gitleaks_enabled and type(adapter).__name__ == "GitleaksAdapter"
assert "sentinel_worker.scanners.semgrep" not in sys.modules
print("isolated")
"""
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and inline probe
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False, timeout=60
    )

    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip() == "isolated"

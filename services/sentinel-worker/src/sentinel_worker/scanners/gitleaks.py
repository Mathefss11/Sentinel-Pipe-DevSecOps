# ruff: noqa: E501 - the constant sandbox script is kept on readable single lines.
"""Gitleaks 8.30.1 secret detection (ADR-0010; runbook docs/runbooks/gitleaks.md).

**Input.** The repository snapshot arrives on stdin as a tar archive with three
top-level directories:

* ``repo/``: the snapshot;
* ``config/``: the worker's ruleset (``gitleaks-rules.toml``, derived from the pinned
  upstream default without path-based allowlists; see below);
* ``meta/``: ``paths.txt``, the snapshot's paths, one per line, so that secrets in
  file *names* are detected with the same rules as content.

The constant script stages the archive in the sandbox's tmpfs and lists it **before**
extracting: every entry must be a regular file or directory (no symbolic or hard links,
devices or FIFOs; BusyBox lists hard links as files with a ``-> target`` suffix, which is
refused), names must be relative, without ``..``, unique, and under ``repo/``,
``config/`` or ``meta/``. It then extracts and verifies:

* ``repo/`` must hold only regular files and directories, exactly the expected number of
  files, and no root ``.gitleaksignore``;
* the ``sha256sum`` digest over every extracted file's name and content must equal the
  worker's (``RepositorySnapshot.extraction_sha256``), so the scanner provably sees exactly
  the snapshot.

This matters because Gitleaks reports a missing or empty target as a clean scan (exit 0,
``[]``).

**Repository-controlled suppression is disabled** (each verified against 8.30.1):

* ``--config`` points at the worker's ruleset, so a repository ``.gitleaks.toml``
  (loaded automatically from the target otherwise) cannot disable rules;
* the ruleset has **no path-based allowlists**. Upstream's global allowlist skips files by
  name (for example ``*.png``, ``node_modules/``, any path containing ``gitleaks.toml``),
  which a repository author controls;
* ``--ignore-gitleaks-allow`` ignores inline ``gitleaks:allow`` comments;
* a root ``.gitleaksignore`` (always loaded from the target) is excluded from the
  snapshot, and ``--gitleaks-ignore-path`` points at the worker's config directory;
* the sandbox has no environment, so ``GITLEAKS_CONFIG``/``GITLEAKS_CONFIG_TOML`` cannot
  be set.

**Exit-code semantics.** Gitleaks itself exits 0 when clean, with ``--exit-code`` (42)
when leaks are found, and 1 on errors. The script runs it twice (content, then paths) and
uses its own codes, distinct from both:

====  ==============================================  ==========================
code  meaning                                         job result
====  ==============================================  ==========================
0     both scans ran, no leaks                        COMPLETED (no findings)
41    leaks in content only                           COMPLETED (findings)
42    leaks in file names only                        COMPLETED (findings)
43    leaks in content and in file names              COMPLETED (findings)
70    Gitleaks failed (any other exit code)           FAILED SCANNER_ERROR
71    input could not be extracted                    FAILED SCANNER_ERROR
72    extracted input differs from the snapshot       FAILED SCANNER_ERROR
73    report missing                                  FAILED SCANNER_ERROR
74    report larger than the supported size           FAILED RESOURCE_LIMIT_EXCEEDED
75    archive refused before extraction (entry type,  FAILED SCANNER_ERROR
      name, duplicate)
====  ==============================================  ==========================

Anything else from 1 to 127 is SCANNER_ERROR; signals are SANDBOX_ERROR. A code that
disagrees with the reports (for example 0 with findings) fails closed.

**Redaction.** ``--redact=100`` makes Gitleaks replace the secret in its reports, so the
raw value never leaves the sandbox in normal operation. Defense in depth in the worker:

* every report entry must say ``Secret: "REDACTED"``;
* ``Match``, ``Secret``, entropy and the Git metadata fields are never kept;
* descriptions are sanitized;
* paths must be files of the snapshot, and are persisted only in their safe form
  (:mod:`.paths`);
* the native reports are parsed in memory and only their digest is recorded.

Errors are raised outside ``except`` blocks, so no exception chain carries report
content.
"""

from __future__ import annotations

import hashlib
import re
from importlib import resources
from typing import Any

from sentinel_worker.execution.evidence import MAX_ARTIFACT_BYTES, Artifact
from sentinel_worker.execution.leases import FailureReason, JobLease
from sentinel_worker.repository.snapshot import (
    InputError,
    InputErrorCode,
    RepositorySnapshot,
    SkipReason,
)
from sentinel_worker.sandbox.docker import SandboxRun
from sentinel_worker.sandbox.policy import GITLEAKS_IMAGE, SandboxPolicy, Workload
from sentinel_worker.sandbox.protocol import InvalidOutputError, parse
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.findings import (
    FILE_CONTENT,
    FILE_PATH,
    Finding,
    FindingsLimitError,
    Scanner,
    build_document,
    safe_text,
)
from sentinel_worker.scanners.paths import components_in_byte_window, safe_paths
from sentinel_worker.scanners.sandbox_input import (
    INPUT_DIR,
    INVALID_JSON,
    PROLOGUE,
    STAGE_AND_VERIFY,
    checked_int,
    failures,
    load_json,
)

SCANNER_TYPE = "GITLEAKS"
IDENTITY = Scanner(name="gitleaks", version="8.30.1", image=GITLEAKS_IMAGE)
EVIDENCE_NAME = "findings.json"
REPORT_NAME = "gitleaks-report.json"
PATHS_REPORT_NAME = "gitleaks-paths-report.json"
#: The pinned, derived ruleset (scripts/dev/derive-gitleaks-rules.py).
CONFIG = resources.files(__package__).joinpath("gitleaks-rules.toml").read_bytes()
MAX_REPORT_BYTES = MAX_ARTIFACT_BYTES
MAX_PATHS_REPORT_BYTES = 256 * 1024
#: Raw report entries accepted before deduplication (each report).
MAX_REPORT_ENTRIES = 5000
LIMITATIONS = (
    "ARCHIVES_NOT_SCANNED",
    "COMMIT_NOT_VERIFIED",
    "GIT_HISTORY_NOT_SCANNED",
    "RULESET_DEFAULT_ONLY",
)

_REPO = f"{INPUT_DIR}/repo/"
_PATHS_FILE = f"{INPUT_DIR}/meta/paths.txt"
_CONTENT_BIT, _PATH_BIT = 1, 2
_SUCCESS_CODES = {0: 0, 41: _CONTENT_BIT, 42: _PATH_BIT, 43: _CONTENT_BIT | _PATH_BIT}
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REPORT_KEYS = frozenset(
    {
        "RuleID", "Description", "StartLine", "EndLine", "StartColumn", "EndColumn", "Match",
        "Secret", "File", "SymlinkFile", "Commit", "Entropy", "Author", "Email", "Date",
        "Message", "Tags", "Fingerprint",
    }
)  # fmt: skip
#: Gitleaks' replacement for a redacted value.
_REDACTED = "REDACTED"
#: Git metadata and link fields: always empty when scanning a directory snapshot.
_EMPTY_KEYS = ("SymlinkFile", "Commit", "Author", "Email", "Date", "Message")

# Positional parameters: $1 expected number of files, $2 maximum content report bytes,
# $3 maximum paths report bytes, $4 expected extraction digest (all generated by the worker).
_SCRIPT = (
    PROLOGUE
    + "expected_files=$1\nexpected_digest=$4\n"
    + STAGE_AND_VERIFY
    + r"""
report=/tmp/report.json
paths_report=/tmp/paths-report.json
[ -f "$input/config/gitleaks.toml" ] && [ -f "$input/meta/paths.txt" ] || exit 72
[ ! -e "$input/repo/.gitleaksignore" ] || exit 72
flags="--config $input/config/gitleaks.toml --gitleaks-ignore-path $input/config --ignore-gitleaks-allow --max-archive-depth 0 --no-banner --no-color --log-level error --redact=100 --report-format json --exit-code 42"
gitleaks dir $flags --report-path "$report" "$input/repo" > /dev/null
rc=$?
case "$rc" in 0|42) ;; *) exit 70 ;; esac
gitleaks dir $flags --report-path "$paths_report" "$input/meta" > /dev/null
prc=$?
case "$prc" in 0|42) ;; *) exit 70 ;; esac
[ -f "$report" ] && [ -f "$paths_report" ] || exit 73
[ "$(wc -c < "$report")" -le "$2" ] && [ "$(wc -c < "$paths_report")" -le "$3" ] || exit 74
printf '{"artifacts":[{"content_base64":"'
base64 "$report" | tr -d '\n'
printf '","media_type":"application/json","name":"gitleaks-report.json"},{"content_base64":"'
base64 "$paths_report" | tr -d '\n'
printf '","media_type":"application/json","name":"gitleaks-paths-report.json"}],"schema_version":1}'
code=40
[ "$rc" -eq 42 ] && code=$((code + 1))
[ "$prc" -eq 42 ] && code=$((code + 2))
[ "$code" -eq 40 ] && code=0
exit "$code"
"""
)

_SCRIPT_FAILURES = failures("GITLEAKS_FAILED")


def _invalid(code: str = "INVALID_REPORT") -> ScannerError:
    return ScannerError(code, FailureReason.SCANNER_ERROR)


def _int(value: Any, minimum: int) -> int:
    checked = checked_int(value, minimum)
    if checked is None:
        raise _invalid()
    return checked


def _entries(report: bytes) -> list[dict[str, Any]]:
    """Validated report entries: exact keys, redacted values, empty Git metadata."""
    entries = load_json(report)
    if entries is INVALID_JSON or not isinstance(entries, list):
        raise _invalid()
    if len(entries) > MAX_REPORT_ENTRIES:
        raise ScannerError("FINDINGS_LIMIT_EXCEEDED", FailureReason.RESOURCE_LIMIT_EXCEEDED)
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _REPORT_KEYS:
            raise _invalid()
        # Defense in depth: Gitleaks must have redacted the value; nothing raw is kept.
        if entry["Secret"] != _REDACTED or not isinstance(entry["Match"], str):
            raise _invalid("UNREDACTED_REPORT")
        if _REDACTED not in entry["Match"]:
            raise _invalid("UNREDACTED_REPORT")
        if any(entry[key] != "" for key in _EMPTY_KEYS):
            raise _invalid()
        if not isinstance(entry["RuleID"], str) or not _RULE_ID.match(entry["RuleID"]):
            raise _invalid()
        if not isinstance(entry["Description"], str) or not isinstance(entry["File"], str):
            raise _invalid()
        if _int(entry["EndLine"], 1) < _int(entry["StartLine"], 1):
            raise _invalid()
        _int(entry["StartColumn"], 0)
        _int(entry["EndColumn"], 0)
    return entries


class GitleaksAdapter:
    @property
    def scanner_type(self) -> str:
        return SCANNER_TYPE

    @property
    def identity(self) -> Scanner:
        return IDENTITY

    def policy(
        self, timeout_seconds: float = 300.0, cpus: float = 1.0, runtime: str | None = None
    ) -> SandboxPolicy:
        """Limits for scanning a snapshot of at most 16 MiB in 5000 files: the tmpfs holds
        the staged archive (deleted after extraction), the extracted files (page-granular)
        and the reports; the memory limit includes it.
        Gitleaks is a reviewed tool (TRUSTED_TOOL); the repository content it parses stays
        untrusted (ADR-0009 trust policy)."""
        return SandboxPolicy(
            image=IDENTITY.image,
            memory_bytes=512 * 1024 * 1024,
            cpus=cpus,
            pids=128,
            tmpfs_bytes=96 * 1024 * 1024,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=2 * 1024 * 1024,
            max_stdin_bytes=32 * 1024 * 1024,
            runtime=runtime,
            workload=Workload.TRUSTED_TOOL,
        )

    def prepare(self, snapshot: RepositorySnapshot) -> RepositorySnapshot:
        """The root ``.gitleaksignore`` *file* is already excluded by every repository
        source. Files inside a root *directory* of that name cannot be presented to
        Gitleaks (it would try to load the directory as an ignore file), so they are
        skipped as unsupported names, which makes coverage incomplete instead of failing
        the scan."""
        return snapshot.without(
            lambda path: path.split("/", 1)[0] == ".gitleaksignore" and "/" in path,
            SkipReason.UNSUPPORTED_NAME,
        )

    def stdin(self, snapshot: RepositorySnapshot) -> bytes:
        archive = snapshot.archive(
            "repo",
            {"config/gitleaks.toml": CONFIG, "meta/paths.txt": snapshot.path_manifest()},
        )
        if len(archive) > self.policy().max_stdin_bytes:
            raise InputError(InputErrorCode.INPUT_TOO_LARGE)
        return archive

    def command(self, snapshot: RepositorySnapshot) -> list[str]:
        digest = snapshot.extraction_sha256
        if not _SHA256.match(digest):  # pragma: no cover - hexdigest
            raise ValueError("invalid digest")
        return ["/bin/sh", "-c", _SCRIPT, "sentinel-gitleaks", str(len(snapshot.files)),
                str(MAX_REPORT_BYTES), str(MAX_PATHS_REPORT_BYTES), digest]  # fmt: skip

    def interpret(
        self, run: SandboxRun, snapshot: RepositorySnapshot, lease: JobLease
    ) -> tuple[Artifact, ...]:
        code = run.exit_code
        if code in _SCRIPT_FAILURES:
            raise ScannerError(*_SCRIPT_FAILURES[code])
        if code not in _SUCCESS_CODES:
            if code is not None and 0 < code < 128:
                raise _invalid("UNEXPECTED_EXIT_CODE")
            raise ScannerError("TERMINATED", FailureReason.SANDBOX_ERROR)
        reports = self._reports(run.stdout)
        if reports is None:
            raise _invalid("INVALID_OUTPUT")
        content_report, paths_report = reports
        content_entries, path_entries = _entries(content_report), _entries(paths_report)
        expected = _SUCCESS_CODES[code]
        if bool(expected & _CONTENT_BIT) != bool(content_entries) or bool(
            expected & _PATH_BIT
        ) != bool(path_entries):
            raise _invalid("INCONSISTENT_EXIT_CODE")
        ordered = snapshot.ordered_paths
        flagged = self._flagged_paths(path_entries, ordered)
        safe = safe_paths(ordered, flagged)
        findings = [self._content_finding(entry, safe) for entry in content_entries]
        findings += [
            Finding(
                rule_id=entry["RuleID"],
                category="SECRET",
                description=safe_text(entry["Description"], 512) or None,
                path=safe[ordered[entry["StartLine"] - 1]].value,
                start_line=None,
                end_line=None,
                start_column=None,
                end_column=None,
                target=FILE_PATH,
                path_redacted=True,
            )
            for entry in path_entries
        ]
        digest = hashlib.sha256(content_report + b"\0" + paths_report).hexdigest()
        document: bytes | None = None
        failure: ScannerError | None = None
        try:
            document = build_document(
                IDENTITY,
                lease,
                snapshot,
                findings,
                code,
                digest,
                LIMITATIONS,
                paths_redacted=sum(1 for value in safe.values() if value.redacted),
            )
        except FindingsLimitError:
            failure = ScannerError("FINDINGS_LIMIT_EXCEEDED", FailureReason.RESOURCE_LIMIT_EXCEEDED)
        except ValueError:
            failure = _invalid("INVALID_FINDING")
        if failure is not None or document is None:
            raise failure or _invalid("INVALID_FINDING")
        return (Artifact(EVIDENCE_NAME, "application/json", document),)

    @staticmethod
    def _reports(stdout: bytes) -> tuple[bytes, bytes] | None:
        try:
            artifacts = parse(stdout)
        except InvalidOutputError:
            return None
        by_name = {artifact.name: artifact.content for artifact in artifacts}
        if len(artifacts) != 2 or set(by_name) != {REPORT_NAME, PATHS_REPORT_NAME}:
            return None
        return by_name[REPORT_NAME], by_name[PATHS_REPORT_NAME]

    @staticmethod
    def _flagged_paths(
        entries: list[dict[str, Any]], ordered: tuple[str, ...]
    ) -> dict[int, set[int]]:
        """Path index -> components to redact, from detections in ``paths.txt``.

        Gitleaks reports byte columns (1-based, inclusive end) and counts the preceding
        line break on every line after the first, so a match's start is ``StartColumn - 1``
        or ``StartColumn - 2``. The window covers both; overlapping separators are harmless
        and an empty overlap redacts the whole path."""
        flagged: dict[int, set[int]] = {}
        for entry in entries:
            line = entry["StartLine"]
            if entry["File"] != _PATHS_FILE or entry["EndLine"] != line:
                raise _invalid("UNKNOWN_PATH")
            if not 1 <= line <= len(ordered):
                raise _invalid("UNKNOWN_PATH")
            path = ordered[line - 1]
            window = components_in_byte_window(
                path, max(entry["StartColumn"] - 2, 0), max(entry["EndColumn"] - 1, 0)
            )
            flagged.setdefault(line - 1, set()).update(window)
        return flagged

    @staticmethod
    def _content_finding(entry: dict[str, Any], safe: dict[str, Any]) -> Finding:
        file = entry["File"]
        relative = file[len(_REPO) :] if file.startswith(_REPO) else None
        if relative is None or relative not in safe:
            raise _invalid("UNKNOWN_PATH")
        location = safe[relative]
        return Finding(
            rule_id=entry["RuleID"],
            category="SECRET",
            description=safe_text(entry["Description"], 512) or None,
            path=location.value,
            start_line=entry["StartLine"],
            end_line=entry["EndLine"],
            start_column=entry["StartColumn"],
            end_column=entry["EndColumn"],
            target=FILE_CONTENT,
            path_redacted=location.redacted,
        )

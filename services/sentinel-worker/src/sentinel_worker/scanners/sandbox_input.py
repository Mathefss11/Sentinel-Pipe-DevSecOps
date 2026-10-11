# ruff: noqa: E501 - the constant sandbox script is kept on readable single lines.
"""Shared, reviewed pieces of every scanner's sandbox script (ADR-0010).

:data:`STAGE_AND_VERIFY` is the BusyBox shell fragment each adapter's constant script
starts with. It expects ``expected_files`` (the snapshot's file count) and
``expected_digest`` (``RepositorySnapshot.extraction_sha256``) to be set from validated,
worker-generated positional arguments. It:

1. stages stdin as an archive in the sandbox's tmpfs;
2. **lists it before extracting** and refuses (exit 75) anything but regular files and
   directories. That covers symbolic and hard links (BusyBox lists a hard link as a file
   with a ``-> target`` suffix, so each long-listing line must end with exactly its
   name), devices and FIFOs; absolute names; ``..``; duplicates; and names outside
   ``repo/``, ``config/`` and ``meta/``;
3. extracts into ``/tmp/input`` and deletes the archive;
4. verifies that ``repo/`` holds only files and directories, exactly ``expected_files``
   files, and that the ``sha256sum`` digest over every name and content equals
   ``expected_digest`` (exit 72). The scanner therefore sees exactly the snapshot.

Exit codes shared by all scanner scripts: 70 scanner failed, 71 staging or extraction
failed, 72 verification failed, 73 report missing, 74 report too large, 75 archive
refused. Adapters add their own success codes.
"""

from __future__ import annotations

import json
from typing import Any

from sentinel_worker.execution.leases import FailureReason

INPUT_DIR = "/tmp/input"  # noqa: S108 - path inside the sandbox
REPO_PREFIX = f"{INPUT_DIR}/repo/"

STAGE_AND_VERIFY = r"""
input=/tmp/input
archive=/tmp/input.tar
cat > "$archive" || exit 71
tar -t -f "$archive" > /tmp/names || exit 75
tar -tv -f "$archive" > /tmp/long || exit 75
[ "$(wc -l < /tmp/names)" -eq "$(wc -l < /tmp/long)" ] || exit 75
[ -z "$(sort /tmp/names | uniq -d)" ] || exit 75
awk 'NR == FNR { names[FNR] = $0; next } { t = substr($0, 1, 1); name = names[FNR]; if ((t != "-" && t != "d") || substr($0, length($0) - length(name) + 1) != name) exit 1 }' /tmp/names /tmp/long || exit 75
while IFS= read -r name; do
  case "$name" in
    /*|..|../*|*/..|*/../*|*/../) exit 75 ;;
    repo|repo/|repo/*|config|config/|config/*|meta|meta/|meta/*) ;;
    *) exit 75 ;;
  esac
done < /tmp/names
mkdir "$input" || exit 71
tar -x -f "$archive" -C "$input" || exit 71
rm -f "$archive" /tmp/names /tmp/long
[ -d "$input/repo" ] || exit 72
[ "$(find "$input/repo" ! -type f ! -type d | wc -l)" -eq 0 ] || exit 72
[ "$(find "$input/repo" -type f | wc -l)" -eq "$expected_files" ] || exit 72
actual=$(cd "$input/repo" && find . -type f | sort | while IFS= read -r f; do sha256sum "$f"; done | sha256sum) || exit 72
[ "${actual%% *}" = "$expected_digest" ] || exit 72
"""

#: Shell prologue of every scanner script.
PROLOGUE = "set -u\numask 077\nexport LC_ALL=C\n"


def failures(scanner_failed_code: str) -> dict[int, tuple[str, FailureReason]]:
    """The shared exit codes, with the adapter's sanitized code for exit 70."""
    return {
        70: (scanner_failed_code, FailureReason.SCANNER_ERROR),
        71: ("INPUT_EXTRACTION_FAILED", FailureReason.SCANNER_ERROR),
        72: ("INPUT_VERIFICATION_FAILED", FailureReason.SCANNER_ERROR),
        73: ("REPORT_MISSING", FailureReason.SCANNER_ERROR),
        74: ("REPORT_TOO_LARGE", FailureReason.RESOURCE_LIMIT_EXCEEDED),
        75: ("INPUT_REJECTED", FailureReason.SCANNER_ERROR),
    }


INVALID_JSON = object()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate keys")
    return dict(pairs)


def _reject_constant(_: str) -> None:
    raise ValueError("non-standard constant")


def load_json(report: bytes) -> Any:
    """Strict JSON (no duplicate keys, no NaN/Infinity, UTF-8) or :data:`INVALID_JSON`.
    Never raises, so no exception (whose context could hold report text) escapes."""
    try:
        return json.loads(
            report.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return INVALID_JSON


def checked_int(value: Any, minimum: int, maximum: int = 10_000_000) -> int | None:
    """``value`` if it is an int (not a bool) within bounds, else ``None``."""
    if type(value) is not int or not minimum <= value <= maximum:
        return None
    return value

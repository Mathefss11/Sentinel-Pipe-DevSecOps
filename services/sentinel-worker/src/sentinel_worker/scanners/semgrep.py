# ruff: noqa: E501 - the constant sandbox script is kept on readable single lines.
"""Semgrep 1.179.0 static analysis with a bundled, reviewed ruleset (ADR-0011; runbook
docs/runbooks/semgrep.md).

**Ruleset.** ``semgrep-rules.json`` is authored and reviewed in this repository. It is
pinned by SHA-256 (:data:`RULESET_SHA256`) and validated structurally when this module is
imported:

* every rule uses only allowlisted keys and pattern operators (no ``pattern-where-python``,
  no ``paths``, no ``fix``, no taint or extract modes);
* only the supported languages;
* static messages with no ``$`` metavariable interpolation, so a message can never carry
  matched source text;
* metadata limited to CWE and OWASP identifiers.

A mismatch fails closed at worker start. Messages, metadata and severities are taken
from this catalog, **never** from Semgrep's output. The ruleset travels in the input
archive as worker configuration (``config/rules.json``), which the shared ``repo/``
digest does not cover, so the script also checks its SHA-256 inside the sandbox before
Semgrep starts (exit 72), as the Trivy adapter does for its report template.

**Input.** The repository snapshot arrives on stdin (:mod:`.sandbox_input`). Repository
``.semgrepignore`` files (root or nested) are removed from the input
(:meth:`SemgrepAdapter.prepare`), and the script refuses to scan if one is present. It
then writes the worker's **empty** ``.semgrepignore`` at the scan root. Otherwise
Semgrep applies a default ignore list (``tests/``, ``node_modules/``, ``vendor/``,
``*.min.js`` and more) that a repository author controls by naming files. Verified
against 1.179.0.

**Execution.** Semgrep runs with a cleared environment (``env -i``):

* only ``PATH``, a tmpfs ``HOME``, ``PYTHONIOENCODING``, metrics off and version check
  off, so the image's telemetry variables never reach it;
* ``--config`` is the bundled ruleset;
* ``--metrics=off --disable-version-check --oss-only``;
* ``--disable-nosem`` (inline ``nosemgrep`` comments ignored);
* ``--no-git-ignore`` (``.gitignore`` not consulted);
* ``--jobs 1``, ``--timeout 30``, ``--timeout-threshold 0``, ``--max-memory 256``,
  ``--max-target-bytes 2000000``;
* ``--error``, so findings exit 1.

Semgrep's stderr stays inside the sandbox.

**Exit codes** (shared ones in :mod:`.sandbox_input`): 0 clean, 41 findings, 70 Semgrep
failed (any exit code other than 0 or 1). A code that disagrees with the report fails
closed.

**Coverage.** A supported-language file counts as *not analyzed*, and makes coverage
incomplete, when any of these applies (reasons are reported per file):

* ``scanner_skipped``: Semgrep did not list it in ``paths.scanned``, whatever the cause;
* ``parse_error``: Semgrep reported a per-file parse error, or, for Python, the
  independent syntax check failed. The check is ``ast.parse`` in the sandbox, with the
  image's Python 3.12 under ``env -i python3 -I -S``; it never executes code. It exists
  because Semgrep's error-tolerant parsers can recover from syntax errors without
  reporting them (verified for all four languages);
* ``resource_limit``: Semgrep reported a per-file timeout or memory error;
* ``unverifiable_encoding``: the file contains NUL bytes or starts with a UTF-16/UTF-32
  byte order mark. Semgrep 1.179.0 reports UTF-16 source as analyzed, without findings
  and without an error (verified), so its result cannot be trusted.

Any other error (rule problems, fatal errors) or a skipped rule fails the run. Java,
JavaScript and TypeScript have no independent parser in the image, so silent recovery
there cannot be detected: every document carries ``PARSE_COMPLETENESS_UNVERIFIED``.

**Output handling.** Semgrep's ``extra.message``, ``extra.lines`` and ``extra.metadata``
are never read. Error messages are never read. The report is parsed in memory, bounded,
and only its digest is kept. Paths are persisted only in their safe form (:mod:`.paths`;
heuristic redaction, since no secret rules run over names in this scanner).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
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
from sentinel_worker.sandbox.policy import SEMGREP_IMAGE, SandboxPolicy, Workload
from sentinel_worker.sandbox.protocol import InvalidOutputError, parse
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.findings import (
    CATEGORY_CODE_PATTERN,
    FILE_CONTENT,
    Classification,
    Coverage,
    Finding,
    FindingsLimitError,
    Scanner,
    build_document,
)
from sentinel_worker.scanners.paths import safe_paths
from sentinel_worker.scanners.sandbox_input import (
    INVALID_JSON,
    PROLOGUE,
    REPO_PREFIX,
    STAGE_AND_VERIFY,
    checked_int,
    failures,
    load_json,
)

SCANNER_TYPE = "SEMGREP"
VERSION = "1.179.0"
IDENTITY = Scanner(name="semgrep", version=VERSION, image=SEMGREP_IMAGE)
EVIDENCE_NAME = "findings.json"
REPORT_NAME = "semgrep-report.json"
PYTHON_CHECK_NAME = "python-syntax.json"
RULESET = resources.files(__package__).joinpath("semgrep-rules.json").read_bytes()
#: Reviewed ruleset; update together with the rules and their tests (runbook §5).
RULESET_SHA256 = "d52217f6e2fd6af5c0e609c8cfdb4652751e86ba193abc38a409280f01516a1f"
MAX_REPORT_BYTES = MAX_ARTIFACT_BYTES
MAX_REPORT_ENTRIES = 5000
MAX_REPORT_ERRORS = 10000
#: Semgrep prefixes rule ids with the configuration file's directory path, "/" replaced
#: by "." (verified: /tmp/input/config/rules.json -> "tmp.input.config.<rule id>").
_CHECK_ID_PREFIX = "tmp.input.config."
#: Semgrep 1.179.0's file extensions for the ruleset's languages (verified; ``.d.ts`` is
#: covered by ``.ts``). Not scanned: ``.pyw``, ``.mts``, ``.cts``, extensionless scripts.
LANGUAGE_SUFFIXES = {
    "java": (".java",),
    "python": (".py", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
}
LIMITATIONS = (
    "COMMIT_NOT_VERIFIED",
    "PARSE_COMPLETENESS_UNVERIFIED",
    "PATTERN_MATCHING_ONLY",
    "RULESET_MINIMAL",
)
#: Semgrep per-file error types that mean a resource limit, not a parse problem.
_RESOURCE_ERRORS = frozenset({"Timeout", "Out of memory", "OutOfMemory"})
#: Byte order marks of encodings Semgrep cannot analyze (UTF-32 first: it extends UTF-16 LE).
_UNSUPPORTED_BOMS = (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff", b"\xff\xfe", b"\xfe\xff")
_PYTHON_SUFFIXES = (".py", ".pyi")

_RULE_KEYS = frozenset(
    {"id", "languages", "severity", "message", "metadata", "pattern", "patterns", "pattern-either"}
)
_OPERATORS = frozenset(
    {
        "pattern",
        "pattern-not",
        "pattern-inside",
        "pattern-not-inside",
        "pattern-either",
        "patterns",
        "metavariable-regex",
    }
)
_SEVERITIES = frozenset({"ERROR", "WARNING", "INFO"})
_RULE_ID = re.compile(r"sentinelpipe\.(java|python|javascript)\.[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_CWE = re.compile(r"CWE-[0-9]{1,5}\Z")
_OWASP = re.compile(r"A[0-9]{2}:20[0-9]{2}\Z")
_MESSAGE = re.compile(r"[ -#%-~]{1,512}\Z")  # printable ASCII without "$"

_REPORT_KEYS = frozenset(
    {
        "version",
        "results",
        "errors",
        "paths",
        "skipped_rules",
        "engine_requested",
        "interfile_languages_used",
        "time",
        "profiling_results",
    }
)
_RESULT_KEYS = frozenset({"check_id", "path", "start", "end", "extra"})
_EXTRA_KEYS = frozenset(
    {
        "engine_kind",
        "fingerprint",
        "lines",
        "message",
        "metadata",
        "severity",
        "validation_state",
        "is_ignored",
    }
)
_ERROR_KEYS = frozenset({"code", "level", "type", "message", "path", "spans", "rule_id"})


class RulesetError(Exception):
    """The bundled ruleset is not the reviewed one, or uses a disallowed feature."""


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    languages: frozenset[str]
    severity: str
    message: str
    classification: Classification


def _check_operators(node: Any) -> None:
    if isinstance(node, list):
        for item in node:
            if not isinstance(item, dict) or len(item) != 1:
                raise RulesetError("each pattern item must hold exactly one operator")
            _check_operators(item)
        return
    if not isinstance(node, dict):
        raise RulesetError("invalid pattern structure")
    for key, value in node.items():
        if key not in _OPERATORS:
            raise RulesetError("disallowed pattern operator")
        if key in ("patterns", "pattern-either"):
            if not isinstance(value, list) or not value:
                raise RulesetError("pattern lists must be non-empty")
            _check_operators(value)
        elif key == "metavariable-regex":
            if not isinstance(value, dict) or set(value) != {"metavariable", "regex"}:
                raise RulesetError("invalid metavariable-regex")
            if not all(isinstance(v, str) and v for v in value.values()):
                raise RulesetError("invalid metavariable-regex")
        elif not isinstance(value, str) or not value.strip():
            raise RulesetError("patterns must be non-empty strings")


def load_ruleset(raw: bytes, expected_sha256: str = RULESET_SHA256) -> dict[str, Rule]:
    """The validated rule catalog. Raises :class:`RulesetError`."""
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RulesetError("the bundled Semgrep ruleset is not the reviewed one")
    document = load_json(raw)
    if document is INVALID_JSON or not isinstance(document, dict) or set(document) != {"rules"}:
        raise RulesetError("invalid ruleset document")
    if not isinstance(document["rules"], list) or not document["rules"]:
        raise RulesetError("invalid ruleset document")
    catalog: dict[str, Rule] = {}
    for rule in document["rules"]:
        if not isinstance(rule, dict) or not set(rule) <= _RULE_KEYS:
            raise RulesetError("disallowed rule key")
        rule_id, languages = rule.get("id"), rule.get("languages")
        if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id) or rule_id in catalog:
            raise RulesetError("invalid or duplicate rule id")
        if (
            not isinstance(languages, list)
            or not languages
            or not set(languages) <= set(LANGUAGE_SUFFIXES)
        ):
            raise RulesetError("unsupported rule language")
        if rule.get("severity") not in _SEVERITIES:
            raise RulesetError("invalid rule severity")
        message = rule.get("message")
        if not isinstance(message, str) or not _MESSAGE.match(message):
            raise RulesetError("rule messages must be static printable text without '$'")
        matchers = [key for key in ("pattern", "patterns", "pattern-either") if key in rule]
        if len(matchers) != 1:
            raise RulesetError("each rule needs exactly one top-level matcher")
        _check_operators({matchers[0]: rule[matchers[0]]})
        metadata = rule.get("metadata", {})
        if not isinstance(metadata, dict) or not set(metadata) <= {"cwe", "owasp"}:
            raise RulesetError("rule metadata is limited to cwe and owasp")
        cwe, owasp = metadata.get("cwe", []), metadata.get("owasp", [])
        if not all(isinstance(v, str) and _CWE.match(v) for v in cwe) or not all(
            isinstance(v, str) and _OWASP.match(v) for v in owasp
        ):
            raise RulesetError("invalid cwe or owasp identifier")
        catalog[rule_id] = Rule(
            rule_id=rule_id,
            languages=frozenset(languages),
            severity=rule["severity"],
            message=message,
            classification=Classification(tuple(cwe), tuple(owasp)),
        )
    return catalog


#: The reviewed catalog; importing this module fails if the ruleset is not the reviewed one.
CATALOG = load_ruleset(RULESET)
SUPPORTED_SUFFIXES = tuple(
    sorted(
        {
            suffix
            for rule in CATALOG.values()
            for lang in rule.languages
            for suffix in LANGUAGE_SUFFIXES[lang]
        }
    )
)

# Positional parameters: $1 expected number of files, $2 maximum report bytes, $3 expected
# extraction digest, $4 expected ruleset SHA-256 (all generated by the worker).
_SCRIPT = (
    PROLOGUE
    + "expected_files=$1\nexpected_digest=$3\n"
    + STAGE_AND_VERIFY
    + r"""
report=/tmp/report.json
[ -f "$input/config/rules.json" ] || exit 72
ruleset=$(sha256sum < "$input/config/rules.json") || exit 72
[ "${ruleset%% *}" = "$4" ] || exit 72
[ -z "$(find "$input/repo" -name .semgrepignore)" ] || exit 72
: > "$input/repo/.semgrepignore" || exit 71
mkdir /tmp/home /tmp/work || exit 71
cd /tmp/work || exit 71
env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/home PYTHONIOENCODING=utf8 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 semgrep scan --config "$input/config/rules.json" --json --output "$report" --metrics=off --disable-version-check --disable-nosem --no-git-ignore --oss-only --max-target-bytes 2000000 --max-memory 256 --jobs 1 --timeout 30 --timeout-threshold 0 --error "$input/repo" > /dev/null 2> /tmp/semgrep.err
rc=$?
case "$rc" in 0|1) ;; *) exit 70 ;; esac
[ -f "$report" ] || exit 73
[ "$(wc -c < "$report")" -le "$2" ] || exit 74
cat > /tmp/pycheck.py << 'PYCHECK'
import ast, json, sys, warnings
warnings.simplefilter("ignore")
failed = []
for raw in sys.stdin.buffer.read().split(b"\n"):
    if raw:
        path = raw.decode("utf-8")
        try:
            with open("/tmp/input/repo/" + path, "rb") as handle:
                ast.parse(handle.read(), filename="<input>")
        except BaseException:
            failed.append(path)
json.dump({"failed": sorted(failed)}, sys.stdout)
PYCHECK
(cd "$input/repo" && find . -type f \( -name '*.py' -o -name '*.pyi' \) | sed 's|^\./||') > /tmp/python-files || exit 70
env -i PATH=/usr/local/bin:/usr/bin:/bin python3 -I -S /tmp/pycheck.py < /tmp/python-files > /tmp/python-syntax.json 2> /dev/null || exit 70
[ "$(wc -c < /tmp/python-syntax.json)" -le "$2" ] || exit 74
printf '{"artifacts":[{"content_base64":"'
base64 "$report" | tr -d '\n'
printf '","media_type":"application/json","name":"semgrep-report.json"},{"content_base64":"'
base64 /tmp/python-syntax.json | tr -d '\n'
printf '","media_type":"application/json","name":"python-syntax.json"}],"schema_version":1}'
[ "$rc" -eq 1 ] && exit 41
exit 0
"""
)

_SCRIPT_FAILURES = failures("SEMGREP_FAILED")
_SUCCESS_CODES = {0: False, 41: True}


def _invalid(code: str = "INVALID_REPORT") -> ScannerError:
    return ScannerError(code, FailureReason.SCANNER_ERROR)


def _relative(path: Any, snapshot_paths: frozenset[str]) -> str:
    """The snapshot path of a reported absolute path, or ScannerError."""
    if not isinstance(path, str) or not path.startswith(REPO_PREFIX):
        raise _invalid("UNKNOWN_PATH")
    relative = path[len(REPO_PREFIX) :]
    if relative not in snapshot_paths:
        raise _invalid("UNKNOWN_PATH")
    return relative


def _position(value: Any) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise _invalid()
    line, column = checked_int(value.get("line"), 1), checked_int(value.get("col"), 1)
    if line is None or column is None:
        raise _invalid()
    return line, column


def supported(path: str) -> bool:
    return path.endswith(SUPPORTED_SUFFIXES)


class SemgrepAdapter:
    @property
    def scanner_type(self) -> str:
        return SCANNER_TYPE

    @property
    def identity(self) -> Scanner:
        return IDENTITY

    @property
    def sandbox_image(self) -> str:
        return IDENTITY.image

    def policy(
        self, timeout_seconds: float = 300.0, cpus: float = 1.0, runtime: str | None = None
    ) -> SandboxPolicy:
        """Measured on 1 CPU (docs/runbooks/semgrep.md): peak memory 220-280 MiB including
        tmpfs pages for inputs up to the snapshot limits, peak 7 processes, up to 20 MiB of
        tmpfs, a few seconds. A single pathological file (a 960 KB line) peaked at up to
        about 700 MiB with Semgrep's per-file limit at 400 MiB, which occasionally OOM-killed
        a 768 MiB sandbox (security review S2-7); with the per-file limit at 256 MiB it
        peaked at about 265 MiB and fails alone as a per-file ``Out of memory``. Limits:
        1 GiB, per-file 256 MiB, 64 processes, 128 MiB tmpfs (the staged archive is up to
        32 MiB). Semgrep is a reviewed tool (TRUSTED_TOOL); the code it parses stays
        untrusted (ADR-0009 trust policy)."""
        return SandboxPolicy(
            image=IDENTITY.image,
            memory_bytes=1024 * 1024 * 1024,
            cpus=cpus,
            pids=64,
            tmpfs_bytes=128 * 1024 * 1024,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=2 * 1024 * 1024,
            max_stdin_bytes=32 * 1024 * 1024,
            runtime=runtime,
            workload=Workload.TRUSTED_TOOL,
        )

    def prepare(self, snapshot: RepositorySnapshot) -> RepositorySnapshot:
        """Removes every repository ``.semgrepignore`` file (root or nested): Semgrep obeys
        them all. Files inside a *directory* named ``.semgrepignore`` cannot be presented
        to Semgrep (it would treat the directory as an ignore file), so they are skipped
        as unsupported names, which makes coverage incomplete instead of failing the
        scan."""
        without_ignore_files = snapshot.without(
            lambda path: path.rsplit("/", 1)[-1] == ".semgrepignore", SkipReason.SUPPRESSION_FILE
        )
        return without_ignore_files.without(
            lambda path: ".semgrepignore" in path.split("/")[:-1], SkipReason.UNSUPPORTED_NAME
        )

    def stdin(self, snapshot: RepositorySnapshot) -> bytes:
        archive = snapshot.archive("repo", {"config/rules.json": RULESET})
        if len(archive) > self.policy().max_stdin_bytes:
            raise InputError(InputErrorCode.INPUT_TOO_LARGE)
        return archive

    def command(self, snapshot: RepositorySnapshot) -> list[str]:
        return ["/bin/sh", "-c", _SCRIPT, "sentinel-semgrep", str(len(snapshot.files)),
                str(MAX_REPORT_BYTES), snapshot.extraction_sha256, RULESET_SHA256]  # fmt: skip

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
        outputs = self._outputs(run.stdout)
        if outputs is None:
            raise _invalid("INVALID_OUTPUT")
        raw, python_check = outputs
        report = load_json(raw)
        if report is INVALID_JSON or not isinstance(report, dict):
            raise _invalid()
        if not {"version", "results", "errors", "paths"} <= set(report) <= _REPORT_KEYS:
            raise _invalid()
        if report["version"] != VERSION:
            raise _invalid("UNEXPECTED_VERSION")
        if report.get("skipped_rules", []) != []:
            raise ScannerError("RULES_SKIPPED", FailureReason.SCANNER_ERROR)
        paths = snapshot.paths
        scanned = self._scanned(report["paths"], paths)
        parse_errors, resource_errors = self._error_paths(report["errors"], paths)
        parse_errors |= self._python_failures(python_check, paths)
        results = report["results"]
        if not isinstance(results, list):
            raise _invalid()
        if len(results) > MAX_REPORT_ENTRIES:
            raise ScannerError("FINDINGS_LIMIT_EXCEEDED", FailureReason.RESOURCE_LIMIT_EXCEEDED)
        if _SUCCESS_CODES[code] != bool(results):
            raise _invalid("INCONSISTENT_EXIT_CODE")
        safe = safe_paths(snapshot.ordered_paths)
        findings = [self._finding(result, paths, safe) for result in results]
        supported_files = [entry for entry in snapshot.files if supported(entry.path)]
        supported_paths = {entry.path for entry in supported_files}
        reasons = {
            "scanner_skipped": supported_paths - scanned,
            "parse_error": parse_errors & supported_paths,
            "resource_limit": resource_errors & supported_paths,
            "unverifiable_encoding": {
                entry.path
                for entry in supported_files
                if b"\x00" in entry.content or entry.content.startswith(_UNSUPPORTED_BOMS)
            },
        }
        not_analyzed = set().union(*reasons.values())
        coverage = Coverage(
            files_supported=len(supported_files),
            files_analyzed=len(supported_files) - len(not_analyzed),
            files_not_analyzed=len(not_analyzed),
            files_unsupported=len(snapshot.files) - len(supported_files),
            not_analyzed_reasons={reason: len(files) for reason, files in reasons.items()},
        )
        limitations = set(LIMITATIONS)
        if not_analyzed:
            limitations.add("FILES_NOT_ANALYZED")
        if coverage.files_unsupported:
            limitations.add("UNSUPPORTED_FILES_PRESENT")
        if not supported_files:
            limitations.add("NO_SUPPORTED_FILES")
        document: bytes | None = None
        failure: ScannerError | None = None
        try:
            document = build_document(
                IDENTITY,
                lease,
                snapshot,
                findings,
                code,
                hashlib.sha256(raw).hexdigest(),
                limitations,
                paths_redacted=sum(1 for value in safe.values() if value.redacted),
                coverage=coverage,
            )
        except FindingsLimitError:
            failure = ScannerError("FINDINGS_LIMIT_EXCEEDED", FailureReason.RESOURCE_LIMIT_EXCEEDED)
        except ValueError:
            failure = _invalid("INVALID_FINDING")
        if failure is not None or document is None:
            raise failure or _invalid("INVALID_FINDING")
        return (Artifact(EVIDENCE_NAME, "application/json", document),)

    @staticmethod
    def _outputs(stdout: bytes) -> tuple[bytes, bytes] | None:
        """(Semgrep report, Python syntax check) or ``None``."""
        try:
            artifacts = parse(stdout)
        except InvalidOutputError:
            return None
        by_name = {artifact.name: artifact.content for artifact in artifacts}
        if len(artifacts) != 2 or set(by_name) != {REPORT_NAME, PYTHON_CHECK_NAME}:
            return None
        return by_name[REPORT_NAME], by_name[PYTHON_CHECK_NAME]

    @staticmethod
    def _python_failures(raw: bytes, paths: frozenset[str]) -> set[str]:
        """Python files whose syntax the independent check could not verify."""
        document = load_json(raw)
        if (
            document is INVALID_JSON
            or not isinstance(document, dict)
            or set(document) != {"failed"}
        ):
            raise _invalid()
        failed = document["failed"]
        if not isinstance(failed, list) or len(failed) > len(paths):
            raise _invalid()
        result: set[str] = set()
        for path in failed:
            if (
                not isinstance(path, str)
                or path not in paths
                or not path.endswith(_PYTHON_SUFFIXES)
            ):
                raise _invalid("UNKNOWN_PATH")
            result.add(path)
        return result

    @staticmethod
    def _scanned(value: Any, paths: frozenset[str]) -> set[str]:
        if not isinstance(value, dict) or set(value) != {"scanned"}:
            raise _invalid()
        scanned = value["scanned"]
        if not isinstance(scanned, list) or len(scanned) > len(paths):
            raise _invalid()
        return {_relative(path, paths) for path in scanned}

    @staticmethod
    def _error_paths(errors: Any, paths: frozenset[str]) -> tuple[set[str], set[str]]:
        """(Files with parse errors, files with timeouts or memory errors). Any error that
        is not a per-file warning about a snapshot file means the run is unusable. Error
        messages (which can quote source) are never read."""
        if not isinstance(errors, list) or len(errors) > MAX_REPORT_ERRORS:
            raise _invalid()
        parse_errors: set[str] = set()
        resource_errors: set[str] = set()
        for error in errors:
            if not isinstance(error, dict) or not set(error) <= _ERROR_KEYS:
                raise _invalid()
            if error.get("level") != "warn" or "path" not in error:
                raise ScannerError("SEMGREP_ERROR", FailureReason.SCANNER_ERROR)
            kind = error.get("type")
            name = kind[0] if isinstance(kind, list) and kind else kind
            target = _relative(error["path"], paths)
            if isinstance(name, str) and name in _RESOURCE_ERRORS:
                resource_errors.add(target)
            else:
                parse_errors.add(target)
        return parse_errors, resource_errors

    @staticmethod
    def _finding(result: Any, paths: frozenset[str], safe: dict[str, Any]) -> Finding:
        if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
            raise _invalid()
        extra = result["extra"]
        if not isinstance(extra, dict) or not set(extra) <= _EXTRA_KEYS:
            raise _invalid()
        check_id = result["check_id"]
        if not isinstance(check_id, str) or not check_id.startswith(_CHECK_ID_PREFIX):
            raise _invalid("UNKNOWN_RULE")
        rule = CATALOG.get(check_id[len(_CHECK_ID_PREFIX) :])
        if rule is None:
            raise _invalid("UNKNOWN_RULE")
        if extra.get("severity") != rule.severity:
            raise _invalid()
        relative = _relative(result["path"], paths)
        if not supported(relative):
            raise _invalid("UNKNOWN_PATH")
        (start_line, start_column), (end_line, end_column) = (
            _position(result["start"]),
            _position(result["end"]),
        )
        if (end_line, end_column) < (start_line, start_column):
            raise _invalid()
        location = safe[relative]
        # Message, metadata and severity come from the reviewed catalog. Semgrep's
        # message can interpolate matched source, and ``lines`` holds source excerpts;
        # neither is ever read.
        return Finding(
            rule_id=rule.rule_id,
            category=CATEGORY_CODE_PATTERN,
            description=rule.message,
            path=location.value,
            start_line=start_line,
            end_line=end_line,
            start_column=start_column,
            end_column=end_column,
            target=FILE_CONTENT,
            path_redacted=location.redacted,
            scanner_severity=rule.severity,
            classification=rule.classification,
        )

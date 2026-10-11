# ruff: noqa: S108 - /tmp paths are inside the sandbox, as Semgrep reports them
"""The Semgrep adapter without containers (ADR-0011).

The reviewed ruleset and its integrity; exit-code semantics; strict parsing of
untrusted reports; coverage accounting; normalization from the catalog only (never
Semgrep's message, metadata or source lines); safe paths; settings. The real container
is exercised in tests/sandbox/test_semgrep_sandbox.py.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from scanner_support import exited, lease, synthetic_github_token
from semgrep_support import envelope, report, result
from sentinel_worker.config import ConfigurationError, Environment
from sentinel_worker.execution.leases import FailureReason
from sentinel_worker.execution.settings import ExecutionSettings
from sentinel_worker.messaging import contracts
from sentinel_worker.repository.snapshot import RepositorySnapshot, SkipReason, SnapshotFile
from sentinel_worker.sandbox.policy import (
    IMAGE_ENVIRONMENT,
    SEMGREP_IMAGE,
    Workload,
    new_sandbox_name,
    run_arguments,
)
from sentinel_worker.scanners import semgrep
from sentinel_worker.scanners.adapter import ScannerError
from sentinel_worker.scanners.semgrep import (
    CATALOG,
    RULESET,
    RULESET_SHA256,
    RulesetError,
    SemgrepAdapter,
    load_ruleset,
)

ADAPTER = SemgrepAdapter()
SNAPSHOT = RepositorySnapshot(
    files=tuple(
        SnapshotFile(path, b"x")
        for path in sorted(["app.py", "README.md", "src/App.java", "web/ünï.ts", "z.js"])
    ),
    skipped={},
)
ALL_SUPPORTED = ["app.py", "src/App.java", "web/ünï.ts", "z.js"]
SOURCE_MARKER = "SENTINEL_PROPRIETARY_SOURCE_" + "Z" * 24


def run_with(code: int, document: bytes, snapshot: RepositorySnapshot = SNAPSHOT) -> dict[str, Any]:
    (artifact,) = ADAPTER.interpret(exited(code, envelope(document)), snapshot, lease())
    parsed: dict[str, Any] = json.loads(artifact.content)
    assert list(contracts.validator(contracts.FINDINGS_SCHEMA).iter_errors(parsed)) == []
    return parsed


def failure(code: int | None, stdout: bytes) -> ScannerError:
    with pytest.raises(ScannerError) as raised:
        ADAPTER.interpret(exited(code, stdout), SNAPSHOT, lease())
    assert raised.value.__context__ is None
    return raised.value


def ruleset_with(mutate: Any) -> bytes:
    document = json.loads(RULESET)
    mutate(document["rules"])
    return json.dumps(document).encode()


# --- The reviewed ruleset ------------------------------------------------------------


def test_the_bundled_ruleset_is_the_reviewed_one() -> None:
    assert hashlib.sha256(RULESET).hexdigest() == RULESET_SHA256
    assert len(CATALOG) == 13
    languages = {language for rule in CATALOG.values() for language in rule.languages}
    assert languages == {"java", "python", "javascript", "typescript"}
    assert semgrep.SUPPORTED_SUFFIXES == (
        ".cjs", ".java", ".js", ".jsx", ".mjs", ".py", ".pyi", ".ts", ".tsx"
    )  # fmt: skip
    for rule in CATALOG.values():
        assert "$" not in rule.message  # no metavariable interpolation of source text
        assert rule.classification.cwe, rule.rule_id


def test_a_ruleset_that_is_not_the_reviewed_one_is_refused() -> None:
    with pytest.raises(RulesetError, match="reviewed"):
        load_ruleset(RULESET + b" ")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rules: rules[0].update({"pattern-where-python": "True"}),
        lambda rules: rules[0].update({"paths": {"exclude": ["*"]}}),
        lambda rules: rules[0].update({"fix": "safe()"}),
        lambda rules: rules[0].update({"mode": "taint"}),
        lambda rules: rules[0].update({"message": "Found $X in the code"}),
        lambda rules: rules[0].update({"languages": ["ruby"]}),
        lambda rules: rules[0].update({"severity": "CRITICAL"}),
        lambda rules: rules[0].update({"metadata": {"cwe": ["CWE-89"], "references": ["x"]}}),
        lambda rules: rules[0].update({"metadata": {"cwe": ["89"]}}),
        lambda rules: rules[1].update({"id": rules[0]["id"]}),
        lambda rules: rules[0].update({"id": "registry.python.rule"}),
        lambda rules: rules[0]["patterns"].append({"pattern-where-python": "True"}),
        lambda rules: rules[0]["patterns"].append({"pattern": "a", "pattern-not": "b"}),
        lambda rules: rules[0]["patterns"].append({"metavariable-comparison": {"x": 1}}),
    ],
    ids=[
        "where-python",
        "paths",
        "fix",
        "taint-mode",
        "interpolated-message",
        "language",
        "severity",
        "metadata-key",
        "cwe-format",
        "duplicate-id",
        "foreign-id",
        "nested-where-python",
        "two-operators",
        "disallowed-operator",
    ],
)
def test_disallowed_ruleset_features_are_refused(mutate: Any) -> None:
    raw = ruleset_with(mutate)

    with pytest.raises(RulesetError):
        load_ruleset(raw, hashlib.sha256(raw).hexdigest())


# --- Successful runs: normalization from the catalog only ----------------------------


def test_a_clean_run_reports_language_coverage_and_is_not_a_decision() -> None:
    document = run_with(0, report(scanned=ALL_SUPPORTED))

    assert document["finding_count"] == 0
    assert document["execution"]["status"] == "NO_FINDINGS"
    assert document["coverage"] | {"limitations": None} == {
        "complete": True,
        "limitations": None,
        "files_supported": 4,
        "files_analyzed": 4,
        "files_not_analyzed": 0,
        "files_unsupported": 1,
        "not_analyzed_reasons": {
            "scanner_skipped": 0,
            "parse_error": 0,
            "resource_limit": 0,
            "unverifiable_encoding": 0,
        },
    }
    assert set(document["coverage"]["limitations"]) == {
        "COMMIT_NOT_VERIFIED", "PARSE_COMPLETENESS_UNVERIFIED", "PATTERN_MATCHING_ONLY",
        "RULESET_MINIMAL", "UNSUPPORTED_FILES_PRESENT",
    }  # fmt: skip
    assert "decision" not in json.dumps(document).lower()


def test_findings_take_message_metadata_and_severity_from_the_catalog_only() -> None:
    rule = CATALOG["sentinelpipe.python.code-injection-eval"]
    forged = result(
        "app.py",
        line=3,
        message=f"leaked source: {SOURCE_MARKER}",
        lines=f"eval('{SOURCE_MARKER}')",
        metadata={"cwe": ["CWE-1"], "owasp": ["A99:2099"], "confidence": "HIGH"},
    )

    document = run_with(41, report([forged], scanned=ALL_SUPPORTED))

    (finding,) = document["findings"]
    assert SOURCE_MARKER not in json.dumps(document)
    assert finding["category"] == "CODE_PATTERN"
    assert finding["description"] == rule.message
    assert finding["scanner_severity"] == "ERROR"
    assert finding["classification"] == {"cwe": ["CWE-95"], "owasp": ["A03:2021"]}
    assert finding["severity"] is None  # not mapped onto a normalized scale
    assert finding["confidence"] is None
    assert finding["remediation"] is None
    assert finding["evidence"] == {"redacted": True, "excerpt": None}
    assert finding["location"] == {
        "target": "FILE_CONTENT",
        "path": "app.py",
        "path_redacted": False,
        "start_line": 3,
        "end_line": 3,
        "start_column": 5,
        "end_column": 12,
    }
    assert document["execution"]["exit_code"] == 41


def test_duplicates_are_merged_and_fingerprints_are_deterministic() -> None:
    results = [
        result("z.js", "javascript.code-injection-eval", line=2),
        result("app.py", line=4),
        result("app.py", line=4),
        result("app.py", "python.weak-hash-algorithm", line=4, severity="WARNING"),
    ]
    claimed = lease()
    first = ADAPTER.interpret(
        exited(41, envelope(report(results, ALL_SUPPORTED))), SNAPSHOT, claimed
    )
    second = ADAPTER.interpret(
        exited(41, envelope(report(list(reversed(results)), ALL_SUPPORTED))), SNAPSHOT, claimed
    )

    document = json.loads(first[0].content)
    # Same findings in the same order with the same ids, whatever the report order (only
    # the digest of the differently ordered raw report differs).
    assert json.loads(second[0].content)["findings"] == document["findings"]
    assert [(f["location"]["path"], f["rule_id"].rsplit(".", 1)[-1], f["occurrences"])
            for f in document["findings"]] == [
        ("app.py", "code-injection-eval", 2),
        ("app.py", "weak-hash-algorithm", 1),
        ("z.js", "code-injection-eval", 1),
    ]  # fmt: skip


def test_secret_shaped_file_names_are_redacted_in_findings() -> None:
    token = synthetic_github_token(51)
    snapshot = RepositorySnapshot(files=(SnapshotFile(f"keys/{token}.py", b"x"),), skipped={})

    document = run_with(41, report([result(f"keys/{token}.py")], [f"keys/{token}.py"]), snapshot)

    assert token not in json.dumps(document)
    assert document["findings"][0]["location"]["path"] == "keys/[redacted-1]"
    assert document["findings"][0]["location"]["path_redacted"] is True
    assert document["input"]["paths_redacted"] == 1


# --- Coverage ------------------------------------------------------------------------


def test_supported_files_missing_from_the_scan_make_coverage_incomplete() -> None:
    document = run_with(0, report(scanned=["app.py", "z.js"]))

    assert document["coverage"]["complete"] is False
    assert document["coverage"]["files_not_analyzed"] == 2
    assert "FILES_NOT_ANALYZED" in document["coverage"]["limitations"]


def test_per_file_errors_are_partial_coverage_never_silent() -> None:
    errors = [
        {"code": 3, "level": "warn", "type": "Syntax error", "message": f"near {SOURCE_MARKER}",
         "path": "/tmp/input/repo/z.js"},
        {"code": 3, "level": "warn", "type": "Timeout", "message": "x",
         "path": "/tmp/input/repo/app.py"},
    ]  # fmt: skip

    document = run_with(0, report(scanned=ALL_SUPPORTED, errors=errors))

    assert document["coverage"]["files_not_analyzed"] == 2
    assert document["coverage"]["complete"] is False
    assert SOURCE_MARKER not in json.dumps(document)


def test_a_repository_without_supported_files_is_flagged() -> None:
    snapshot = RepositorySnapshot(files=(SnapshotFile("main.rb", b"x"),), skipped={})

    document = run_with(0, report(), snapshot)

    assert "NO_SUPPORTED_FILES" in document["coverage"]["limitations"]
    assert document["coverage"]["files_unsupported"] == 1


@pytest.mark.parametrize(
    "error",
    [
        {"code": 2, "level": "error", "type": "Rule parse error", "message": "x"},
        {"code": 3, "level": "warn", "type": "Other", "message": "x"},
        {
            "code": 3,
            "level": "error",
            "type": "Fatal",
            "message": "x",
            "path": "/tmp/input/repo/app.py",
        },
    ],
    ids=["fatal", "warning-without-path", "error-level"],
)
def test_errors_that_are_not_per_file_warnings_fail_the_run(error: dict[str, Any]) -> None:
    raised = failure(0, envelope(report(scanned=ALL_SUPPORTED, errors=[error])))

    assert (raised.code, raised.reason) == ("SEMGREP_ERROR", FailureReason.SCANNER_ERROR)


def test_skipped_rules_fail_the_run() -> None:
    raised = failure(0, envelope(report(scanned=ALL_SUPPORTED, skipped_rules=[{"rule_id": "x"}])))

    assert raised.code == "RULES_SKIPPED"


# --- Exit codes and malformed output -------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected", "reason"),
    [
        (70, "SEMGREP_FAILED", FailureReason.SCANNER_ERROR),
        (71, "INPUT_EXTRACTION_FAILED", FailureReason.SCANNER_ERROR),
        (72, "INPUT_VERIFICATION_FAILED", FailureReason.SCANNER_ERROR),
        (73, "REPORT_MISSING", FailureReason.SCANNER_ERROR),
        (74, "REPORT_TOO_LARGE", FailureReason.RESOURCE_LIMIT_EXCEEDED),
        (75, "INPUT_REJECTED", FailureReason.SCANNER_ERROR),
        (1, "UNEXPECTED_EXIT_CODE", FailureReason.SCANNER_ERROR),
        (2, "UNEXPECTED_EXIT_CODE", FailureReason.SCANNER_ERROR),
        (42, "UNEXPECTED_EXIT_CODE", FailureReason.SCANNER_ERROR),
        (137, "TERMINATED", FailureReason.SANDBOX_ERROR),
        (None, "TERMINATED", FailureReason.SANDBOX_ERROR),
    ],
)
def test_failures_are_never_clean_scans(
    code: int | None, expected: str, reason: FailureReason
) -> None:
    raised = failure(code, envelope(report(scanned=ALL_SUPPORTED)))

    assert (raised.code, raised.reason) == (expected, reason)


def test_exit_codes_must_agree_with_the_report() -> None:
    assert failure(0, envelope(report([result("app.py")], ALL_SUPPORTED))).code == (
        "INCONSISTENT_EXIT_CODE"
    )
    assert failure(41, envelope(report(scanned=ALL_SUPPORTED))).code == "INCONSISTENT_EXIT_CODE"


@pytest.mark.parametrize(
    ("stdout", "code"),
    [
        (b"", "INVALID_OUTPUT"),
        (envelope(report(), name="other.json"), "INVALID_OUTPUT"),
        (envelope(b"{not json"), "INVALID_REPORT"),
        (envelope(b"[]"), "INVALID_REPORT"),
        (envelope(report(unexpected=1)), "INVALID_REPORT"),
        (envelope(report(version="1.0.0")), "UNEXPECTED_VERSION"),
        (envelope(report(results="x")), "INVALID_REPORT"),
        (envelope(report(paths={"scanned": [], "skipped": []})), "INVALID_REPORT"),
        (envelope(report(scanned=["../etc/passwd"])), "UNKNOWN_PATH"),
        (envelope(b'{"version": "1.179.0", "version": "1.179.0"}'), "INVALID_REPORT"),
    ],
    ids=[
        "empty",
        "artifact-name",
        "json",
        "not-an-object",
        "unknown-key",
        "version",
        "results-type",
        "paths-keys",
        "foreign-scanned-path",
        "duplicate-keys",
    ],
)
def test_malformed_reports_fail_closed(stdout: bytes, code: str) -> None:
    assert failure(0, stdout).code == code


@pytest.mark.parametrize(
    ("entry", "code"),
    [
        (result("app.py") | {"extra_key": 1}, "INVALID_REPORT"),
        (result("app.py", unexpected="x"), "INVALID_REPORT"),
        (
            result("app.py") | {"check_id": "sentinelpipe.python.code-injection-eval"},
            "UNKNOWN_RULE",
        ),
        (result("app.py") | {"check_id": "tmp.input.config.p.python.lang.eval"}, "UNKNOWN_RULE"),
        (result("app.py", severity="WARNING"), "INVALID_REPORT"),
        (result("not-in-snapshot.py"), "UNKNOWN_PATH"),
        (result("README.md"), "UNKNOWN_PATH"),
        (result("app.py") | {"path": "/etc/passwd"}, "UNKNOWN_PATH"),
        (result("app.py") | {"start": {"line": 0, "col": 1}}, "INVALID_REPORT"),
        (result("app.py") | {"start": {"line": True, "col": 1}}, "INVALID_REPORT"),
        (
            result("app.py") | {"start": {"line": 9, "col": 1}, "end": {"line": 2, "col": 1}},
            "INVALID_REPORT",
        ),
    ],
    ids=[
        "result-key",
        "extra-key",
        "unprefixed-rule",
        "registry-rule",
        "severity-mismatch",
        "foreign-path",
        "unsupported-language",
        "absolute-path",
        "line-zero",
        "bool-line",
        "inverted-range",
    ],
)
def test_unexpected_results_are_refused(entry: dict[str, Any], code: str) -> None:
    assert failure(41, envelope(report([entry], ALL_SUPPORTED))).code == code


def test_errors_never_carry_source_text_or_exception_chains(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bad = [
        envelope(f'{{"version": "{SOURCE_MARKER}"'.encode()),
        envelope(report([result("app.py", message=SOURCE_MARKER, severity="INFO")], ALL_SUPPORTED)),
        SOURCE_MARKER.encode(),
    ]
    with caplog.at_level(logging.DEBUG):
        for stdout in bad:
            error = failure(41, stdout)
            assert SOURCE_MARKER not in str(error) + repr(error) + error.code
    assert SOURCE_MARKER not in caplog.text


def test_entry_bounds_fail_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(semgrep, "MAX_REPORT_ENTRIES", 1)

    raised = failure(
        41,
        envelope(
            report(
                [result("app.py"), result("z.js", "javascript.code-injection-eval")], ALL_SUPPORTED
            )
        ),
    )

    assert raised.reason is FailureReason.RESOURCE_LIMIT_EXCEEDED


# --- Input, command and policy -------------------------------------------------------


def test_repository_semgrepignore_files_are_removed_at_every_depth() -> None:
    snapshot = RepositorySnapshot(
        files=tuple(
            SnapshotFile(path, b"x")
            for path in sorted(
                [".semgrepignore", "a.py", "deep/x/.semgrepignore", "my.semgrepignore"]
            )
        ),
        skipped={SkipReason.SUPPRESSION_FILE: 1},
    )

    prepared = ADAPTER.prepare(snapshot)

    assert prepared.ordered_paths == ("a.py", "my.semgrepignore")
    assert prepared.skipped[SkipReason.SUPPRESSION_FILE] == 3


def test_the_input_carries_only_the_bundled_ruleset_outside_the_repository() -> None:
    with tarfile.open(fileobj=io.BytesIO(ADAPTER.stdin(SNAPSHOT))) as archive:
        names = archive.getnames()
        rules = archive.extractfile("config/rules.json")
        assert rules is not None
        assert rules.read() == RULESET
    assert not any(name.startswith(("meta", "repo/config")) for name in names)


def test_the_command_is_constant_hardened_and_takes_only_worker_values() -> None:
    argv = ADAPTER.command(SNAPSHOT)
    script = argv[2]

    assert argv[:2] == ["/bin/sh", "-c"]
    assert argv[3:] == [
        "sentinel-semgrep", "5", str(1024 * 1024), SNAPSHOT.extraction_sha256, RULESET_SHA256
    ]  # fmt: skip
    for required in ("env -i ", "--config \"$input/config/rules.json\"", "--metrics=off",
                     "--disable-version-check", "--disable-nosem", "--no-git-ignore",
                     "--oss-only", "--jobs 1", "--timeout 30", "--max-memory 256", "--error",
                     ': > "$input/repo/.semgrepignore"', "-name .semgrepignore"):  # fmt: skip
        assert required in script, required
    forbidden_flags = (
        "--config auto", "--config=auto", "--pro", "--config p/", "--config r/",
        "--dangerously", "--allow-untrusted-validators", "--include", "--exclude",
        "--severity", "--project-root", "SEMGREP_RULES", "SEMGREP_APP_TOKEN", "http",
    )  # fmt: skip
    for forbidden in forbidden_flags:
        assert forbidden not in script.replace("--pro-", "").replace("--oss-only", ""), forbidden
    assert all(name not in " ".join(argv) for name in SNAPSHOT.ordered_paths)


def test_the_ruleset_is_verified_inside_the_sandbox_before_semgrep_runs() -> None:
    """Review follow-up (ADR-0011, Slice 3 note): ``config/rules.json`` is worker data that
    the shared ``repo/`` digest does not cover. Its pinned SHA-256 is passed as a worker
    argument and checked in the sandbox (exit 72) before Semgrep starts, as Trivy does for
    its report template."""
    argv = ADAPTER.command(SNAPSHOT)
    script = argv[2]

    assert argv[-1] == RULESET_SHA256 == hashlib.sha256(RULESET).hexdigest()
    check = 'ruleset=$(sha256sum < "$input/config/rules.json") || exit 72'
    compare = '[ "${ruleset%% *}" = "$4" ] || exit 72'
    assert check in script
    assert compare in script
    assert script.index(compare) < script.index("semgrep scan")


def test_the_semgrep_policy_is_explicit_bounded_and_mounts_nothing() -> None:
    policy = ADAPTER.policy(timeout_seconds=60)
    args = run_arguments(policy, new_sandbox_name(), ADAPTER.command(SNAPSHOT), {}, 1, True)

    assert policy.image == SEMGREP_IMAGE
    assert policy.workload is Workload.TRUSTED_TOOL
    assert (policy.memory_bytes, policy.pids, policy.tmpfs_bytes) == (1024 << 20, 64, 128 << 20)
    expected_flags = (
        "--network none", "--read-only", "--cap-drop ALL", "--user 65534:65534",
        "--security-opt no-new-privileges", "--pull never", "--interactive",
    )  # fmt: skip
    for expected in expected_flags:
        assert expected in " ".join(args), expected
    for forbidden in ("-v", "--volume", "--mount", "-e", "--env", "--privileged"):
        assert forbidden not in args


def test_the_declared_image_environment_is_exactly_reviewed() -> None:
    assert IMAGE_ENVIRONMENT[SEMGREP_IMAGE] == {
        "SEMGREP_IN_DOCKER", "SEMGREP_USER_AGENT_APPEND", "PYTHONIOENCODING",
        "PYTHONUNBUFFERED", "DOCKER_OTEL_RESOURCE_ATTRIBUTES", "DD_SERVICE", "TSAN_OPTIONS",
    }  # fmt: skip


# --- Settings ------------------------------------------------------------------------

DB_ENV = {"SENTINEL_WORKER_DB_USERNAME": "w", "SENTINEL_WORKER_DB_PASSWORD": "pw"}


def semgrep_env(tmp_path: Path) -> dict[str, str]:
    return DB_ENV | {
        "SENTINEL_WORKER_SEMGREP_ENABLED": "true",
        "SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": str(tmp_path),
        "SENTINEL_WORKER_DOCKER_CLI": sys.executable,
    }


def test_semgrep_can_be_the_only_enabled_scanner(tmp_path: Path) -> None:
    settings = ExecutionSettings.from_env(Environment.CI, semgrep_env(tmp_path))

    assert settings.semgrep_enabled
    assert not settings.gitleaks_enabled
    assert settings.semgrep_policy == ADAPTER.policy()


def test_semgrep_is_refused_in_production(tmp_path: Path) -> None:
    env = semgrep_env(tmp_path) | {"SENTINEL_WORKER_DB_SSLMODE": "verify-full"}

    with pytest.raises(ConfigurationError, match="SEMGREP_ENABLED=true is not permitted"):
        ExecutionSettings.from_env(Environment.PRODUCTION, env)


@pytest.mark.parametrize(
    "overrides",
    [
        {"SENTINEL_WORKER_SEMGREP_ENABLED": "1"},
        {"SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR": ""},
        {"SENTINEL_WORKER_DOCKER_CLI": "docker"},
    ],
)
def test_unsafe_semgrep_settings_are_refused(tmp_path: Path, overrides: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        ExecutionSettings.from_env(Environment.CI, semgrep_env(tmp_path) | overrides)

import copy
import json

import pytest
from jsonschema import Draft202012Validator

from sentinel_worker.messaging import contracts
from support import CONTRACTS_DIR, scan_requested

SHARED_LOCATIONS = {
    contracts.SCAN_REQUESTED_SCHEMA: CONTRACTS_DIR / "messages" / "v1",
    contracts.PROCESSING_RECEIPT_SCHEMA: CONTRACTS_DIR / "messages" / "v1",
    contracts.DEAD_LETTER_METADATA_SCHEMA: CONTRACTS_DIR / "messages" / "v1",
    contracts.TOPOLOGY: CONTRACTS_DIR / "messaging",
}


def errors(message: object) -> list[str]:
    validator = contracts.validator(contracts.SCAN_REQUESTED_SCHEMA)
    return [error.message for error in validator.iter_errors(message)]


@pytest.mark.parametrize("name", contracts.BUNDLED_FILES)
def test_bundled_contracts_are_identical_to_the_shared_contracts(name: str) -> None:
    shared = (SHARED_LOCATIONS[name] / name).read_bytes().replace(b"\r\n", b"\n")
    assert contracts.read_bytes(name).replace(b"\r\n", b"\n") == shared


@pytest.mark.parametrize(
    "name",
    [
        contracts.SCAN_REQUESTED_SCHEMA,
        contracts.PROCESSING_RECEIPT_SCHEMA,
        contracts.DEAD_LETTER_METADATA_SCHEMA,
    ],
)
def test_bundled_schemas_are_valid_json_schema_2020_12(name: str) -> None:
    Draft202012Validator.check_schema(contracts.load(name))


def test_schema_examples_conform() -> None:
    for example in contracts.load(contracts.SCAN_REQUESTED_SCHEMA)["examples"]:
        assert errors(example) == []


def test_a_fresh_valid_message_conforms() -> None:
    assert errors(scan_requested()) == []


@pytest.mark.parametrize(
    "field",
    [
        "event_id",
        "schema_version",
        "scan_id",
        "project_id",
        "organization_id",
        "commit_sha",
        "occurred_at",
        "correlation_id",
    ],
)
def test_required_identifiers_are_enforced(field: str) -> None:
    message = scan_requested()
    del message[field]

    assert errors(message)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("event_type", "scan.cancelled"),
        ("event_id", "not-a-uuid"),
        ("organization_id", "0B8F6A0E-6F2B-4D55-9A8B-2C0C4B3F1D10"),
        ("commit_sha", "4f2c8e1"),
        ("commit_sha", "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e\n"),
        ("branch", "refs/heads/main"),
        ("branch", "main\n"),
        ("occurred_at", "2026-13-45T25:61:00Z"),
        ("occurred_at", "yesterday"),
        ("trigger_type", "WEBHOOK"),
    ],
)
def test_invalid_values_are_rejected(field: str, value: object) -> None:
    assert errors(scan_requested(**{field: value}))


def test_unknown_fields_such_as_credentials_are_rejected() -> None:
    assert errors(scan_requested(access_token="secret"))
    message = scan_requested()
    message["repository"] = {**message["repository"], "url": "https://evil.example/repo.git"}
    assert errors(message)


def test_python_end_anchor_matches_ecma_semantics() -> None:
    # Python's `$` alone would accept a trailing newline; the strict validator must not.
    message = copy.deepcopy(scan_requested())
    message["scan_id"] += "\n"
    assert errors(message)


def test_topology_contract_defines_the_worker_queue_and_dead_lettering() -> None:
    topology = json.loads(contracts.read_bytes(contracts.TOPOLOGY))
    worker = next(q for q in topology["queues"] if q["name"] == "sentinel.scan-requests.worker")

    assert worker["arguments"]["x-queue-type"] == "quorum"
    assert worker["arguments"]["x-dead-letter-exchange"] == "sentinel.scan-requests.dlx"
    assert worker["arguments"]["x-delivery-limit"] >= 1

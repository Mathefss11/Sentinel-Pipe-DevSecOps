"""Bundled copies of the shared message contracts.

The JSON files in this package are byte-identical copies of
``packages/contracts/messages/v1/*.schema.json`` and
``packages/contracts/messaging/topology.v1.json``; a test fails if they drift. They are
bundled so an installed worker validates messages without access to the repository.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators

_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})\Z", re.ASCII
)

_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _is_date_time(value: object) -> bool:
    """RFC 3339 date-time, checked with the standard library only."""
    if not isinstance(value, str):
        return True
    if not _RFC3339.match(value):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _strict_pattern(
    validator: Any, pattern: str, instance: object, schema: dict[str, Any]
) -> Iterator[ValidationError]:
    """ECMA-262 ``pattern`` semantics: ``$`` matches only at the very end.

    Python's ``$`` also matches before a trailing newline, which would let
    ``"<sha>\\n"`` pass ``^[0-9a-f]{40}$``. Contract patterns only use ``$`` as an end
    anchor, so it is translated to ``\\Z``.
    """
    if not validator.is_type(instance, "string"):
        return
    if not re.search(pattern.replace("$", r"\Z"), instance):  # type: ignore[arg-type]
        yield ValidationError(f"does not match the pattern for {schema.get('title', 'value')}")


_StrictValidator = validators.extend(Draft202012Validator, {"pattern": _strict_pattern})

SCAN_REQUESTED_SCHEMA = "scan-requested.v1.schema.json"
PROCESSING_RECEIPT_SCHEMA = "processing-receipt.v1.schema.json"
DEAD_LETTER_METADATA_SCHEMA = "dead-letter-metadata.v1.schema.json"
TOPOLOGY = "topology.v1.json"

BUNDLED_FILES = (
    SCAN_REQUESTED_SCHEMA,
    PROCESSING_RECEIPT_SCHEMA,
    DEAD_LETTER_METADATA_SCHEMA,
    TOPOLOGY,
)


def read_bytes(name: str) -> bytes:
    if name not in BUNDLED_FILES:
        raise ValueError("unknown contract file")
    return resources.files(__package__).joinpath(name).read_bytes()


@cache
def load(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(read_bytes(name))
    return document


@cache
def validator(schema_name: str) -> Any:
    """A strict validator: format assertions enabled, ECMA-262 end anchors."""
    schema = load(schema_name)
    Draft202012Validator.check_schema(schema)
    return _StrictValidator(schema, format_checker=_FORMAT_CHECKER)


def topology() -> dict[str, Any]:
    return load(TOPOLOGY)

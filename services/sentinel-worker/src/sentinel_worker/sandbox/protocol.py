"""Strict parsing of a sandbox's stdout (``sandbox-output.v1``, ADR-0009).

Everything a sandbox writes is untrusted. The parser accepts only a single JSON object
of at most the policy's stdout limit, without duplicate keys or non-standard constants,
conforming to the bundled schema. It decodes base64 strictly and builds
:class:`~sentinel_worker.execution.evidence.Artifact` values, which re-check names, media
types and sizes. Names are identifiers, never paths, so the worker never touches a
filesystem location chosen by the sandbox. Errors carry codes only, never content.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from sentinel_worker.execution.evidence import MAX_ARTIFACTS, MAX_TOTAL_BYTES, Artifact
from sentinel_worker.messaging import contracts


class InvalidOutputError(ValueError):
    """The sandbox output violates sandbox-output.v1. ``code`` is a sanitized reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise InvalidOutputError("DUPLICATE_KEYS")
    return dict(pairs)


def _reject_constant(_: str) -> None:
    raise InvalidOutputError("INVALID_JSON")


def parse(stdout: bytes) -> tuple[Artifact, ...]:
    try:
        text = stdout.decode("utf-8")
        document = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
    except InvalidOutputError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidOutputError("INVALID_JSON") from None
    if not isinstance(document, dict):
        raise InvalidOutputError("INVALID_JSON")
    if document.get("schema_version") != 1:
        raise InvalidOutputError("UNSUPPORTED_SCHEMA_VERSION")
    validator = contracts.validator(contracts.SANDBOX_OUTPUT_SCHEMA)
    if next(validator.iter_errors(document), None) is not None:
        raise InvalidOutputError("SCHEMA_VIOLATION")
    artifacts: list[Artifact] = []
    for entry in document["artifacts"][:MAX_ARTIFACTS]:
        try:
            content = base64.b64decode(entry["content_base64"], validate=True)
            artifacts.append(Artifact(entry["name"], entry["media_type"], content))
        except (binascii.Error, ValueError):
            raise InvalidOutputError("INVALID_ARTIFACT") from None
    names = [artifact.name for artifact in artifacts]
    if len(names) != len(set(names)):
        raise InvalidOutputError("DUPLICATE_ARTIFACT")
    if sum(len(artifact.content) for artifact in artifacts) > MAX_TOTAL_BYTES:
        raise InvalidOutputError("OUTPUT_TOO_LARGE")
    return tuple(artifacts)

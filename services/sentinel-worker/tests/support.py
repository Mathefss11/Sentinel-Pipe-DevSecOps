"""Shared helpers for worker tests."""

import json
import uuid
from pathlib import Path
from typing import Any

from sentinel_worker.messaging.handler import MessageProperties

CONTRACTS_DIR = Path(__file__).resolve().parents[3] / "packages" / "contracts"


def scan_requested(**overrides: Any) -> dict[str, Any]:
    """A valid scan.requested v1 message with fresh identifiers."""
    message: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_type": "scan.requested",
        "schema_version": 1,
        "occurred_at": "2026-10-09T12:02:00.500000Z",
        "correlation_id": str(uuid.uuid4()),
        "scan_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "commit_sha": "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e",
        "branch": "feature/login",
        "trigger_type": "PULL_REQUEST",
        "repository": {"provider": "GITHUB", "owner": "acme-corp", "name": "payments-service"},
    }
    message.update(overrides)
    return message


def encode(message: Any) -> bytes:
    return json.dumps(message).encode("utf-8")


def properties_for(message: dict[str, Any]) -> MessageProperties:
    return MessageProperties(
        message_id=message.get("event_id"),
        message_type="scan.requested.v1",
        content_type="application/json",
    )

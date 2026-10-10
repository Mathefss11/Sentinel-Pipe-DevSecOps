from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel_worker.messaging.receipts import SqliteReceiptStore


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SqliteReceiptStore]:
    with SqliteReceiptStore(tmp_path / "receipts.sqlite3") as receipt_store:
        yield receipt_store

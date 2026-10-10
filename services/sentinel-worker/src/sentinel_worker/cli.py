"""Command-line entry point for the worker."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence

from sentinel_worker import __version__
from sentinel_worker.config import ConfigurationError, WorkerSettings
from sentinel_worker.health import run_self_check

EXIT_OK = 0
EXIT_UNHEALTHY = 1
EXIT_CONFIGURATION = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-worker",
        description="SentinelPipe execution and processing plane worker.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "self-check",
        help="Verify the runtime and configuration; prints a JSON report.",
    )
    consume = commands.add_parser(
        "consume",
        help="Consume scan.requested messages from RabbitMQ and record processing receipts.",
    )
    consume.add_argument(
        "--max-messages", type=int, default=None, help="Stop after handling this many messages."
    )
    consume.add_argument(
        "--idle-timeout",
        type=float,
        default=None,
        help="Stop after this many seconds without a message.",
    )
    return parser


def _consume(args: argparse.Namespace) -> int:
    # Imported lazily so `self-check` works without broker libraries being importable.
    from sentinel_worker.messaging.consumer import ScanRequestConsumer, new_worker_id
    from sentinel_worker.messaging.handler import MessageHandler
    from sentinel_worker.messaging.receipts import SqliteReceiptStore
    from sentinel_worker.messaging.settings import ConsumerSettings

    try:
        worker_settings = WorkerSettings.from_env()
        settings = ConsumerSettings.from_env()
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    logging.basicConfig(
        level=worker_settings.log_level, format="%(asctime)s %(levelname)s %(message)s"
    )
    worker_id = new_worker_id()
    with SqliteReceiptStore(settings.receipt_db) as store:
        consumer = ScanRequestConsumer(settings, MessageHandler(store, worker_id), worker_id)
        consumer.run(max_messages=args.max_messages, inactivity_timeout=args.idle_timeout)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "self-check":
        report = run_self_check()
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK if report.healthy else EXIT_UNHEALTHY

    if args.command == "consume":
        return _consume(args)

    raise AssertionError(f"unhandled command: {args.command}")  # pragma: no cover

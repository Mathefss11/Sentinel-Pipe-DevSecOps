"""Command-line entry point for the worker."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from sentinel_worker import __version__
from sentinel_worker.health import run_self_check

EXIT_OK = 0
EXIT_UNHEALTHY = 1


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "self-check":
        report = run_self_check()
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK if report.healthy else EXIT_UNHEALTHY

    raise AssertionError(f"unhandled command: {args.command}")  # pragma: no cover

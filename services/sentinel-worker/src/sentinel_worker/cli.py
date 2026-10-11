"""Command-line entry point for the worker and the operator recovery tools."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
from collections.abc import Sequence
from typing import Any

from sentinel_worker import __version__
from sentinel_worker.config import ConfigurationError, WorkerSettings
from sentinel_worker.health import run_self_check

EXIT_OK = 0
EXIT_UNHEALTHY = 1
EXIT_CONFIGURATION = 2
EXIT_UNAVAILABLE = 3


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
    execute = commands.add_parser(
        "execute",
        help="Claim scan jobs with leases, execute them and report outcomes (ADR-0007).",
    )
    execute.add_argument("--max-jobs", type=int, default=None, help="Stop after this many jobs.")
    execute.add_argument(
        "--idle-timeout",
        type=float,
        default=None,
        help="Stop after this many seconds without a claimable job.",
    )

    # Operator recovery tools (operator credentials; see docs/runbooks/messaging.md).
    commands.add_parser("outbox-summary", help="[operator] Outbox counts and oldest pending age.")
    listing = commands.add_parser(
        "outbox-list-failed", help="[operator] List FAILED outbox events (no payloads)."
    )
    listing.add_argument("--limit", type=int, default=20)
    requeue = commands.add_parser(
        "outbox-requeue-failed",
        help="[operator] Return FAILED outbox events to PENDING (audited, bounded).",
    )
    _audit_arguments(requeue)
    requeue.add_argument(
        "--event-id", action="append", default=None, help="Specific event id (repeatable)."
    )
    requeue.add_argument("--limit", type=int, default=10, help="Oldest FAILED events (1-100).")
    sandbox_check = commands.add_parser(
        "sandbox-check",
        help="Verify the sandbox runtime, image and isolation controls; prints a JSON report.",
    )
    sandbox_check.add_argument(
        "--profile",
        choices=("fixture", "gitleaks", "semgrep"),
        default="fixture",
        help="Sandbox image and limits to verify (default: fixture).",
    )
    commands.add_parser("dlq-depth", help="[operator] Ready messages in the dead-letter queue.")
    replay = commands.add_parser(
        "dlq-replay",
        help="[operator] Republish dead-lettered messages for reprocessing (audited, bounded).",
    )
    _audit_arguments(replay)
    replay.add_argument("--max-messages", type=int, default=10, help="1-100, oldest first.")
    return parser


def _audit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--operator", required=True, help="Your operator name (audited).")
    parser.add_argument("--reason", required=True, help="Why (audited; e.g. an incident id).")


def _consume(args: argparse.Namespace) -> int:
    # Imported lazily so `self-check` works without broker libraries being importable.
    from sentinel_worker.messaging.consumer import ScanRequestConsumer, new_worker_id
    from sentinel_worker.messaging.handler import MessageHandler
    from sentinel_worker.messaging.receipts import (
        PostgresReceiptStore,
        ReceiptStore,
        SqliteReceiptStore,
    )
    from sentinel_worker.messaging.settings import (
        ConsumerSettings,
        ReceiptBackend,
        ReceiptStoreSettings,
    )
    from sentinel_worker.metrics import MetricsSettings, WorkerMetrics, serve

    try:
        worker_settings = WorkerSettings.from_env()
        settings = ConsumerSettings.from_env()
        store_settings = ReceiptStoreSettings.from_env(worker_settings.environment)
        metrics_settings = MetricsSettings.from_env()
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    logging.basicConfig(
        level=worker_settings.log_level, format="%(asctime)s %(levelname)s %(message)s"
    )
    worker_id = new_worker_id()
    store: ReceiptStore
    if store_settings.backend is ReceiptBackend.SQLITE:
        if store_settings.sqlite_path is None:  # pragma: no cover - guaranteed by settings
            raise AssertionError("sqlite path missing")
        logging.getLogger(__name__).warning(
            json.dumps(
                {
                    "event": "receipt_store.development_only",
                    "backend": "sqlite",
                    "note": "single host, no control-plane verification",
                }
            )
        )
        store = SqliteReceiptStore(store_settings.sqlite_path)
    else:
        if store_settings.database is None:  # pragma: no cover - guaranteed by settings
            raise AssertionError("database settings missing")
        store = PostgresReceiptStore(store_settings.database, worker_id)
    metrics = WorkerMetrics()
    serve(metrics, metrics_settings)
    try:
        consumer = ScanRequestConsumer(
            settings, MessageHandler(store, worker_id), worker_id, metrics=metrics
        )
        consumer.run(max_messages=args.max_messages, inactivity_timeout=args.idle_timeout)
    finally:
        store.close()
    return EXIT_OK


def _execute(args: argparse.Namespace) -> int:
    # Imported lazily so `self-check` works without database libraries being importable.
    from sentinel_worker.execution.fixture import FixtureExecutor
    from sentinel_worker.execution.leases import JobLeaseClient
    from sentinel_worker.execution.runner import ExecutionLoop, JobExecutor
    from sentinel_worker.execution.sandboxed import SandboxedFixtureExecutor
    from sentinel_worker.execution.settings import ExecutionSettings
    from sentinel_worker.messaging.consumer import new_worker_id
    from sentinel_worker.metrics import ExecutionMetrics, MetricsSettings, serve
    from sentinel_worker.repository.snapshot import LocalFixtureRepositorySource
    from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxError
    from sentinel_worker.scanners.executor import DispatchingExecutor, ScannerExecutor

    try:
        worker_settings = WorkerSettings.from_env()
        settings = ExecutionSettings.from_env(worker_settings.environment)
        metrics_settings = MetricsSettings.from_env()
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    logging.basicConfig(
        level=worker_settings.log_level, format="%(asctime)s %(levelname)s %(message)s"
    )
    executors: list[JobExecutor] = []
    try:
        if settings.fixture_enabled and settings.fixture_executor == "sandbox":
            if settings.docker_cli is None or settings.sandbox_policy is None:  # pragma: no cover
                raise AssertionError("sandbox settings missing")
            sandbox = DockerSandbox(DockerCli(settings.docker_cli), settings.sandbox_policy)
            sandbox.check()
            # Sandboxes left behind by a crashed worker are removed once they expire.
            sandbox.reap_expired()
            executors.append(
                SandboxedFixtureExecutor(sandbox, settings.fixture_mode, settings.fixture_seconds)
            )
        elif settings.fixture_enabled:
            executors.append(FixtureExecutor(settings.fixture_seconds))
        # Adapters are imported only when enabled: the Semgrep module verifies its bundled
        # ruleset on import, which must not affect workers that do not run Semgrep.
        scanners = (
            (settings.gitleaks_enabled, settings.gitleaks_policy, "gitleaks"),
            (settings.semgrep_enabled, settings.semgrep_policy, "semgrep"),
        )
        for enabled, scanner_policy, scanner_name in scanners:
            if not enabled:
                continue
            adapter = _adapter(scanner_name)
            if (
                settings.docker_cli is None
                or scanner_policy is None
                or settings.repository_fixtures_dir is None
            ):  # pragma: no cover - guaranteed by settings
                raise AssertionError("scanner settings missing")
            scanner_sandbox = DockerSandbox(DockerCli(settings.docker_cli), scanner_policy)
            scanner_sandbox.check()
            scanner_sandbox.reap_expired()
            executors.append(
                ScannerExecutor(
                    scanner_sandbox,
                    adapter,
                    LocalFixtureRepositorySource(settings.repository_fixtures_dir),
                )
            )
    except SandboxError as exc:
        print(f"unavailable: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    executor: JobExecutor = executors[0] if len(executors) == 1 else DispatchingExecutor(executors)
    worker_id = new_worker_id()
    client = JobLeaseClient(settings.database, worker_id)
    heartbeats = JobLeaseClient(settings.database, f"{worker_id[:50]}-heartbeat")
    metrics = ExecutionMetrics()
    serve(metrics, metrics_settings)
    loop = ExecutionLoop(
        client,
        heartbeats,
        executor,
        poll_interval=settings.poll_interval_seconds,
        metrics=metrics,
    )
    previous = {
        signum: signal.signal(signum, lambda *_: loop.request_shutdown())
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        summary = loop.run(max_jobs=args.max_jobs, idle_timeout=args.idle_timeout)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        client.close()
        heartbeats.close()
    print(json.dumps(summary.to_dict()))
    return EXIT_OK


def _adapter(name: str) -> Any:
    if name == "gitleaks":
        from sentinel_worker.scanners.gitleaks import GitleaksAdapter

        return GitleaksAdapter()
    from sentinel_worker.scanners.semgrep import SemgrepAdapter

    return SemgrepAdapter()


def _sandbox_check(profile: str = "fixture") -> int:
    """Runs the isolation probe in a real sandbox and verifies every control. The
    ``gitleaks`` and ``semgrep`` profiles run it with that scanner's image and limits (both
    have a BusyBox userland)."""
    import threading

    from sentinel_worker.execution.settings import _docker_cli
    from sentinel_worker.sandbox.docker import DockerCli, DockerSandbox, SandboxError, SandboxStatus
    from sentinel_worker.sandbox.isolation import probe_command, verify
    from sentinel_worker.sandbox.policy import SandboxPolicy
    from sentinel_worker.scanners.gitleaks import GitleaksAdapter
    from sentinel_worker.scanners.semgrep import SemgrepAdapter

    profiles = {
        "fixture": lambda: SandboxPolicy(timeout_seconds=60),
        "gitleaks": lambda: GitleaksAdapter().policy(timeout_seconds=60),
        "semgrep": lambda: SemgrepAdapter().policy(timeout_seconds=60),
    }
    policy = profiles[profile]()
    try:
        sandbox = DockerSandbox(DockerCli(_docker_cli(os.environ)), policy)
        sandbox.check()
        run = sandbox.run(probe_command(), threading.Event())
    except (ConfigurationError, SandboxError) as exc:
        print(json.dumps({"healthy": False, "error": str(exc)}, indent=2))
        return EXIT_UNAVAILABLE
    report = (
        verify(run, sandbox.policy)
        if run.status is SandboxStatus.EXITED
        else {
            "healthy": False,
            "error": f"probe ended with {run.status.value}",
        }
    )
    print(json.dumps(report, indent=2))
    return EXIT_OK if report["healthy"] else EXIT_UNHEALTHY


def _operator(args: argparse.Namespace) -> int:
    import pika
    import pika.exceptions
    import psycopg

    from sentinel_worker import operations

    try:
        environment = WorkerSettings.from_env().environment
        if args.command in ("outbox-requeue-failed", "dlq-replay"):
            operations.require_audit_fields(args.operator, args.reason)
        database = (
            operations.operator_database_settings(environment)
            if args.command != "dlq-depth"
            else None
        )
        broker = (
            operations.OperatorBrokerSettings.from_env()
            if args.command in ("dlq-depth", "dlq-replay")
            else None
        )
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION

    result: Any
    try:
        connection = (
            psycopg.connect(**database.connection_kwargs("sentinel-operator"))
            if database is not None
            else None
        )
        try:
            if args.command == "outbox-summary":
                result = operations.outbox_summary(connection)
            elif args.command == "outbox-list-failed":
                result = operations.list_failed_outbox_events(connection, args.limit)
            elif args.command == "outbox-requeue-failed":
                requeued = operations.requeue_failed_outbox_events(
                    connection, args.operator, args.reason, args.event_id, args.limit
                )
                result = {"requeued": requeued}
            else:
                if broker is None:  # pragma: no cover - guaranteed above
                    raise AssertionError("broker settings missing")
                parameters = pika.ConnectionParameters(
                    host=broker.host,
                    port=broker.port,
                    virtual_host=broker.virtual_host,
                    credentials=pika.PlainCredentials(broker.username, broker.password),
                    client_properties={"connection_name": "sentinel-operator"},
                )
                amqp = pika.BlockingConnection(parameters)
                try:
                    channel = amqp.channel()
                    if args.command == "dlq-depth":
                        result = {"dead_letter_ready": operations.dead_letter_depth(channel)}
                    else:
                        channel.confirm_delivery()
                        audit = operations.audit_dead_letter_replay(
                            connection, args.operator, args.reason
                        )
                        result = operations.replay_dead_letters(
                            channel, audit, args.max_messages
                        ).to_dict()
                finally:
                    if amqp.is_open:
                        amqp.close()
        finally:
            if connection is not None:
                connection.close()
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    except (psycopg.Error, pika.exceptions.AMQPError) as exc:
        # Error type only: driver messages can contain host names or user names.
        print(f"unavailable: {type(exc).__name__}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    print(json.dumps(result, indent=2, default=str))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "self-check":
        report = run_self_check()
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK if report.healthy else EXIT_UNHEALTHY

    if args.command == "consume":
        return _consume(args)

    if args.command == "execute":
        return _execute(args)

    if args.command == "sandbox-check":
        return _sandbox_check(args.profile)

    return _operator(args)

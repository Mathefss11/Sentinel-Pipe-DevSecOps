"""Runs one sandboxed process in a fresh container and always removes it.

Lifecycle of :meth:`DockerSandbox.run`:

1. **create and start** ``docker run`` with the arguments of :mod:`.policy` (no shell on the
   host; the Docker CLI receives a sanitized environment without ``SENTINEL_*`` variables);
2. **controlled execution**: stdout and stderr are read by bounded readers (excess is
   drained and discarded, never buffered); stdin is closed;
3. **resource monitoring**: ``docker stats`` is sampled for peak PIDs and memory;
4. **timeout**, **cancellation** (the caller's stop event, set on job cancellation, lease
   loss or shutdown) and **output overflow** each trigger
5. **forced termination**: ``docker kill --signal KILL`` ends the container's whole process
   tree (PID namespace); the CLI process is killed if it does not exit;
6. **cleanup**: ``docker rm --force`` in a ``finally`` block, after success, failure,
   timeout and cancellation;
7. **crash recovery**: containers carry an expiry label. :meth:`reap_expired` removes
   sandboxes left behind by crashed workers once they expire.

The sandbox never sees the worker's database credentials, lease token or broker
credentials: they are not passed to the container, and the Docker CLI process does not
receive ``SENTINEL_*`` variables either.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import IO, Any

from sentinel_worker.sandbox.policy import (
    EXPIRES_LABEL,
    SANDBOX_LABEL,
    SANDBOX_NAME,
    SandboxPolicy,
    new_sandbox_name,
    run_arguments,
)

logger = logging.getLogger(__name__)

_CHUNK = 64 * 1024
_CLI_TIMEOUT = 30.0
_SECRET_LIKE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_SIZE = re.compile(r"([0-9.]+)\s*([KMGT]?i?B)", re.IGNORECASE)
_UNITS = {"b": 1, "kb": 1000, "kib": 1024, "mb": 1000**2, "mib": 1024**2, "gb": 1000**3,
          "gib": 1024**3, "tb": 1000**4, "tib": 1024**4}  # fmt: skip


class SandboxStatus(StrEnum):
    EXITED = "EXITED"
    """The process ended on its own; see ``exit_code``."""

    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    OOM_KILLED = "OOM_KILLED"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    PIDS_EXHAUSTED = "PIDS_EXHAUSTED"
    """The process count reached the PID limit (observed by the monitor)."""

    START_FAILED = "START_FAILED"
    """The runtime could not create or start the container."""

    LOST = "LOST"
    """The runtime CLI ended while the container was still running (CLI killed, daemon
    connection lost): the outcome is unknown, so it fails closed."""


@dataclass(frozen=True, slots=True)
class SandboxRun:
    status: SandboxStatus
    exit_code: int | None
    stdout: bytes = field(repr=False)
    stderr_excerpt: str
    duration_seconds: float
    peak_pids: int | None
    peak_memory_bytes: int | None
    removed: bool


class SandboxError(Exception):
    """The container runtime is unusable (missing CLI, daemon down)."""


def sanitize(text: bytes | str, limit: int = 256) -> str:
    """A log-safe excerpt: control characters removed, long token-like runs redacted,
    length bounded."""
    value = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    value = _CONTROL.sub(" ", value)
    value = _SECRET_LIKE.sub("[redacted]", value)
    value = " ".join(value.split())
    return value[:limit]


def cli_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The Docker CLI's environment: the worker's, minus every ``SENTINEL_*`` variable
    (database and broker credentials never reach the runtime tooling)."""
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if not key.upper().startswith("SENTINEL_")}


class _BoundedReader(threading.Thread):
    """Keeps at most ``limit`` bytes of a stream and drains the rest."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        super().__init__(daemon=True, name="sentinel-sandbox-reader")
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._kept = 0
        self.overflowed = False

    def run(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            while True:
                chunk = (
                    self._stream.read1(_CHUNK)
                    if hasattr(self._stream, "read1")
                    else (self._stream.read(_CHUNK))
                )
                if not chunk:
                    return
                room = self._limit - self._kept
                if len(chunk) > room:
                    self.overflowed = True
                    chunk = chunk[: max(room, 0)]
                if chunk:
                    self._chunks.append(chunk)
                    self._kept += len(chunk)

    def data(self) -> bytes:
        return b"".join(self._chunks)


def _parse_size(text: str) -> int | None:
    match = _SIZE.search(text)
    if match is None:
        return None
    unit = _UNITS.get(match.group(2).lower())
    return int(float(match.group(1)) * unit) if unit else None


class _Monitor(threading.Thread):
    """Samples ``docker stats`` for the peak PID count and memory usage."""

    def __init__(self, docker: DockerCli, name: str, interval: float) -> None:
        super().__init__(daemon=True, name="sentinel-sandbox-monitor")
        self._docker = docker
        self._name = name
        self._interval = interval
        self._stopped = threading.Event()
        self.peak_pids: int | None = None
        self.peak_memory: int | None = None

    def run(self) -> None:
        while not self._stopped.wait(self._interval):
            try:
                result = self._docker.call(
                    ["stats", "--no-stream", "--format", "{{.PIDs}}|{{.MemUsage}}", self._name],
                    timeout=10,
                )
            except (SandboxError, subprocess.TimeoutExpired):
                continue
            if result.returncode != 0:
                continue
            pids_text, _, memory_text = (
                result.stdout.decode("ascii", "replace").strip().partition("|")
            )
            if pids_text.isdigit():
                self.peak_pids = max(self.peak_pids or 0, int(pids_text))
            memory = _parse_size(memory_text.split("/")[0])
            if memory is not None:
                self.peak_memory = max(self.peak_memory or 0, memory)

    def stop(self) -> None:
        self._stopped.set()
        self.join(timeout=15)


class DockerCli:
    """Invokes one fixed Docker CLI executable with argument vectors (never a shell)."""

    def __init__(self, executable: str, environ: Mapping[str, str] | None = None) -> None:
        if not os.path.isabs(executable) or not os.path.isfile(executable):
            raise SandboxError("the container runtime CLI must be an existing absolute path")
        self.executable = executable
        self._env = cli_environment(environ)

    def call(
        self, arguments: Sequence[str], timeout: float = _CLI_TIMEOUT
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(  # noqa: S603 - fixed executable, argument vector, no shell
                [self.executable, *arguments],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                env=self._env,
                check=False,
            )
        except OSError as exc:
            raise SandboxError("container runtime unavailable") from exc

    def start(self, arguments: Sequence[str]) -> subprocess.Popen[bytes]:
        try:
            return subprocess.Popen(  # noqa: S603 - fixed executable, argument vector, no shell
                [self.executable, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
            )
        except OSError as exc:
            raise SandboxError("container runtime unavailable") from exc


class DockerSandbox:
    def __init__(
        self,
        docker: DockerCli,
        policy: SandboxPolicy,
        monitor_interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._docker = docker
        self.policy = policy
        self._monitor_interval = monitor_interval
        self._clock = clock
        self._wall_clock = wall_clock

    def run(
        self,
        argv: Sequence[str],
        stop: threading.Event,
        timeout_seconds: float | None = None,
        job_id: str | None = None,
    ) -> SandboxRun:
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout must be positive")
        timeout = min(
            timeout_seconds if timeout_seconds is not None else self.policy.timeout_seconds,
            self.policy.timeout_seconds,
        )
        if stop.is_set():
            # Cancelled before anything started: nothing to create or clean up.
            return SandboxRun(SandboxStatus.CANCELLED, None, b"", "", 0.0, None, None, True)
        name = new_sandbox_name()
        labels = {"sentinelpipe.job": job_id} if job_id else {}
        expires_at = int(self._wall_clock() + timeout + self.policy.expiry_grace_seconds)
        arguments = run_arguments(self.policy, name, argv, labels, expires_at)
        started = self._clock()
        process = self._docker.start(arguments)
        if process.stdout is None or process.stderr is None:  # pragma: no cover - PIPE
            raise SandboxError("sandbox streams unavailable")
        stdout = _BoundedReader(process.stdout, self.policy.max_stdout_bytes)
        stderr = _BoundedReader(process.stderr, self.policy.max_stderr_bytes)
        monitor = _Monitor(self._docker, name, self._monitor_interval)
        for thread in (stdout, stderr, monitor):
            thread.start()
        reason: SandboxStatus | None = None
        removed = False
        try:
            deadline = started + timeout
            while process.poll() is None:
                if stop.is_set():
                    reason = SandboxStatus.CANCELLED
                elif self._clock() >= deadline:
                    reason = SandboxStatus.TIMED_OUT
                elif stdout.overflowed:
                    reason = SandboxStatus.OUTPUT_LIMIT
                if reason is not None:
                    self._kill(name, process)
                    break
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=0.05)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=_CLI_TIMEOUT)
            stdout.join(timeout=10)
            stderr.join(timeout=10)
            monitor.stop()
            state = self._inspect(name)
        finally:
            # Also on unexpected errors: no monitor thread or container may outlive the run.
            monitor.stop()
            if process.poll() is None:
                process.kill()
            removed = self.remove(name)
        duration = self._clock() - started
        status, exit_code = self._classify(reason, state, stdout.overflowed, monitor.peak_pids)
        run = SandboxRun(
            status=status,
            exit_code=exit_code,
            stdout=stdout.data(),
            stderr_excerpt=sanitize(stderr.data()),
            duration_seconds=duration,
            peak_pids=monitor.peak_pids,
            peak_memory_bytes=monitor.peak_memory,
            removed=removed,
        )
        logger.info(
            json.dumps(
                {
                    "event": "sandbox.finished",
                    "status": status.value,
                    "exit_code": exit_code,
                    "duration_seconds": round(duration, 3),
                    "peak_pids": monitor.peak_pids,
                    "peak_memory_bytes": monitor.peak_memory,
                    "removed": removed,
                    "stderr_bytes": len(stderr.data()),
                },
                sort_keys=True,
            )
        )
        return run

    def _classify(
        self,
        reason: SandboxStatus | None,
        state: dict[str, Any] | None,
        overflowed: bool,
        peak_pids: int | None,
    ) -> tuple[SandboxStatus, int | None]:
        exit_code = state.get("ExitCode") if state else None
        if reason is SandboxStatus.CANCELLED:
            return reason, exit_code
        if (
            state is None
            or not state.get("StartedAt", "").strip()
            or state.get("StartedAt", "").startswith("0001-01-01")
        ):
            return SandboxStatus.START_FAILED, exit_code
        if state.get("Running") and reason is None:
            # The CLI is gone but the container still runs: no trustworthy exit status.
            return SandboxStatus.LOST, None
        if state.get("OOMKilled"):
            return SandboxStatus.OOM_KILLED, exit_code
        if overflowed or reason is SandboxStatus.OUTPUT_LIMIT:
            return SandboxStatus.OUTPUT_LIMIT, exit_code
        if peak_pids is not None and peak_pids >= self.policy.pids:
            return SandboxStatus.PIDS_EXHAUSTED, exit_code
        if reason is SandboxStatus.TIMED_OUT:
            return reason, exit_code
        return SandboxStatus.EXITED, exit_code

    def _kill(self, name: str, process: subprocess.Popen[bytes]) -> None:
        with contextlib.suppress(SandboxError, subprocess.TimeoutExpired):
            self._docker.call(["kill", "--signal", "KILL", name], timeout=15)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=15)
        if process.poll() is None:
            process.kill()

    def _inspect(self, name: str) -> dict[str, Any] | None:
        try:
            result = self._docker.call(["inspect", "--format", "{{json .State}}", name])
        except (SandboxError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        try:
            state = json.loads(result.stdout)
        except ValueError:
            return None
        return state if isinstance(state, dict) else None

    def remove(self, name: str) -> bool:
        """Removes the container (idempotent). Returns whether it is gone."""
        try:
            result = self._docker.call(["rm", "--force", name], timeout=60)
        except (SandboxError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 or b"No such container" in result.stderr

    def reap_expired(self) -> int:
        """Removes sandboxes left behind by crashed workers. Returns the number removed.

        Ownership rule: a sandbox belongs to the worker that started it until its expiry
        label (wall-clock deadline plus grace) passes. Its owner always ends it before then,
        so a live sandbox of another worker is never removed. Only sandbox containers
        (label and exact name pattern) are considered. A container whose expiry label is
        missing or malformed is removed only once it is no longer running.
        """
        try:
            result = self._docker.call(
                [
                    "ps",
                    "--all",
                    "--filter",
                    f"label={SANDBOX_LABEL}=1",
                    "--format",
                    f'{{{{.Names}}}}\t{{{{.State}}}}\t{{{{.Label "{EXPIRES_LABEL}"}}}}',
                ]
            )
        except (SandboxError, subprocess.TimeoutExpired):
            return 0
        if result.returncode != 0:
            return 0
        now = self._wall_clock()
        removed = 0
        for line in result.stdout.decode("ascii", "replace").splitlines():
            name, _, rest = line.partition("\t")
            state, _, expires = rest.partition("\t")
            if not SANDBOX_NAME.match(name):
                continue
            # Without a valid expiry, only a stopped container is considered abandoned.
            expired = int(expires) <= now if expires.isdigit() else state != "running"
            if expired and self.remove(name):
                removed += 1
        if removed:
            logger.warning(json.dumps({"event": "sandbox.reaped", "count": removed}))
        return removed

    def check(self) -> None:
        """Raises :class:`SandboxError` unless the runtime answers and the image is present
        locally (images are never pulled at execution time)."""
        result = self._docker.call(["image", "inspect", "--format", "{{.Id}}", self.policy.image])
        if result.returncode != 0:
            raise SandboxError("sandbox image unavailable (provision it before running workers)")

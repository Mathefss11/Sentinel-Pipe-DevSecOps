"""Immutable sandbox policy and the exact container runtime arguments it produces.

Everything that reaches the container runtime is built here from a frozen policy, an
allowlisted image and a validated argument vector. Nothing is interpreted by a shell on
the host. The container gets:

* no network (``--network none``), no IPC namespace sharing, a fresh hostname;
* a read-only root filesystem; one size-limited, ``noexec,nosuid,nodev`` tmpfs at ``/tmp``;
* a non-root user (65534), every capability dropped, ``no-new-privileges``, the runtime's
  default seccomp profile, an init process reaping children;
* memory (swap disabled), CPU, PID, open-file and core-dump limits;
* **no** volumes, bind mounts, Docker socket, devices, host namespaces, environment
  variables from the host, credentials or registry access (``--pull never``).

Whether these controls are a strong boundary depends on the runtime: with the default
``runc`` they share the host kernel (see ADR-0009 and docs/threat-model).

Trust policy (ADR-0009), enforced by :class:`SandboxPolicy`: every policy declares its
:class:`Workload`. Controlled fixtures and explicitly trusted scanner implementations may
run under runc (:attr:`Workload.TRUSTED_TOOL`). Arbitrary untrusted repository code
(:attr:`Workload.UNTRUSTED_CODE`) is refused unless a hardened runtime (gVisor, Kata)
is configured. Repository content stays untrusted input in both cases.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

#: Images the worker may start, pinned by digest. alpine:3.22 (BusyBox userland), used
#: only by the harmless FIXTURE scanner. Must match .github/workflows/ci.yml.
FIXTURE_IMAGE = "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
ALLOWED_IMAGES = frozenset({FIXTURE_IMAGE})

#: Executables a sandbox may start (inside the image).
ALLOWED_COMMANDS = frozenset({"/bin/sh"})

#: Hardened OCI runtimes that may replace runc (gVisor, Kata Containers).
ALLOWED_RUNTIMES = frozenset({"runsc", "kata-runtime", "kata"})

SANDBOX_LABEL = "sentinelpipe.sandbox"
JOB_LABEL = "sentinelpipe.job"
EXPIRES_LABEL = "sentinelpipe.expires-at"
SANDBOX_USER = "65534:65534"


class Workload(StrEnum):
    """What a sandbox executes, which decides the isolation it requires."""

    TRUSTED_TOOL = "trusted_tool"
    """Controlled fixtures and explicitly trusted scanner implementations (reviewed,
    digest-pinned images and commands). Any repository content they process is still
    untrusted input. Allowed under runc."""

    UNTRUSTED_CODE = "untrusted_code"
    """Arbitrary code from repositories (builds, test suites, package scripts). Never under
    runc: requires a hardened runtime (and, per ADR-0009, a validated deployment)."""


#: Runtimes that may execute UNTRUSTED_CODE: user-space kernel or VM isolation.
HARDENED_RUNTIMES = frozenset({"runsc", "kata-runtime", "kata"})

_DIGEST_REF = re.compile(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}\Z")
SANDBOX_NAME = re.compile(r"sentinel-sandbox-[0-9a-f]{32}\Z")
_LABEL_VALUE = re.compile(r"[0-9a-f-]{1,64}\Z")


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    image: str = FIXTURE_IMAGE
    memory_bytes: int = 256 * 1024 * 1024
    cpus: float = 1.0
    pids: int = 64
    tmpfs_bytes: int = 32 * 1024 * 1024
    timeout_seconds: float = 300.0
    max_stdout_bytes: int = 2 * 1024 * 1024
    max_stderr_bytes: int = 64 * 1024
    open_files: int = 256
    runtime: str | None = None
    #: Extra time after the timeout before an orphaned sandbox counts as expired.
    expiry_grace_seconds: int = 60
    workload: Workload = Workload.TRUSTED_TOOL

    def __post_init__(self) -> None:
        if self.image not in ALLOWED_IMAGES or not _DIGEST_REF.match(self.image):
            raise ValueError("sandbox image is not an allowlisted, digest-pinned image")
        if not 16 * 1024 * 1024 <= self.memory_bytes <= 8 * 1024 * 1024 * 1024:
            raise ValueError("memory must be between 16 MiB and 8 GiB")
        if not 0.1 <= self.cpus <= 8:
            raise ValueError("cpus must be between 0.1 and 8")
        if not 8 <= self.pids <= 4096:
            raise ValueError("pids must be between 8 and 4096")
        if not 1024 * 1024 <= self.tmpfs_bytes <= 1024 * 1024 * 1024:
            raise ValueError("tmpfs must be between 1 MiB and 1 GiB")
        if not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("timeout must be between 1 s and 1 h")
        if not 1024 <= self.max_stdout_bytes <= 16 * 1024 * 1024:
            raise ValueError("stdout limit must be between 1 KiB and 16 MiB")
        if not 1024 <= self.max_stderr_bytes <= 1024 * 1024:
            raise ValueError("stderr limit must be between 1 KiB and 1 MiB")
        if not 16 <= self.open_files <= 65536:
            raise ValueError("open file limit must be between 16 and 65536")
        if self.runtime is not None and self.runtime not in ALLOWED_RUNTIMES:
            raise ValueError("unsupported container runtime")
        if not 1 <= self.expiry_grace_seconds <= 3600:
            raise ValueError("expiry grace must be between 1 s and 1 h")
        if self.workload is Workload.UNTRUSTED_CODE and self.runtime not in HARDENED_RUNTIMES:
            raise ValueError(
                "untrusted code must not run under the default runc boundary; "
                "configure a hardened runtime (ADR-0009 trust policy)"
            )


def new_sandbox_name() -> str:
    return f"sentinel-sandbox-{uuid.uuid4().hex}"


def run_arguments(
    policy: SandboxPolicy,
    name: str,
    argv: Sequence[str],
    labels: Mapping[str, str],
    expires_at: int,
) -> list[str]:
    """The ``docker run`` arguments (without the executable) for one sandbox."""
    if not SANDBOX_NAME.match(name):
        raise ValueError("invalid sandbox name")
    if not argv or argv[0] not in ALLOWED_COMMANDS:
        raise ValueError("command is not allowlisted")
    for argument in argv:
        if not isinstance(argument, str) or "\x00" in argument or len(argument) > 64 * 1024:
            raise ValueError("invalid command argument")
    arguments = [
        "run",
        "--name", name,
        "--pull", "never",
        "--network", "none",
        "--ipc", "none",
        "--hostname", "sandbox",
        "--read-only",
        # Paths inside the container, not host temporary files.
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes}",  # noqa: S108
        "--workdir", "/tmp",  # noqa: S108
        "--user", SANDBOX_USER,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--init",
        "--memory", f"{policy.memory_bytes}b",
        "--memory-swap", f"{policy.memory_bytes}b",
        "--cpus", f"{policy.cpus:g}",
        "--pids-limit", str(policy.pids),
        "--ulimit", f"nofile={policy.open_files}:{policy.open_files}",
        "--ulimit", "core=0",
        "--log-driver", "none",
        "--label", f"{SANDBOX_LABEL}=1",
        "--label", f"{EXPIRES_LABEL}={int(expires_at)}",
    ]  # fmt: skip
    for key, value in sorted(labels.items()):
        if key != JOB_LABEL or not _LABEL_VALUE.match(value):
            raise ValueError("invalid sandbox label")
        arguments += ["--label", f"{key}={value}"]
    if policy.runtime is not None:
        arguments += ["--runtime", policy.runtime]
    arguments += ["--entrypoint", argv[0], policy.image, *argv[1:]]
    return arguments

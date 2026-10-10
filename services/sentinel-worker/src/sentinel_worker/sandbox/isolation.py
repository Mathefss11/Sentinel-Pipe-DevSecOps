"""Verification of the sandbox isolation controls from inside a running sandbox.

``sentinel-worker sandbox-check`` and the sandbox tests run the FIXTURE isolation probe
and compare what the process observed with the policy. This verifies the controls on
the actual host and runtime, rather than trusting the configuration.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sentinel_worker.sandbox.docker import SandboxRun
from sentinel_worker.sandbox.fixture import FixtureMode, script_command
from sentinel_worker.sandbox.policy import SandboxPolicy
from sentinel_worker.sandbox.protocol import InvalidOutputError, parse

#: Variables the container runtime itself sets; nothing else may reach the sandbox.
RUNTIME_VARIABLES = frozenset({"HOME", "HOSTNAME", "PATH", "PWD", "SHLVL"})

#: Mount points the runtime itself creates: the read-only root, the bounded tmpfs, the
#: read-only resolver and host files it generates, its init binary, and kernel
#: filesystems. Any other mount target (a host directory, a socket) fails the check.
RUNTIME_MOUNTS = frozenset(
    {"/", "/tmp", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/sbin/docker-init"}  # noqa: S108 - container paths
)
KERNEL_FILESYSTEMS = ("/proc", "/dev", "/sys")


def unexpected_mounts(targets: list[str]) -> list[str]:
    return [
        target
        for target in targets
        if target not in RUNTIME_MOUNTS
        and not any(target == root or target.startswith(root + "/") for root in KERNEL_FILESYSTEMS)
    ]


def probe_command() -> list[str]:
    return script_command(
        FixtureMode.ISOLATION_PROBE, str(uuid.uuid4()), str(uuid.uuid4()), 1, 1, 0
    )


def observations(run: SandboxRun) -> dict[str, Any]:
    (artifact,) = parse(run.stdout)
    document = json.loads(artifact.content)
    if not isinstance(document, dict):
        raise InvalidOutputError("SCHEMA_VIOLATION")
    return document


def verify(run: SandboxRun, policy: SandboxPolicy) -> dict[str, Any]:
    """A report of every control: ``{"healthy": bool, "controls": {name: bool}}``."""
    try:
        seen = observations(run)
    except (InvalidOutputError, ValueError):
        return {"healthy": False, "error": "isolation probe output invalid"}
    environment = set(str(seen.get("environment", "")).split())
    controls = {
        "non_root_user": seen.get("uid") == 65534,
        "no_capabilities": seen.get("capabilities_effective") == "0000000000000000",
        "no_new_privileges": seen.get("no_new_privs") == "1",
        "seccomp_filter": seen.get("seccomp") == "2",
        "read_only_root_filesystem": seen.get("root_writable") is False,
        "noexec_temporary_storage": seen.get("tmp_writable") is True
        and seen.get("tmp_executable") is False,
        "no_docker_socket": seen.get("docker_socket") is False,
        "no_host_mounts": bool(str(seen.get("mounts", "")).split())
        and not unexpected_mounts(str(seen.get("mounts", "")).split()),
        "no_network": seen.get("internet_reachable") is False,
        "no_host_environment": seen.get("sentinel_variables") == 0
        and environment <= RUNTIME_VARIABLES,
        "pid_limit": seen.get("pids_max") == str(policy.pids),
        "memory_limit": seen.get("memory_max") == str(policy.memory_bytes),
        "container_removed": run.removed,
    }
    return {"healthy": all(controls.values()), "controls": controls}

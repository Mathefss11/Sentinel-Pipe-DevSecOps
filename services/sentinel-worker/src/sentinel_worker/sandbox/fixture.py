# ruff: noqa: E501 - constant shell scripts are kept on readable single lines.
"""Deterministic FIXTURE modes, executed inside the sandbox (development and CI only).

Every mode is a constant BusyBox ``sh`` script from this module. Nothing is taken from
the repository, the job or the environment except the validated lease identifiers,
passed as separate positional arguments (UUIDs and integers) and never interpolated
into the script. The fixture reads no repository content: the sandbox has none to read.
It contacts no service, since there is no network.
"""

from __future__ import annotations

import re
from enum import StrEnum

from sentinel_worker.execution.leases import JobLease


class FixtureMode(StrEnum):
    SUCCESS = "success"
    NONZERO_EXIT = "nonzero_exit"
    TIMEOUT = "timeout"
    MEMORY = "memory"
    CPU = "cpu"
    PIDS = "pids"
    NETWORK = "network"
    CRASH = "crash"
    ISOLATION_PROBE = "isolation_probe"
    OVERSIZED_OUTPUT = "oversized_output"
    MALICIOUS_OUTPUT = "malicious_output"


# Positional parameters: $1 job id, $2 scan id, $3 attempt, $4 lease epoch, $5 seconds.
_EMIT = r"""
emit() {
  b64=$(printf '%s' "$1" | base64 | tr -d '\n')
  printf '{"artifacts":[{"content_base64":"%s","media_type":"application/json","name":"fixture-result.json"}],"schema_version":1}' "$b64"
}
"""

_SCRIPTS = {
    FixtureMode.SUCCESS: r"""
sleep "$5"
emit "$(printf '{"attempt":%s,"fixture":"harmless","job_id":"%s","lease_epoch":%s,"repository_content_read":false,"sandboxed":true,"scan_id":"%s"}' "$3" "$1" "$4" "$2")"
""",
    FixtureMode.NONZERO_EXIT: r"""
echo "fixture: simulated scanner failure" >&2
exit 3
""",
    FixtureMode.TIMEOUT: r"""
sleep 86400
""",
    FixtureMode.MEMORY: r"""
head -c 4000m /dev/zero | tail > /dev/null
exit 1
""",
    FixtureMode.CPU: r"""
while :; do :; done
""",
    FixtureMode.PIDS: r"""
while :; do (sleep 600 &) 2>/dev/null; done
""",
    FixtureMode.NETWORK: r"""
internet=false; wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null && internet=true
dns=false; nslookup example.com >/dev/null 2>&1 && dns=true
database=false; wget -q -T 2 -O /dev/null http://host.docker.internal:5432/ 2>/dev/null && database=true
emit "$(printf '{"database_reachable":%s,"dns_resolved":%s,"fixture":"harmless","internet_reachable":%s,"job_id":"%s"}' "$database" "$dns" "$internet" "$1")"
""",
    FixtureMode.CRASH: r"""
echo "fixture: simulated crash" >&2
kill -KILL $$
""",
    FixtureMode.ISOLATION_PROBE: r"""
uid=$(id -u)
capeff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
no_new_privs=$(sed -n 's/^NoNewPrivs:[[:space:]]*//p' /proc/self/status)
seccomp=$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status)
root_writable=false; touch /sentinel-probe 2>/dev/null && root_writable=true
tmp_writable=false; : > /tmp/probe 2>/dev/null && tmp_writable=true
tmp_executable=false; cp /bin/busybox /tmp/probe-exec 2>/dev/null && /tmp/probe-exec true 2>/dev/null && tmp_executable=true
docker_socket=false; { [ -e /var/run/docker.sock ] || [ -e /run/docker.sock ]; } && docker_socket=true
sentinel_env=$(env | grep -c '^SENTINEL_')
env_names=$(env | cut -d= -f1 | sort | tr '\n' ' ')
internet=false; wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null && internet=true
pids_max=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)
memory_max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)
emit "$(printf '{"capabilities_effective":"%s","docker_socket":%s,"environment":"%s","internet_reachable":%s,"memory_max":"%s","no_new_privs":"%s","pids_max":"%s","root_writable":%s,"seccomp":"%s","sentinel_variables":%s,"tmp_executable":%s,"tmp_writable":%s,"uid":%s}' "$capeff" "$docker_socket" "$env_names" "$internet" "$memory_max" "$no_new_privs" "$pids_max" "$root_writable" "$seccomp" "$sentinel_env" "$tmp_executable" "$tmp_writable" "$uid")"
""",
    FixtureMode.OVERSIZED_OUTPUT: r"""
head -c 4000000 /dev/zero | tr '\0' 'A'
""",
    FixtureMode.MALICIOUS_OUTPUT: r"""
printf '{"artifacts":[{"content_base64":"e30=","media_type":"application/json","name":"../../etc/passwd"}],"schema_version":1}'
""",
}

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def command(mode: FixtureMode, lease: JobLease, seconds: float) -> list[str]:
    """The argument vector for one fixture run. Arguments are validated, never quoted."""
    return script_command(
        mode, str(lease.job_id), str(lease.scan_id), lease.attempt, lease.epoch, seconds
    )


def script_command(
    mode: FixtureMode, job_id: str, scan_id: str, attempt: int, epoch: int, seconds: float
) -> list[str]:
    if not _UUID.match(job_id) or not _UUID.match(scan_id):
        raise ValueError("invalid lease identifiers")
    if not 0 <= seconds <= 600:
        raise ValueError("fixture duration must be between 0 and 600 seconds")
    return [
        "/bin/sh",
        "-c",
        _EMIT + _SCRIPTS[mode],
        "sentinel-fixture",
        job_id,
        scan_id,
        str(int(attempt)),
        str(int(epoch)),
        f"{seconds:g}",
    ]

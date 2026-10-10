# ADR-0009: Isolated, ephemeral sandbox execution

- **Status:** Proposed (pending owner review; security review of 2026-10-10 applied)
- **Date:** 2026-10-10
- **Milestone:** M3 Phase 1 (Slice 4)
- **Builds on:** [ADR-0007](0007-database-authoritative-execution-leases.md) (leases),
  [ADR-0008](0008-result-integrity-and-evidence.md) (verified evidence)
- **Threat model:** [execution sandbox](../threat-model/execution-sandbox.md)

## Context

Scanners will process untrusted repository content. A scanner, its plugins or the
content it parses may be hostile. The worker holds credentials, while scanners must not:
- the worker's database login, which can claim jobs and submit results;
- the lease token;
- broker credentials and the host.

Real scanners are out of scope for this slice. The harmless FIXTURE must, however,
exercise the same isolation, limits and lifecycle that real scanners will use.

## Decision

1. **Trust split.**
   - The worker process is trusted orchestration. It holds the lease, the credentials and
     the Docker CLI, and talks to PostgreSQL.
   - Each job attempt runs in a **fresh, single-use container** that is untrusted. The
     container gets no credentials, no token, no network and no host files.
   - Results leave the sandbox only as data on stdout, and the worker validates them
     before anything reaches the control plane (ADR-0008).

2. **Hardened, immutable configuration** (`sentinel_worker/sandbox/policy.py`). The
   runtime arguments are built in code from a frozen policy, a digest-pinned image
   allowlist and an allowlisted command (`/bin/sh` from the pinned image). Argument
   vectors are passed without any host shell:

   | Control | Setting |
   |---|---|
   | Network | `--network none` (loopback only); no DNS; `--ipc none`; fresh hostname |
   | Filesystem | `--read-only` root; `/tmp` tmpfs `rw,noexec,nosuid,nodev`, 32 MiB; no volumes, bind mounts or devices; `--workdir /tmp` |
   | Identity | `--user 65534:65534` (nobody), `--cap-drop ALL`, `--security-opt no-new-privileges`, the runtime's default seccomp profile |
   | Processes | `--init` reaps children; `--pids-limit` (64 by default) |
   | Memory | `--memory` with `--memory-swap` equal (no swap); 256 MiB by default |
   | CPU | `--cpus` (1.0 by default) |
   | Files | `--ulimit nofile=256`, `--ulimit core=0` |
   | Time | Wall-clock limit (300 s by default), capped by the scan's hard deadline minus 5 s |
   | Output | stdout at most 2 MiB, stderr at most 64 KiB; excess is drained and discarded; overflow kills the sandbox |
   | Supply chain | `--pull never`; images are pinned by digest and provisioned in advance |
   | Logs | `--log-driver none` (output is read only through the bounded pipe) |
   | Secrets | The container receives no host environment. The Docker CLI process is started without `SENTINEL_*` variables. No Docker socket and no registry credentials inside |

3. **Lifecycle.** `DockerSandbox.run` covers the whole lifecycle:
   - **Start:** create and start the container.
   - **Read output:** bounded readers consume stdout and stderr.
   - **Monitor:** sample `docker stats` for peak PIDs and memory.
   - **Stop on any of:** the timeout, an output overflow, or the stop event. The stop event
     is set by the lease keeper on cancellation, lease loss or a passed deadline, and by
     worker shutdown.
   - **Kill:** `docker kill --signal KILL` ends the whole process tree in the PID namespace.
   - **Inspect:** read the exit code and the OOM flag.
   - **Remove:** `docker rm --force` in a `finally` block.
   - **Crash recovery:** every container carries an expiry label (timeout plus 60 s). A
     worker removes expired sandboxes at startup and at least every 60 s afterwards, which
     covers containers left behind when a worker process crashes.

   A stale worker cannot get a result accepted, for two reasons: its sandbox is killed when
   its lease is lost, and the database fences its epoch anyway (ADR-0007).

   Further lifecycle rules:
   - **Ownership:** a sandbox belongs to the worker that started it until its expiry
     label passes. Its owner always ends it before then (the time limit is shorter than
     the expiry), so another worker never removes a live sandbox.
   - **Reaper scope:** the reaper considers only containers with the sandbox label and
     the exact `sentinel-sandbox-<32 hex>` name pattern. A sandbox without a valid
     expiry label is removed only once it has stopped.
   - **Lost runtime:** if the runtime CLI ends while the container is still running, for
     example when the CLI is killed or the daemon connection drops, the outcome is unknown.
     It fails closed as `SANDBOX_ERROR`, and the container is removed.
   - **Already cancelled:** a job whose stop event is already set never starts a
     sandbox.

4. **Output channel instead of shared files.**
   - The sandbox writes one `sandbox-output.v1` JSON document to stdout
     (`packages/contracts/messages/v1`), with artifacts embedded as base64 under
     identifier names.
   - The worker never opens a path chosen by the sandbox, so path traversal, symlink
     escapes and access to another job's files are impossible by construction. There is
     no shared or host storage to escape into.
   - Parsing is strict:
     - duplicate keys, non-standard constants and unknown fields are rejected;
     - base64 is decoded strictly;
     - names, media types, sizes and counts are re-checked.
   - A violation is reported as `SCANNER_ERROR`; only a sanitized code is logged.

5. **Outcome mapping onto the existing job-result.v1 reasons** (no schema change):

   | Sandbox outcome | Result |
   |---|---|
   | exit 0, valid output | COMPLETED with artifacts |
   | exit 0 with invalid output, or exit 1–127 | FAILED `SCANNER_ERROR` (retried) |
   | exit ≥ 128 (killed unexpectedly), runtime failure | FAILED `SANDBOX_ERROR` (retried) |
   | wall-clock limit | FAILED `EXECUTION_TIMEOUT` (final) |
   | memory (OOM), PID limit reached, output limit | FAILED `RESOURCE_LIMIT_EXCEEDED` (final) |
   | cancellation, lease loss | not reported (the lease is gone); `WORKER_SHUTDOWN` on shutdown |

6. **Deterministic fixture modes** (development and CI only):
   - `success`
   - `nonzero_exit`, `timeout`, `memory`, `cpu`, `pids`, `crash`
   - `network`
   - `isolation_probe`
   - `oversized_output`, `malicious_output`

   Each mode is a constant BusyBox script from code. Lease identifiers are passed as
   validated positional arguments and never interpolated. The fixture stays disabled by
   default and refused in production on both the API and the worker.

7. **Verification on the real host.** `sentinel-worker sandbox-check` runs the isolation
   probe in a real sandbox and verifies 12 controls from the inside:
   - non-root user, no capabilities, no-new-privileges, a seccomp filter;
   - read-only root, noexec `/tmp`;
   - no Docker socket, no network, no host environment;
   - the PID and memory limits;
   - removal of the container.

   CI runs it, and the sandbox test suite, in a dedicated job.

## Enforced controls and what they depend on

| Property | Enforced by | Depends on |
|---|---|---|
| No credentials, token or host environment in the sandbox | Worker code (arguments, CLI environment) | — |
| No path traversal, symlink escape or cross-job file access | Protocol design (data, not paths) | — |
| Bounded output, bounded time, prompt cancellation, removal | Worker code | A responsive container runtime (removal of orphans after a crash relies on the next worker) |
| Read-only root, noexec tmpfs, user 65534, no capabilities, no-new-privileges, seccomp, PID, memory and CPU limits, no network | Container runtime | Linux kernel namespaces, cgroups v2, seccomp. Docker Desktop provides them inside its Linux VM |
| Containment of a kernel exploit or container escape | **Not provided by runc** | A stronger boundary: gVisor (`runsc`), Kata Containers or a microVM. The `--runtime` option is allowlisted for this |

## Trust policy

These rules are binding for every execution path:

1. **Local Docker/runc execution is allowed only for controlled fixtures and explicitly
   trusted scanner implementations.** Trusted means a reviewed scanner, a digest-pinned
   image, and an allowlisted command whose arguments are built in code.
2. **Arbitrary untrusted repository code must not execute under the default Docker/runc
   boundary.** This covers builds, test suites, package lifecycle scripts, and code a
   scanner would evaluate.
3. **Stronger isolation is required before untrusted code is enabled.** That means
   disposable VMs per job, or a gVisor/Kata deployment that has been validated. Validated
   means:
   - `sentinel-worker sandbox-check` passes under that runtime on the target hosts;
   - the hosts are dedicated to workers;
   - the deployment was reviewed and approved by the owner.
4. **Repository content is always untrusted input, even when the scanner is trusted.** A
   trusted scanner parsing hostile files can be exploited. The sandbox controls therefore
   apply to every scanner run, and no scanner output is trusted
   (`sandbox-output.v1`, ADR-0008).

Enforcement in code: every `SandboxPolicy` declares a `Workload`.
- `TRUSTED_TOOL` (the default; fixtures and trusted scanners) may use runc.
- `UNTRUSTED_CODE` is refused unless the runtime is one of `runsc`, `kata-runtime` or
  `kata`, so rule 2 cannot be bypassed by configuration.

No code path creates an `UNTRUSTED_CODE` policy yet. Rule 3's validation and approval
remain operational requirements that code cannot check.

## Trust model and limits

- **runc containers share the host kernel.** They are a resource and namespace boundary,
  not a security boundary against hostile code that exploits the kernel or the runtime.
  This is acceptable now because **no untrusted repository content is executed or even
  fetched yet**: the FIXTURE runs constant scripts.
- **Before untrusted repository code or scanners process attacker-controlled content in
  production,** at least one of the following is required, and is an open decision for the
  owner:
  - a stronger runtime (`SENTINEL_WORKER_SANDBOX_RUNTIME=runsc`, gVisor, or Kata), or
  - a disposable VM per job (GitHub-hosted ephemeral runners, as CLAUDE.md's hybrid
    model intends; or microVMs);

  in both cases on worker hosts that hold no other secrets than the worker's own
  scoped credentials.
- **The worker controls the Docker daemon**, which is root-equivalent on its host. Worker
  hosts are therefore part of the trusted computing base and must be dedicated.
  Rootless Docker or Podman reduces the impact of a daemon compromise. The daemon must be
  local: a remote daemon over plain TCP is not supported, and expiry labels assume one host
  clock. A large forward step of the wall clock can make another worker reap a live sandbox
  early; the owner then sees `LOST` or `START_FAILED`, which is a retryable failure, never
  an accepted result.
- **Classification of PID exhaustion is best-effort.** The kernel always enforces the
  limit. Reporting the cause as `RESOURCE_LIMIT_EXCEEDED` relies on sampled `docker stats`
  (about 1 s apart); a missed sample results in `SCANNER_ERROR` or a timeout, which also
  fails closed.
- **Disk.** The root filesystem is read-only and the only writable path is a
  size-limited tmpfs, so a sandbox cannot fill the host disk. Image layers are shared and
  read-only.

## Which tests exercise the real runtime

| Tests | Runtime |
|---|---|
| `tests/sandbox/test_sandbox_isolation.py`, `tests/integration/test_sandboxed_execution.py` (marker `sandbox`), `sentinel-worker sandbox-check`, `ScanExecutionE2ETests` | **Real Docker containers**: every isolation property is observed from inside a running sandbox |
| `tests/test_sandbox.py` | No containers: argument construction, the trust policy, parsing, classification, reaper ownership against a scripted CLI listing, settings |

CI runs the real-runtime tests in the `sandbox` and `e2e` jobs. `SENTINEL_REQUIRE_SANDBOX=1`
turns a missing runtime or image into a failure rather than a skip.

## Platform differences

| | Linux CI (GitHub-hosted, Docker Engine) | Docker Desktop on Windows (development) | Production (assumed) |
|---|---|---|---|
| Kernel | Runner's Linux kernel, cgroups v2 | LinuxKit VM kernel (WSL2), cgroups v2 | Dedicated Linux hosts; gVisor or Kata, or ephemeral VMs |
| Sandbox ↔ host | Shares the runner's kernel; the runner VM is ephemeral | Shares the VM's kernel; the Windows host is behind the VM | Must not share a kernel with credentials beyond the worker's |
| `host.docker.internal` | Absent | Resolves normally, but unreachable under `--network none` (verified) | Absent |
| Docker CLI | `/usr/bin/docker` | `docker.exe` resolved from `PATH` (per-user installs: `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin`). Windows argument quoting was verified with the fixture scripts and the reaper's quoted Go template (Python's quoting). Java's `ProcessBuilder` mangles embedded quotes, so the Java tests read labels as JSON instead | Absolute path configured with `SENTINEL_WORKER_DOCKER_CLI` |
| Killing the worker | Child `docker` CLI may survive; the container survives until reaped | Same | Same; the reaper and lease expiry recover |

## Consequences

- Every future scanner adapter runs through this layer and must emit `sandbox-output.v1`.
  Large outputs (SBOMs, SARIF) will need larger limits and, eventually, the object-storage
  evidence backend (ADR-0008).
- Running workers requires Docker access on the worker host and the pinned image to be
  provisioned in advance (`docker pull <digest>`). `sentinel-worker execute` refuses to
  start otherwise.
- The in-process FIXTURE remains (`SENTINEL_WORKER_FIXTURE_EXECUTOR=inline`) for
  environments without Docker; only the `success` mode is available there.

## Alternatives considered

- **Bind-mounted output directory.** Rejected: it needs host paths, ownership changes or
  world-writable directories, and careful symlink and traversal handling, and it cannot
  bound disk usage. The stdout envelope removes the whole class of problems at small sizes.
- **`docker run --rm`.** Rejected: the exit state (OOM) must be inspected before removal.
  Removal is explicit in a `finally` block instead.
- **A Docker SDK library.** Not needed: the CLI with argument vectors is auditable, adds
  no dependency, and behaves the same on Linux and Docker Desktop.
- **Running scanners directly in the worker process.** Rejected: the worker holds
  credentials (CLAUDE.md: no untrusted code in the control plane, nor in the worker).

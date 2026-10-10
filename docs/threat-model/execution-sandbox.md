# Threat model: scan execution plane

Scope: worker processes, sandbox containers and their interfaces to PostgreSQL. This
covers Flyway V007/V008, ADR-0007, ADR-0008 and ADR-0009. Method: STRIDE per trust
boundary. Status: M3 Phase 1, Slice 4. Only the harmless FIXTURE executes; no repository
content is fetched yet.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Worker database login | Worker process environment | Can claim jobs, upload evidence and submit results for any tenant's jobs it leases |
| Lease tokens | Worker memory only (hash in the database) | Authorize heartbeats, evidence and results for one job attempt |
| Evidence and results | `evidence.*`, `lifecycle.job_reports` | Basis of future security decisions (M4) |
| Docker daemon access | Worker host | Root-equivalent on that host |
| Repository content (future) | Sandbox only | Customer source code and secrets |

## Trust boundaries

```text
[control plane: API + PostgreSQL]  ← fenced functions, own login →  [worker process (trusted)]
                                                                         │ docker CLI (argv, no shell, no SENTINEL_* env)
                                                                         ▼
                                                     [sandbox container (UNTRUSTED), single use]
                                                       stdout envelope → worker → database
```

## Threats and controls

| # | STRIDE | Threat | Controls | Verified by | Residual risk |
|---|---|---|---|---|---|
| T1 | Information disclosure | Sandbox reads worker credentials or the lease token | No environment passed; CLI started without `SENTINEL_*`; no mounts | Isolation probe (`no_host_environment`); unit test of the CLI environment | None known at the container level |
| T2 | Elevation of privilege | Sandbox controls the Docker daemon | No socket or mounts; the argument builder refuses volume, mount and device options | Probe (`no_docker_socket`); argument tests | — |
| T3 | Elevation of privilege | Container escape through a kernel or runtime vulnerability | Non-root, no capabilities, no-new-privileges, seccomp, read-only root, no network | Probe | **High with runc against hostile code.** Requires gVisor, Kata or a VM before untrusted code runs (ADR-0009) |
| T4 | Information disclosure, tampering | Network exfiltration, or attacks on PostgreSQL or the broker | `--network none` | `network` mode and probe (internet, DNS and database all unreachable) | — |
| T5 | Denial of service | Fork bomb, memory or CPU exhaustion, disk fill, output flood | PID, memory (no swap) and CPU limits; tmpfs size; read-only root; bounded output with kill; time limit | `pids`, `memory`, `cpu`, `oversized_output` modes; worker-responsiveness test | Several concurrent sandboxes on one host still compete; size hosts and worker concurrency together |
| T6 | Tampering | Path traversal, symlink escape, or reading another job's artifacts | Data-only output channel; names are identifiers; no shared storage; one container per attempt | `malicious_output` mode; protocol tests | — |
| T7 | Tampering, spoofing | Malformed or forged result or evidence | Strict parsing; database-computed digests; lease-bound, tenant-scoped evidence (ADR-0008) | Protocol and result-integrity tests | A lease holder can still submit false evidence for its own job (attestation is M6) |
| T8 | Repudiation | Disputed results | Append-only execution events; deduplicated rejection records; worker login recorded | Audit tests | — |
| T9 | Spoofing | A stale or cancelled worker reports late | Lease keeper stops the sandbox; database epoch fencing | Cancellation and lease-loss tests with real sandboxes | — |
| T10 | Denial of service | Orphaned sandboxes after a worker crash | Expiry labels; reaping at startup and periodically | Crash test (killed worker process) | Orphans live until expiry (timeout plus 60 s) if no worker restarts on that host |
| T11 | Injection | Shell or option injection through job data | Argument vectors only; constant scripts; validated UUID and integer arguments; name and label validation; command and image allowlists | Unit tests | — |
| T12 | Information disclosure | Secrets in logs | Sanitized, length-limited stderr excerpts with token-like runs redacted; evidence never logged; codes only | Log tests | Excerpts are heuristically redacted, not guaranteed secret-free; they are not logged by default (only sizes are) |
| T13 | Tampering (supply chain) | Image replaced or pulled at run time | Digest-pinned allowlist; `--pull never`; pre-provisioned image | Policy tests; CI pre-pull | Trust in the upstream image digest; signature verification is M6 |

## Trust policy

The binding policy is in ADR-0009 ("Trust policy"):
- runc only for controlled fixtures and explicitly trusted scanners;
- never for arbitrary untrusted repository code (enforced by `Workload.UNTRUSTED_CODE`);
- disposable VMs or validated gVisor/Kata deployments before untrusted code is enabled;
- repository content always treated as untrusted input.

| # | STRIDE | Threat | Controls | Verified by | Residual risk |
|---|---|---|---|---|---|
| T14 | Denial of service, tampering | One worker removes another worker's live sandbox | Expiry ownership; exact name pattern; containers without a valid expiry are reaped only once stopped | Real-runtime ownership test; scripted reaper test | Large wall-clock jumps can expire a live sandbox early; the result is a retryable failure |
| T15 | Spoofing | A lost runtime CLI makes a still-running sandbox look finished | `LOST` status, mapped to `SANDBOX_ERROR`; the container is removed | Classification test | — |

## Before running untrusted repository content

This is required by ADR-0009 and is an open decision:
1. A stronger isolation runtime or a disposable VM per job.
2. Dedicated worker hosts with no other credentials.
3. A repository fetch path that runs inside the sandbox or VM with scoped, short-lived
   credentials, never the worker's.
4. Per-scanner network allowlists if a scanner needs its vulnerability database. The
   default stays no network.

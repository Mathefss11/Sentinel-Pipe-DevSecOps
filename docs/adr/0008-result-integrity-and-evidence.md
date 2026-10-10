# ADR-0008: Result integrity, evidence storage and execution observability

- **Status:** Proposed (pending owner review)
- **Date:** 2026-10-10
- **Milestone:** M3 Phase 1 (Slice 3)
- **Amends:** [ADR-0007](0007-database-authoritative-execution-leases.md) (`report_job` is
  replaced by `submit_result`)

## Context

After Slice 2, a worker reported only an outcome code. Later slices will report scanner
output (findings, SBOMs, SARIF). The control plane must:

- tie every result to the exact job, lease, tenant and commit;
- verify evidence bytes instead of trusting digests that workers supply;
- prevent one tenant's evidence from being referenced by another tenant's result;
- stay idempotent under retries;
- keep the audit trail bounded under repeated refused submissions;
- expose execution health without leaking tokens, credentials or evidence.

No cloud services or object-store credentials may be introduced yet.

## Decision

1. **Versioned result contract.** Workers submit one `job-result.v1` document
   (`packages/contracts/messages/v1/job-result.v1.schema.json`, JSON Schema 2020-12):
   - **Fields:** `schema_version`, job, scan, project and organization ids, commit,
     scanner type, attempt, lease epoch, outcome, failure reason, worker timestamps and
     artifact references.
   - **Artifact references:** a name, media type, size and SHA-256.
   - **Limits:** 16 KiB per document; at most 16 artifacts; 1 MiB per artifact; 8 MiB per
     lease.
   - **Canonical serialization:** UTF-8/ASCII, keys sorted by code point, no whitespace,
     no duplicate keys, integers only, artifacts sorted by name.
   - **Result identity:** the SHA-256 of the exact bytes. Identical bytes are DUPLICATE;
     different bytes for the same lease are CONFLICT.
   - **Versions:** a well-formed document with any other `schema_version` is answered
     `REJECTED_UNSUPPORTED_SCHEMA_VERSION`. Malformed documents raise SQLSTATE 22023
     without echoing their content.

2. **Validation in the database, in one transaction** (`worker.submit_result`, Flyway V008).
   The function:
   - validates the document strictly, including duplicate keys, the exact key set, types,
     patterns, enumerations, sorted and unique artifact names, and time order;
   - authenticates the lease (login, token hash, epoch, RUNNING, not expired, deadline);
   - checks every claimed identifier, the commit, the scanner type and the attempt against
     the authoritative rows;
   - checks every artifact reference against an upload bound to the **same job and lease
     epoch**, with exactly the digest, size and media type the database recorded.

   Only then does it record the report, bind the evidence of record and apply the
   transition. Either everything commits, or nothing does.

3. **Database-verified evidence.** `worker.put_evidence` receives the bytes under a valid
   lease and returns the digest and size, both computed by **PostgreSQL**:
   - **Content-addressed per tenant:** objects are keyed by
     `(organization_id, sha256)`. A digest therefore never resolves across tenants, and
     identical bytes from two tenants are two objects.
   - **Bound to the lease:** uploads are keyed by `(job, lease epoch, name)`. Names are
     restricted identifiers (`^[a-z0-9][a-z0-9._-]{0,63}$`, no `..`), never paths, URLs or
     SQL identifiers.
   - **Immutable:** a CHECK constraint recomputes the digest of the stored bytes, so no
     role, not even a superuser using plain SQL, can store content that does not match its
     address. No runtime role can write the evidence tables directly.
   - **Re-verified on read:** the API reads evidence only through `SECURITY DEFINER`
     functions and verifies the bytes again in Java (`EvidenceVerifier`) before use.
   - **On the worker:** it also compares the database's digest with its own and never
     references evidence whose digests differ.

4. **Storage abstraction and retention.**
   - Java `EvidenceStore` (`DatabaseEvidenceStore`) and Python `EvidenceStore`
     (`DatabaseEvidenceStore`) are interfaces over content-addressed, tenant-scoped
     references. An S3-compatible backend can implement them later.
   - That backend must keep the guarantee that **the control plane** establishes the
     digest of the stored bytes: it must not trust a digest from the uploader, and it should
     use pre-signed, scoped and short-lived upload rights, with a verifying step before
     acceptance.
   - PostgreSQL storage is intended for development, CI and small artifacts.
   - Retention: each scan records `evidence_retention_days` (default 90, from
     `sentinel.execution.evidence-retention`). The supervisor purges content past its
     retention in bounded batches. Digests, sizes, bindings and accepted results are kept;
     a purged artifact reports `purged` and cannot be read.

5. **Bounded rejection audit.**
   - Refused results and uploads are counted in `lifecycle.report_rejections` per (job,
     epoch bucket, worker login, operation, reason). Claimed epochs above the current one
     share one bucket, so the number of keys per job is bounded.
   - The first occurrence also writes an `execution_events` row (`REPORT_REJECTED`,
     `REPORT_CONFLICT` or `EVIDENCE_REJECTED`). Repeats only increment the counter and its
     last-seen time.
   - Essential evidence is kept: who, which job and epoch, why, how often, first and last
     time.

6. **Observability.**
   - **API gauges** come from database summaries, so every instance reports the same
     values:
     - jobs by state, including retries pending;
     - scans waiting for evaluation;
     - the age of the oldest running attempt;
     - refused operations by sanitized reason, from a closed set (anything else is
       `OTHER`).

     Plus the existing counters for lease expiries, deadlines, evaluations and purged
     evidence.
   - **Worker** (`sentinel-worker execute`):
     - counters for claims, heartbeats, result answers, final run outcomes and evidence
       uploads;
     - an execution-duration histogram per scanner type.
   - All labels are validated against closed sets. Identifiers, tokens, credentials and
     evidence never become labels or log fields.

## Guarantees and their limits

| Implemented now | Not implemented (future) |
|---|---|
| The digest of every referenced artifact was computed by the control-plane database from the bytes it stores | Proof that the bytes were produced by an honest scanner run (attestation, M6) |
| A result can reference only evidence uploaded under the same lease, job and tenant | Signed provenance of the worker and its image (Sigstore/SLSA, M6) |
| Stored evidence cannot be altered without detection (database CHECK; re-verified on read) | Tamper evidence against a database administrator who drops constraints; independent, append-only storage |
| Results are bound to the authoritative job, scan, project, organization and commit | Verification that the scanned bytes were that commit (requires the sandbox and repository fetch, Slice 4/M5) |
| Duplicate results are idempotent; conflicting results are refused and audited | Exactly-once delivery: delivery is at-least-once |

A worker that holds a valid lease can still upload false evidence for its own job. The
design limits the damage to that job, ensures the false evidence is recorded and
attributable, and prevents it from affecting other jobs or tenants.

## Consequences

- Every scanner adapter (M3 Phase 2) produces evidence through this path. Large artifacts
  need the S3-compatible backend before real scanners run at scale.
- `worker.report_job` was dropped. Workers built for Slice 2 must be updated together with
  the migration (pre-release; no compatibility shim).
- The API still exposes no evidence endpoint. Evidence is reachable only through the
  internal `EvidenceStore`. A future endpoint must authorize the job's organization
  first.

## Alternatives considered

- **Trust worker-supplied digests and verify later.** Rejected: a digest is not proof.
- **Object storage now (MinIO in Compose).** Deferred: it adds a service and credentials,
  and it still needs control-plane verification. The interfaces keep the option open.
- **Global content addressing (sha256 only).** Rejected: a reference could then resolve to
  another tenant's object.
- **Unbounded rejection events.** Rejected: an authenticated worker could grow the audit
  table without limit.

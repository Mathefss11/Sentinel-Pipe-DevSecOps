# ADR-0005: Shared worker receipts, database-verified messages and least-privilege runtime identities

- **Status:** Proposed (pending owner review)
- **Date:** 2026-10-10
- **Milestone:** M2 Phase 2C
- **Amends:** the SQLite receipt store and the shared broker administrator described in
  [ADR-0004](0004-transactional-outbox-and-at-least-once-messaging.md) (the outbox design
  itself is unchanged)

## Context

After Phase 2B, delivery was at-least-once with a durable outbox, publisher confirms and
per-worker deduplication. Three gaps blocked running more than one worker and, later,
executing scanners:

1. **Per-host deduplication.** Receipts lived in a local SQLite file. A redelivery or
   republication routed to another worker host was accepted a second time, and tamper
   detection only worked on the host that held the original receipt.
2. **Trusted payloads.** The worker accepted any schema-valid message. Anyone with write
   access to `sentinel.scan-requests` could forge a scan request for any organization,
   because the payload's `organization_id` was taken at face value.
3. **Over-privileged runtime identities.** The API published with the broker
   administrator, and no database identity existed for the worker.

Idempotency keys also never expired, and recovery depended on hand-written SQL.

## Decision

### Shared, verified receipts in PostgreSQL

- Receipts move to the control-plane PostgreSQL database (Flyway `V005`, schema `worker`).
  `worker.processing_receipts.event_id` is the primary key, so acceptance is decided by
  one atomic `INSERT … ON CONFLICT DO NOTHING` shared by every worker.
- The worker's database role (`sentinel_worker`, NOLOGIN group; login roles are members)
  has **no table privileges**. It may only `EXECUTE worker.record_receipt(jsonb)`, a
  `SECURITY DEFINER` function with a fixed `search_path` that, in one transaction:
  1. returns `DUPLICATE` or `CONFLICT` if a receipt for the `event_id` exists (same or
     different message digest);
  2. otherwise looks up the `scan.requested` outbox event with that id, joined to the
     authoritative scan and project rows, and requires
     `sha256(outbox_events.payload::text)` to equal the delivered message's SHA-256. The
     publisher sends exactly that text, so any modification of the message fails;
  3. requires the claimed scan, project, organization and commit to equal the
     authoritative rows (defense in depth against an inconsistent payload);
  4. inserts the receipt with identifiers **copied from the authoritative rows**.
- Rejections (`REJECTED_UNKNOWN_EVENT`, `REJECTED_DIGEST_MISMATCH`,
  `REJECTED_RELATIONSHIP_MISMATCH`, `CONFLICT`) are dead-lettered by the worker and
  recorded in `worker.delivery_rejections`, deduplicated by digest and reason. Rejected
  deliveries never occupy an `event_id`, so a forged message delivered first cannot
  block the genuine event.
- The worker commits the receipt transaction before `basic.ack`. Any database error,
  including an ambiguous commit, is transient: the message goes through the bounded
  retry queue (5 × 15 s) and is then dead-lettered (`TRANSIENT_RETRIES_EXHAUSTED`). While
  the store is failing, the consumer backs off between messages (1 s doubling to 10 s).
  Connections use connect, statement, lock and idle-in-transaction timeouts.
- SQLite remains only as an explicit development backend
  (`SENTINEL_WORKER_RECEIPT_BACKEND=sqlite`), refused outside the `development`
  environment.

A receipt still means **accepted for processing**, never "scanned".

### Least-privilege runtime identities

| Identity | RabbitMQ (configure / write / read) | PostgreSQL |
|---|---|---|
| API publisher `sentinel-publisher` | none / `sentinel.scan-requests` / none | schema owner (unchanged; see limitations) |
| Worker `sentinel-worker` | none / dlx, retry exchanges / work queue | `sentinel_worker`: EXECUTE `worker.record_receipt` |
| Operator `sentinel-operator` | none / `sentinel.scan-requests` / dead-letter queue | `sentinel_operator`: EXECUTE `ops.*` |
| Broker administrator | provisioning only | — |

Topology is provisioned out of band: `infrastructure/docker/rabbitmq/definitions.json`
(generated from `packages/contracts/messaging/topology.v1.json`, no users or secrets) is
imported by `provision.sh`, which also creates the users. The API defaults to
`sentinel.messaging.declare-topology=false`. The definitions add a policy giving the
dead-letter queue `delivery-limit: -1`: RabbitMQ 4 quorum queues default to 20
deliveries, and the dead-letter queue has no dead-letter exchange, so without the policy
a message returned 20 times would be **dropped**.

### Idempotency-key lifecycle

Keys replay for `sentinel.idempotency.retention` (default 24 h, bounds 1 h–30 d) after the
scan was requested. A key is expired when `requested_at <= now − retention`. Expired keys
never replay; reusing one creates a new scan, even with a different payload. The request
first releases the expired key from the old scan with a row-locking `UPDATE`, then
inserts, in one transaction. A periodic cleanup (bounded batches,
`FOR UPDATE SKIP LOCKED`) clears expired keys. Only `idempotency_key` and
`request_fingerprint` are cleared; scans, outbox events and receipts are never deleted.

### Recovery and observability

- Operator actions are bounded (at most 100 items), audited **before** they take effect
  in `ops.recovery_actions`, and exposed only as CLI commands with operator credentials
  (`sentinel-worker outbox-summary | outbox-list-failed | outbox-requeue-failed |
  dlq-depth | dlq-replay`). There are no recovery HTTP endpoints.
- Low-cardinality metrics on both sides; the Prometheus endpoints are off by default and,
  when enabled, bound to loopback only. See
  [observability runbook](../runbooks/observability.md).

## Consequences

- Deduplication and tamper detection hold across any number of worker hosts, and broker
  write access alone can no longer inject or alter an accepted scan request. Messages are
  authenticated against the database, not signed. A party able to write both the outbox
  and the broker is outside this model.
- Workers now depend on PostgreSQL availability; an outage delays acceptance (bounded
  retries, then the dead-letter queue and an audited replay).
- The digest check binds the message to `payload::text` as rendered by PostgreSQL's
  `jsonb` output. Messages in flight across a major-version upgrade that changed that
  rendering would be rejected (fail closed, recoverable by replay after republication).
- Delivery remains **at-least-once**. Exactly-once *acceptance* per `event_id` is
  guaranteed by the primary key; exactly-once *delivery* is not.
- RabbitMQ authorizes `queue.purge` with the read permission, and even passive
  declarations need some permission on the object. The worker can therefore purge the
  work queue, the operator can purge the dead-letter queue, and the publisher cannot
  observe queue depths (those come from the broker's own metrics).
- Dead-letter replay is audited by the operator tool. The broker cannot require an audit
  row, so the operator's broker credentials alone could republish or discard dead letters
  unaudited. Worker verification still applies to every replayed message.
- The API keeps connecting as the schema owner, and the definer functions run as the
  migration owner. **Before real scanner execution (M3)**, the API needs a separate
  runtime role and the schema a dedicated non-superuser owner.

## Alternatives considered

- **Separate receipt database.** Rejected: the worker could not verify events against
  authoritative scans and organizations.
- **Table grants to the worker.** Rejected: SELECT on `scans` and `outbox_events` would
  expose every tenant's data to every worker. A single verifying function is a narrower
  interface.
- **Message signatures.** Deferred: they need key management and rotation. Database
  verification gives the same authenticity property for this phase.
- **Admin recovery HTTP API.** Rejected for now: it would widen the platform-administrator
  role and add an internet-facing surface. Audited CLI and database functions suffice.

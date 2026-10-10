# Asynchronous messaging: control plane → execution plane

Status: M2 Phase 2C. Decision records: [ADR-0004](../adr/0004-transactional-outbox-and-at-least-once-messaging.md)
(outbox, at-least-once), [ADR-0005](../adr/0005-shared-receipts-tenant-verification-and-least-privilege.md)
(shared verified receipts, least privilege). Operations: [messaging runbook](../runbooks/messaging.md),
[observability runbook](../runbooks/observability.md).

## Message flow

```text
 Client (OIDC access token)
   │  POST /api/v1/projects/{id}/scans      authenticated + MEMBER role (ADR-0003)
   ▼
 sentinel-api ── one PostgreSQL transaction ──────────────────────────────┐
   │   INSERT scans (QUEUED / PENDING)                                     │
   │   INSERT outbox_events (scan.requested v1, PENDING)                   │
   └───────────────────────────────────────────────────────────── COMMIT ─┘
   │
 OutboxPublisher (scheduled, any number of instances; broker user sentinel-publisher)
   │  claim: FOR UPDATE SKIP LOCKED + lease          (database clock)
   │  publish payload::text: persistent, mandatory, publisher confirm
   │  ack & not returned ──► PUBLISHED      otherwise ──► retry with backoff / FAILED
   ▼
 RabbitMQ  sentinel.scan-requests ──scan.requested.v1──► sentinel.scan-requests.worker (quorum)
   │
 sentinel-worker × N (own broker user and DB role, prefetch-bounded, manual acks)
   │  validate size, encoding, JSON, schema, AMQP properties
   │  SELECT worker.record_receipt(receipt)          (PostgreSQL, SECURITY DEFINER, one txn)
   │     receipt exists?  same digest ─► DUPLICATE   different ─► CONFLICT
   │     outbox event + scan + project: sha256(payload::text) = message digest?
   │        and scan / project / organization / commit match?   no ─► REJECTED_*
   │     INSERT receipt (authoritative identifiers), event_id PRIMARY KEY ─► NEW
   │  ├─ invalid / CONFLICT / REJECTED_* ──► sentinel.scan-requests.dlx ──► dead-letter queue
   │  ├─ database unavailable ─────────────► sentinel.scan-requests.retry (TTL 15 s) ──► work queue
   │  └─ NEW or DUPLICATE committed ───────► basic.ack
   ▼
 (later phases: planning, isolated scanner execution, evidence upload)
```

## Trust boundaries

| Boundary | Control |
|---|---|
| Client → API | OIDC JWT validation, server-side organization membership (ADR-0003). Only an authorized MEMBER+ can cause a `scan.requested` event. |
| API → outbox | Same transaction as the scan. The event's organization, project and repository are copied from committed server-side rows, never from request fields. No token, user identity or credential is included. |
| API → broker | Least-privileged publisher identity: write `sentinel.scan-requests` only; no configure (cannot alter topology) and no read. Topology is provisioned by an administrator from `definitions.json`. |
| Broker → worker | The worker treats messages as **untrusted input**: bounded size, strict JSON (no duplicate keys or NaN), schema validation with ECMA-262 anchors, property consistency checks. A message is never an authorization credential. |
| Worker → broker | Least privilege: read the work queue; write only to the retry and dead-letter exchanges; no configure. It cannot inject scan requests or read dead letters. |
| Worker → database | Role `sentinel_worker`: EXECUTE `worker.record_receipt` (and, since V007, the execution protocol functions of [ADR-0007](../adr/0007-database-authoritative-execution-leases.md)) only, with no table privileges. It cannot read scans, organizations or outbox payloads, cannot modify control-plane rows, and cannot read or alter receipts directly. |
| Worker state | Receipts are shared by all workers and keyed by `event_id`. A message is accepted only if it is byte-identical to the committed outbox payload and its scan, project, organization and commit match the authoritative rows. Receipt identifiers are copied from those rows, so payload tenant identifiers are never trusted. Forged and altered messages are dead-lettered and recorded in `worker.delivery_rejections`; they cannot occupy a genuine `event_id`. |
| Operator → system | Separate broker user and database role (`sentinel_operator`). Recovery is bounded and audited before it takes effect (`ops.recovery_actions`). There are no recovery HTTP endpoints. |

**Remaining worker identity requirements** (before workers act on behalf of tenants):
per-worker credentials or mTLS client certificates with rotation; scoped, short-lived
upload credentials for scan evidence (GitHub Actions OIDC, M5); and execution isolation
for scanners. Broker compromise alone can no longer forge an *accepted* scan request:
acceptance is verified against the database.

## Crash windows

Every point where a process can die between two durable steps, and what happens. Each row
is covered by an automated test against real PostgreSQL and RabbitMQ.

| Window | Effect | Recovery | Test |
|---|---|---|---|
| API crashes before the scan transaction commits | Neither scan nor event exists | Client retries (idempotency key) | `TransactionalOutboxIntegrationTests` (rollback) |
| Publisher crashes after claiming, before publishing | Event PENDING, leased | Lease expires, another publisher publishes | `OutboxPublisherIntegrationTests.abandonedClaims…` |
| Publisher crashes **after the broker confirm, before marking PUBLISHED** | Message in queue, event still PENDING | Lease expires, event is republished: **duplicate** | `OutboxPublisherIntegrationTests.aPublisherCrashAfterTheBrokerConfirm…`, `ScanDeliveryE2ETests` (worker absorbs it) |
| Publisher crashes during the final attempt | Event PENDING, no attempts left | Marked FAILED (`LEASE_EXPIRED`), operator requeue | `…aCrashDuringTheFinalAttempt…` |
| Publication slower than the lease | Claim could be taken over while still publishing | Publisher stops publishing when the remaining lease cannot cover a confirm; untried events are released | `…eventsAreNotPublishedOnceTheLease…` |
| Worker crashes before committing the receipt | Message unacknowledged | Redelivered, processed | `test_crash_before_acknowledgement…` |
| Database connection lost **before the receipt commit** | Nothing committed | Retry queue, then accepted once the database returns | `test_a_connection_lost_before_commit…`, `test_a_rolled_back_receipt_transaction…` |
| Worker crashes **after committing the receipt, before ack** | Receipt exists, message redelivered, possibly to another worker | Redelivery recognized as **duplicate** by any worker, acked | `test_crash_after_receipt_commit_but_before_ack…`, `test_a_crash_after_commit_before_ack_is_absorbed_by_another_worker` |
| Two workers receive the same event concurrently | Both call `record_receipt` | Primary key serializes them: exactly one `NEW` | `test_concurrent_workers_accept_an_event_exactly_once`, `test_two_concurrent_workers_share_deduplication` |
| Worker crashes **after a confirmed dead-letter copy, before ack** | Copy in DLQ and original redelivered | Original dead-lettered again: **duplicate dead letter** | `test_crash_after_dead_letter_copy…` |
| Worker crashes **after a confirmed retry copy, before ack** | Copy in retry queue and original redelivered | Both processed, one receipt; the other is a **duplicate** | `test_crash_after_retry_copy…` |
| Dead-letter or retry copy not confirmed | Original not acknowledged | Original requeued after a pause | `test_failed_dead_letter_publication_requeues…` |
| Consumer crashes on every delivery | Crash loop | Quorum delivery limit dead-letters the message | `test_consumer_crash_loops…` |

In no window is an event lost. The cost of every crash is at most a duplicate, which is
absorbed by `event_id` deduplication (receipts) or is visible as a duplicate dead letter.

## What a receipt means

A processing receipt with `outcome: ACCEPTED` means only that the worker **validated the
message and durably accepted it** for processing. It does not mean that a repository was
cloned, that a scanner ran, or that any security result exists; the scan stays `QUEUED` /
`PENDING` (asserted end to end in `ScanDeliveryE2ETests`). Execution state changes only
through the lease-based execution protocol in PostgreSQL
([execution lifecycle](execution-lifecycle.md)), never through queue messages.

## Guarantees and non-guarantees

| Property | Guarantee |
|---|---|
| Scan committed ⇒ event eventually published | Yes, while the database survives and the broker becomes available within the retry budget. FAILED events are kept for manual recovery. |
| Event published ⇒ receipt recorded | At least once. Duplicates are expected and absorbed by the shared receipt store. |
| Acceptance per `event_id` | **Exactly once across all workers** (database primary key), and only for messages identical to the committed outbox payload. |
| Database outage at the worker | Never acknowledged as accepted. Bounded retries (5 × 15 s), then the dead-letter queue and an audited replay. |
| Exactly-once delivery | **No.** Duplicates can arise from publisher crashes after a confirm, lease takeover, consumer crashes after commit, and replays. Effects are made idempotent by `event_id`. |
| Ordering | **None** across events. |
| Poison messages | Bounded: schema failures are dead-lettered immediately; transient failures retry 5 times; crash loops hit the queue's delivery limit (5). |
| Backpressure | Work queue capped at 100 000 messages with `reject-publish`; the publisher retries nacked events later. |

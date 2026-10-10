# Asynchronous messaging: control plane → execution plane

Status: M2 Phase 2B. Decision record: [ADR-0004](../adr/0004-transactional-outbox-and-at-least-once-messaging.md).
Operations: [runbook](../runbooks/messaging.md).

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
 OutboxPublisher (scheduled, any number of instances)
   │  claim: FOR UPDATE SKIP LOCKED + lease          (database clock)
   │  publish: persistent, mandatory, publisher confirm
   │  ack & not returned ──► PUBLISHED      otherwise ──► retry with backoff / FAILED
   ▼
 RabbitMQ  sentinel.scan-requests ──scan.requested.v1──► sentinel.scan-requests.worker (quorum)
   │
 sentinel-worker (own least-privileged user, prefetch-bounded, manual acks)
   │  validate size, encoding, JSON, schema, AMQP properties
   │  ├─ invalid / EVENT_ID_CONFLICT ──► sentinel.scan-requests.dlx ──► dead-letter queue
   │  ├─ receipt store unavailable ────► sentinel.scan-requests.retry (TTL 15 s) ──► work queue
   │  └─ COMMIT processing receipt (SQLite, event_id unique) ──► basic.ack
   ▼
 (later phases: planning, isolated scanner execution, evidence upload)
```

## Trust boundaries

| Boundary | Control |
|---|---|
| Client → API | OIDC JWT validation, server-side organization membership (ADR-0003). Only an authorized MEMBER+ can cause a `scan.requested` event. |
| API → outbox | Same transaction as the scan. The event's organization, project and repository are copied from committed server-side rows, never from request fields. No token, user identity or credential is included. |
| API → broker | Broker credentials from the environment. Events are published only to `sentinel.scan-requests`. |
| Broker → worker | The worker treats messages as **untrusted input**: bounded size, strict JSON (no duplicate keys or NaN), schema validation with ECMA-262 anchors, property consistency checks. A message is never an authorization credential. |
| Worker → broker | Least privilege: read the work queue; write only to the retry and dead-letter exchanges; no configure. It cannot inject scan requests or read dead letters. |
| Worker state | Receipts are keyed by `event_id` with the message hash. A different message reusing an `event_id` (for example another organization's identifiers) cannot overwrite the original receipt. It is dead-lettered as a possible tampering event. |

**Future worker identity requirements** (before workers act on behalf of tenants):
per-worker broker credentials, or mTLS client certificates, with rotation; message
authenticity (for example signatures by the control plane, verified by workers) so broker
compromise cannot forge scan requests; scoped, short-lived upload credentials for scan
evidence (GitHub Actions OIDC, M5); and no worker access to the control-plane database.

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
| Worker crashes **after committing the receipt, before ack** | Receipt exists, message redelivered | Redelivery recognized as **duplicate**, acked | `test_crash_after_receipt_commit_but_before_ack…` |
| Worker crashes **after a confirmed dead-letter copy, before ack** | Copy in DLQ and original redelivered | Original dead-lettered again: **duplicate dead letter** | `test_crash_after_dead_letter_copy…` |
| Worker crashes **after a confirmed retry copy, before ack** | Copy in retry queue and original redelivered | Both processed, one receipt; the other is a **duplicate** | `test_crash_after_retry_copy…` |
| Dead-letter or retry copy not confirmed | Original not acknowledged | Original requeued after a pause | `test_failed_dead_letter_publication_requeues…` |
| Consumer crashes on every delivery | Crash loop | Quorum delivery limit dead-letters the message | `test_consumer_crash_loops…` |

In no window is an event lost. The cost of every crash is at most a duplicate, which is
absorbed by `event_id` deduplication (receipts) or is visible as a duplicate dead letter.

## What a receipt means

A processing receipt with `outcome: ACCEPTED` means only that the worker **validated the
message and durably accepted it** for processing. It does not mean that a repository was
cloned, that a scanner ran, or that any security result exists. No scanner runs in this
phase, and the control plane's scan stays `QUEUED` / `PENDING` (asserted end to end in
`ScanDeliveryE2ETests`). Execution states will come from later phases through separate,
authenticated status events.

## Guarantees and non-guarantees

| Property | Guarantee |
|---|---|
| Scan committed ⇒ event eventually published | Yes, while the database survives and the broker becomes available within the retry budget. FAILED events are kept for manual recovery. |
| Event published ⇒ receipt recorded | At least once. Duplicates are expected and absorbed by the receipt store. |
| Exactly-once delivery | **No.** Duplicates can arise from publisher crashes after a confirm, lease takeover, consumer crashes after commit, and replays. Effects are made idempotent by `event_id`. |
| Ordering | **None** across events. |
| Poison messages | Bounded: schema failures are dead-lettered immediately; transient failures retry 5 times; crash loops hit the queue's delivery limit (5). |
| Backpressure | Work queue capped at 100 000 messages with `reject-publish`; the publisher retries nacked events later. |

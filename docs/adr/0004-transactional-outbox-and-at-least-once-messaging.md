# ADR-0004: Transactional outbox and at-least-once messaging to the worker

- **Status:** Accepted (pending owner review)
- **Date:** 2026-10-09
- **Milestone:** M2 Phase 2B

## Context

An authorized scan request must reliably reach the Python execution plane. Publishing to
RabbitMQ inside the HTTP request is unsafe in both orders:

- publish, then commit: a failed commit leaves a message for a scan that does not exist;
- commit, then publish: a crash or broker outage between the two loses the request.

Distributed (XA) transactions between PostgreSQL and RabbitMQ are not supported by
RabbitMQ and would couple availability. Exactly-once delivery across a database, a
broker and a consumer is not achievable without such coordination.

## Decision

### Transactional outbox (control plane)

- `scans` and `outbox_events` rows are written in **one PostgreSQL transaction**. The
  request path never talks to the broker.
- `outbox_events` stores the exact message body (`payload`), event identity, type and
  schema version, correlation ID, organization, publication state, attempts, the next
  attempt time, a sanitized last error and a **lease** (`lease_owner`, `lease_expires_at`).
- `UNIQUE(aggregate_id, event_type)`: an idempotent replay can never create a second
  `scan.requested` event, even under concurrency (the replay path returns before writing).
- A scheduled `OutboxPublisher` (every instance may run one):
  1. marks events FAILED whose final attempt was abandoned (expired lease);
  2. **claims** due events with `SELECT … FOR UPDATE SKIP LOCKED` and sets a lease
     (database clock), incrementing `attempts` at claim time;
  3. publishes each event outside any business transaction: persistent, `mandatory`,
     with correlated **publisher confirms**;
  4. marks it PUBLISHED **only after a positive confirm for a message that was not
     returned as unroutable**; otherwise schedules a retry with exponential backoff
     (`backoff-initial · 2^(attempt−1)`, capped), or marks it FAILED after
     `max-attempts`.
  Every update after the claim is fenced by `lease_owner`, so a publisher that lost its
  lease cannot overwrite another publisher's outcome. Publishing is time-fenced as well: a
  publication only starts while the remaining lease covers the confirm timeout plus a
  margin (`lease − confirm-timeout − 1 s`). Claimed events beyond that budget are released
  untried with their attempt counters restored, so a slow publisher never publishes an
  event another publisher may have taken over.
- FAILED is terminal for the publisher but recoverable by an operator (runbook).

### Topology (RabbitMQ 4, quorum queues)

Single source of truth: `packages/contracts/messaging/topology.v1.json`, verified by the
Java and Python test suites.

| Object | Purpose |
|---|---|
| `sentinel.scan-requests` (direct) → `sentinel.scan-requests.worker` (quorum, `scan.requested.v1`) | Work queue. `x-delivery-limit: 5` (crash-loop backstop), `x-overflow: reject-publish`, `x-max-length: 100000`, dead-letters to the DLX. |
| `sentinel.scan-requests.retry` (fanout) → `sentinel.scan-requests.retry` (quorum, `x-message-ttl: 15000`) | Delayed retry; expired messages are dead-lettered back to `sentinel.scan-requests` / `scan.requested.v1`. |
| `sentinel.scan-requests.dlx` (fanout) → `sentinel.scan-requests.dead-letter` (quorum) | Dead letters for inspection and replay. |

`reject-publish` makes a full queue **nack** publications, so the outbox retries instead
of the broker silently dropping messages, and it enables at-least-once dead-lettering.

RabbitMQ 4 does not count explicit `basic.nack(requeue=true)` against a quorum queue's
delivery limit (verified by an integration test during development). Transient worker
failures therefore go through the retry queue with a worker-maintained
`x-sentinel-retry-count` header (max 5), and the delivery limit remains the backstop for
consumers that crash before acknowledging.

### Worker (execution plane)

- Validates every message (size ≤ 64 KiB, UTF-8, strict JSON without duplicate keys,
  `scan.requested.v1` schema with ECMA-262 anchor semantics, AMQP `message-id`/`type`/
  `content-type` consistency). Invalid messages are dead-lettered with an
  `x-sentinel-dead-letter` metadata header and the original body; never dropped.
- Commits a durable **processing receipt** (SQLite, `event_id` primary key, message
  SHA-256) **before** acknowledging. A redelivery with the same content is acknowledged
  as a duplicate; the same `event_id` with different content (for example another
  organization) is dead-lettered as `EVENT_ID_CONFLICT` and the original receipt is kept.
- Republications (retry, dead-letter) are confirmed before the original is acknowledged;
  if unconfirmed, the original is requeued.
- Runs with its own RabbitMQ user: no configure permission, write only to the retry and
  dead-letter exchanges, read only the work queue (verified by integration tests).

### Guarantees

- **At-least-once** from committed scan to worker receipt. Duplicates are possible
  (publisher crash after confirm, lease takeover, consumer crash after receipt commit)
  and are absorbed by the receipt store.
- **Not exactly-once.** Exactly-once *processing effects* are approximated by idempotent
  consumers keyed by `event_id`; delivery itself is not deduplicated by the broker.
- **No ordering guarantee** between events (concurrent publishers, retries, redelivery).
  Each scan has a single `scan.requested` event; consumers must not rely on order.
- Messages are not authorization credentials and are not trusted: the organization in a
  message was derived server-side, but the worker validates it and never grants access
  based on it.

A durable receipt (`outcome: ACCEPTED`) means *accepted for processing*, not *scanned*.
The scan stays `QUEUED` / `PENDING` in the control plane; execution status will be reported
by later phases.

Crash windows and their tests are listed in
[asynchronous-messaging.md](../architecture/asynchronous-messaging.md#crash-windows).

## Consequences

- Scan requests succeed while RabbitMQ is down; publication catches up when it returns.
  The `sentinel.outbox.events{status=pending}` gauge exposes the backlog.
- Polling adds up to `poll-interval-ms` (default 1 s) of latency.
- The receipt store is local to a worker host; multiple worker instances on one queue
  need a shared store to deduplicate across instances (next phase). The exact reasons are
  in the runbook (§8).
- Messages are not signed. Integrity relies on broker access control (separate users,
  least privilege). Message signing or per-worker identities (mTLS) are future work.

## Alternatives considered

- **Publish in the request after commit:** loses requests on crash or broker outage.
- **Change data capture (Debezium):** more infrastructure for the same guarantee at this
  scale.
- **Classic queues with requeue:** no delivery limit; poison messages loop forever.

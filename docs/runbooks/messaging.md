# Runbook: outbox publication and dead-letter recovery

Applies to M2 Phase 2B ([ADR-0004](../adr/0004-transactional-outbox-and-at-least-once-messaging.md)).
Commands use Windows PowerShell against the local Compose stack; adapt hosts and
credentials for other environments. Never paste message bodies, tokens or credentials into
tickets or chat.

## 1. Delivery model in one paragraph

A scan request commits a `scans` row and an `outbox_events` row together. The API's
publisher sends pending events to `sentinel.scan-requests` and marks them `PUBLISHED`
after the broker confirms. The worker commits a processing receipt keyed by `event_id`
before acknowledging. Delivery is **at-least-once**: duplicates are expected and are
harmless because of the receipt store. Exactly-once delivery is not guaranteed, and events
are not ordered.

## 2. Provisioning least-privilege broker users (local)

The Compose stack creates one administrative user (`SENTINEL_RABBITMQ_USERNAME`). The
worker must use its own user. Create it once with a random password taken from the
environment (so it is not typed literally or kept in shell history; it is briefly visible
to processes inside the broker container while the command runs):

```powershell
docker compose exec rabbitmq rabbitmqctl add_user sentinel-worker "$env:SENTINEL_WORKER_RABBITMQ_PASSWORD"
docker compose exec rabbitmq rabbitmqctl set_permissions -p / sentinel-worker '^$' '^sentinel\.scan-requests\.(dlx|retry)$' '^sentinel\.scan-requests\.worker$'
```

Use a password that does **not start with `-`**. `rabbitmqctl` parses such an argument as
an option and fails with exit code 64 (`Invalid options for this command`). Hexadecimal
passwords avoid this. The same pitfall caused an intermittent test-fixture failure; see §9.

| User | configure | write | read |
|---|---|---|---|
| `sentinel-worker` | none (`^$`) | `sentinel.scan-requests.dlx`, `sentinel.scan-requests.retry` | `sentinel.scan-requests.worker` |
| API (target) | `^sentinel\.scan-requests.*` (only while it declares the topology) | `^sentinel\.scan-requests.*` | `^sentinel\.scan-requests.*` |

The worker permissions are enforced by the worker's integration tests. With them, the
worker **cannot** publish scan requests, declare or delete queues, or read the dead-letter
queue. The API currently still uses the Compose administrative user; restricting it is
tracked as remaining work. Set `sentinel.messaging.declare-topology=false` when the
topology is provisioned out of band so the API needs no configure permission.

## 3. Signals to watch

| Signal | Where | Meaning / action |
|---|---|---|
| `sentinel.outbox.events{status=pending}` grows | API metrics (Micrometer) | Broker unreachable or publisher not running. See §4. |
| `sentinel.outbox.events{status=failed}` > 0 | API metrics | Events exhausted their attempts. See §5. |
| `sentinel.outbox.publications{outcome=retry_scheduled,reason=…}` | API metrics | Transient publication failures, by sanitized reason. |
| `sentinel.outbox.publications{outcome=lease_lost}` | API metrics | A publisher was too slow; the event may be delivered twice (harmless). Increase `lease-duration` if frequent. |
| `outbox.failed` / `outbox.abandoned_final_attempts` log lines | API logs | Terminal failures, with `event_id` and `correlation_id`. |
| `message.processed` with `outcome=dead_lettered` | Worker logs (JSON) | A message was dead-lettered; `failure_code` says why. See §6. |
| `sentinel.scan-requests.dead-letter` depth > 0 | RabbitMQ management UI (`http://127.0.0.1:15672`) | Messages need inspection. |
| `sentinel.scan-requests.retry` depth stays > 0 | Management UI | The worker's receipt store keeps failing. Check worker disk and permissions. |

Metrics are registered in the API's Micrometer registry. Only `/actuator/health` is
exposed over HTTP today; exposing a metrics endpoint (for example Prometheus) is an M7 task.

## 4. Pending events are not being published

1. Check broker reachability and the API logs for `outbox.retry_scheduled reason=…`:
   - `BROKER_UNAVAILABLE`: the broker is down or credentials are wrong;
   - `NACK`: the work queue is full (`x-max-length` with `reject-publish`). Scale workers
     or investigate why they are not consuming;
   - `UNROUTABLE`: topology missing (queue or binding deleted). Restart the API with
     `declare-topology=true`, or provision the topology;
   - `CONFIRM_TIMEOUT`: the broker is overloaded or the network is degraded.
2. Fix the cause. No action is needed on the events: they retry with exponential backoff
   (default 2 s doubling to 5 min, 8 attempts).

Inspect without exposing payloads:

```sql
SELECT status, last_error, count(*) FROM outbox_events GROUP BY status, last_error;
SELECT id, event_type, attempts, last_error, next_attempt_at, lease_owner, lease_expires_at
FROM outbox_events WHERE status = 'PENDING' ORDER BY next_attempt_at LIMIT 50;
```

## 5. Recovering FAILED events

FAILED events are never published automatically. After fixing the cause:

```sql
-- Review first.
SELECT id, event_type, aggregate_id, attempts, last_error, updated_at
FROM outbox_events WHERE status = 'FAILED' ORDER BY updated_at;

-- Requeue one event (repeat per id; prefer targeted requeues over bulk updates).
UPDATE outbox_events
SET status = 'PENDING', attempts = 0, next_attempt_at = now(), last_error = NULL, updated_at = now()
WHERE id = '<event-id>' AND status = 'FAILED';
```

This is the same operation as `OutboxStore.requeueFailed` (covered by tests). Requeueing
is safe even if the event had actually reached the broker earlier, because consumers
deduplicate by `event_id`. `UNKNOWN_EVENT_TYPE` means the running API version cannot route
the event: deploy a version that can before requeueing.

## 6. Dead-lettered messages

Every message in `sentinel.scan-requests.dead-letter` keeps its **original body** and
properties. Worker-dead-lettered messages carry an `x-sentinel-dead-letter` header
(`packages/contracts/messages/v1/dead-letter-metadata.v1.schema.json`). Broker-dead-lettered
messages (delivery limit reached by a crashing consumer) carry RabbitMQ's
`x-first-death-reason: delivery_limit`.

| `failure_code` / reason | Cause | Action |
|---|---|---|
| `MESSAGE_TOO_LARGE`, `INVALID_ENCODING`, `INVALID_JSON`, `SCHEMA_VIOLATION`, `PROPERTIES_MISMATCH` | Message not produced by a compatible control plane, or a contract mismatch between versions | **Do not replay.** Investigate the producer. Messages that did not come from the API indicate a broker access-control problem. |
| `EVENT_ID_CONFLICT` | Same `event_id` as an already processed but *different* message (possible tampering or replay with altered tenant) | **Do not replay.** Treat as a security event: compare with the outbox row (`SELECT payload FROM outbox_events WHERE id = …`) and review broker users and permissions. |
| `TRANSIENT_RETRIES_EXHAUSTED` | Worker receipt store unavailable for every retry | Fix the worker (disk, permissions), then replay. |
| `delivery_limit` (broker) | Consumers crashed repeatedly on this message | Find the crash in worker logs (`correlation_id`), fix, then replay. |

**Inspect** in the management UI (*Queues → sentinel.scan-requests.dead-letter → Get
messages*). Use *Ack mode: Nack message requeue true* so that inspecting does not remove
the message.

**Replay** after fixing the cause: move messages back to `sentinel.scan-requests` with
routing key `scan.requested.v1`, for example with the management UI's *Move messages*
(shovel plugin), or by republishing the original body and properties *without* the
`x-sentinel-dead-letter` and `x-sentinel-retry-count` headers. Replay is safe because the
worker deduplicates by `event_id`. If the scan was already processed, the replay is
acknowledged as a duplicate.

**Discard** only after recording the `event_id`, `failure_code` and reason in the incident
log. Never discard `EVENT_ID_CONFLICT` messages before the security review.

## 7. Duplicate processing

Expected sources: publisher crash after the broker confirm and before marking PUBLISHED,
lease takeover (`lease_lost`), consumer crash after committing the receipt, and replays.
Each worker host deduplicates through its receipt store
(`SENTINEL_WORKER_RECEIPT_DB`, default `.sentinel-worker/receipts.sqlite3`). Back it up
with the host. Deleting it re-enables processing of already-seen events.

## 8. Known limitations

### Why the SQLite receipt store does not support horizontally scaled workers

The store gives exactly-once *acceptance* per `event_id` **within one host**: concurrent
worker processes on the same host share the file safely (WAL journal, `BEGIN IMMEDIATE`
transactions; tested by `test_concurrent_stores_on_one_file_agree`). It is not sufficient
across hosts or containers:

1. **Deduplication is per store.** RabbitMQ redelivers an unacknowledged message to *any*
   consumer. If worker A commits a receipt and dies before acking, the redelivery may go to
   worker B, whose store has never seen the event, so B accepts it again. Every
   at-least-once duplicate (publisher crash after confirm, lease takeover, replay) can
   reach a different worker the same way.
2. **Tamper detection is per store.** `EVENT_ID_CONFLICT` only fires on the worker that
   holds the original receipt. A conflicting message delivered to another worker is
   accepted there.
3. **Sharing the file is not a fix.** SQLite's documentation warns against network file
   systems (NFS, SMB) because their locking is unreliable, and WAL mode requires shared
   memory on a single host. Several containers mounting one volume on different hosts
   could corrupt the database or break the uniqueness guarantee.
4. **State is tied to the host's disk.** Losing or recreating the worker's volume (for
   example ephemeral containers) loses the deduplication history, and old events are
   accepted again if replayed.

Today this is safe only because processing is acceptance without side effects and a single
worker process per host is the documented deployment. Before running several worker
instances, or before receipts trigger side effects such as scanner execution, the receipt
store must move to a shared database with a unique `event_id` constraint (next phase). No
correctness defect was found for the single-host deployment.

### Other limitations
- Messages are not signed. Integrity depends on broker access control.
- Retries use a fixed delay (retry-queue TTL, 15 s) rather than exponential backoff.
- No automated alerting yet (M7).

## 9. Test infrastructure diagnostics

The worker's RabbitMQ integration tests wrap broker startup and provisioning in
`tests/integration/broker_diagnostics.py`. On any failure they print a full report (exception
chain, Docker engine version, container state, last 400 broker log lines, library
versions) to stderr and write it to `$SENTINEL_TEST_DIAGNOSTICS_DIR` (default
`services/sentinel-worker/.test-diagnostics/`, git-ignored). The container environment is
excluded because it contains credentials.

**Investigated incident (M2 Phase 2B review):** the previously observed intermittent
failure (all integration tests erroring in about 5 s) was reproduced twice in 15
repeated runs with full logs. In both runs `rabbitmqctl add_user` exited with code 64,
`Invalid options for this command`, because the randomly generated test password
(`secrets.token_urlsafe`) began with `-`. That happens with probability 1/64 per run. The
fixture now uses hexadecimal passwords and never echoes command arguments. It previously
printed part of the password in the assertion output; it now redacts it.

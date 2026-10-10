# Runbook: metrics, health and alerting

Applies to M2 Phase 2C ([ADR-0005](../adr/0005-shared-receipts-tenant-verification-and-least-privilege.md)).
Recovery procedures are in the [messaging runbook](messaging.md).

## 1. Exposure model

Metrics are **not exposed over HTTP by default**. When enabled, both endpoints serve
plain HTTP without authentication, so network placement is their access control:

| Service | Enable | Constraint |
|---|---|---|
| sentinel-api | `MANAGEMENT_SERVER_PORT=9464`, `MANAGEMENT_SERVER_ADDRESS=127.0.0.1`, `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,prometheus` → `GET /actuator/prometheus` on the management port | Startup fails unless the management port is separate from the application port and the address is a literal loopback IP (`MetricsExposureGuard`). The application port never serves the scrape endpoint. |
| sentinel-worker | `SENTINEL_WORKER_METRICS_PORT=9465` (optional `SENTINEL_WORKER_METRICS_ADDRESS`, default `127.0.0.1`) | Startup fails for non-loopback addresses. |
| RabbitMQ | Built-in `rabbitmq_prometheus` plugin, port 15692 inside the container (not published by Compose) | Queue depths, including the dead-letter queue. |

Scrape from an agent on the same host, or through an authenticated tunnel or sidecar.
Never publish these ports on a shared network.

Health: `/actuator/health` (aggregate, no details), `/actuator/health/liveness` and
`/actuator/health/readiness` on the application port. The `outbox` contributor is DOWN
when the oldest pending event is older than `sentinel.messaging.outbox.max-pending-age`
(default 15 min). It affects the aggregate status only, never liveness or readiness: a
stalled outbox must not restart the API or stop it from accepting scans, which the
outbox buffers durably.

## 2. Metrics

Labels are fixed enumerations. Event, scan, project and organization identifiers,
payloads and credentials are never labels or values; tests assert this on both services.

### sentinel-api (Micrometer)

| Metric (Prometheus name) | Type | Labels | Meaning |
|---|---|---|---|
| `sentinel_outbox_events{status}` | gauge | `pending`, `failed` | Current outbox counts. |
| `sentinel_outbox_oldest_pending_age_seconds` | gauge | — | Age of the oldest unpublished event; 0 when none. |
| `sentinel_outbox_leases_expired` | gauge | — | Pending events whose publisher claim expired (crashed or stalled publisher). Reclaimed automatically. |
| `sentinel_outbox_publications_total{outcome,reason}` | counter | `published`, `retry_scheduled`, `failed`, `lease_lost`; sanitized reason | Publication outcomes; `retry_scheduled` counts publication retries. |
| `sentinel_outbox_publish_failures_total{reason}` | counter | `BROKER_UNAVAILABLE`, `NACK`, `UNROUTABLE`, `CONFIRM_TIMEOUT`, `UNKNOWN_EVENT_TYPE`, `UNEXPECTED` | Every failed broker publication attempt (RabbitMQ delivery failures). |
| `sentinel_idempotency_keys_released_total` | counter | — | Expired idempotency keys released by the cleanup. |

The DB-backed gauges run a cheap indexed query when scraped and report NaN while the
database is unavailable.

### sentinel-worker (prometheus-client)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sentinel_worker_messages_total{outcome}` | counter | `accepted`, `duplicate`, `dead_lettered`, `retry_scheduled`, `republish_failed_requeued` | Final outcome of each delivery. `accepted` = receipt acceptances; `duplicate` = deduplicated redeliveries. |
| `sentinel_worker_dead_letters_total{failure_code}` | counter | dead-letter `failure_code` enum | Why messages were dead-lettered. |
| `sentinel_worker_rejected_tampered_messages_total` | counter | — | Rejections for `EVENT_ID_CONFLICT`, `UNKNOWN_EVENT`, `DIGEST_MISMATCH`, `RELATIONSHIP_MISMATCH`: possible forgery or tampering. |
| `sentinel_worker_receipt_store_errors_total` | counter | — | Deliveries whose receipt could not be stored (database outage). |

### RabbitMQ (`rabbitmq_prometheus`)

The least-privileged API identity cannot observe queues (RabbitMQ refuses even passive
declarations without a permission on the queue), so queue depths come from the broker:
for example `rabbitmq_detailed_queue_messages_ready{queue="sentinel.scan-requests.dead-letter"}`
from `/metrics/detailed?family=queue_coarse_metrics`. Operators can also run
`sentinel-worker dlq-depth`.

## 3. Suggested alerts

Thresholds are starting points for a low-volume deployment; tune them to observed traffic.

| Alert | Condition | Severity | Response |
|---|---|---|---|
| Outbox stalled | `sentinel_outbox_oldest_pending_age_seconds > 300` for 5 min | page | Broker or publisher problem. [Messaging runbook §4](messaging.md#4-pending-events-are-not-being-published). |
| Outbox events failed | `sentinel_outbox_events{status="failed"} > 0` | ticket | Fix the cause, then audited requeue ([§5](messaging.md#5-recovering-failed-outbox-events)). |
| Publication failures | `rate(sentinel_outbox_publish_failures_total[5m]) > 0` for 10 min | ticket | Read `reason`: credentials, topology, queue full or broker health. |
| Expired claims persist | `sentinel_outbox_leases_expired > 0` for 10 min | ticket | Publishers crashing or stalled; check API restarts and lease settings. |
| Tampering suspected | `increase(sentinel_worker_rejected_tampered_messages_total[15m]) > 0` | **security page** | Treat as a security event ([§6](messaging.md#6-dead-lettered-messages)). Do not replay. Review broker users and credentials. |
| Receipt store failing | `rate(sentinel_worker_receipt_store_errors_total[5m]) > 0` for 5 min | page | Database outage or worker credentials ([§8](messaging.md#8-database-outage)). |
| Dead letters waiting | dead-letter queue ready messages > 0 for 15 min | ticket | Triage by `failure_code` ([§6](messaging.md#6-dead-lettered-messages)). |
| Work queue backlog | work queue ready messages > 1 000 for 15 min, or > 50 000 | ticket / page | Scale workers; at 100 000 the queue rejects publications and the outbox buffers. |
| No acceptances | outbox publishing, but `rate(sentinel_worker_messages_total{outcome="accepted"}[15m]) == 0` | page | Workers down or failing; check worker logs. |

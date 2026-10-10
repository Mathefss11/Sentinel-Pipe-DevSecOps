# Runbook: outbox publication, worker receipts and recovery

Applies to M2 Phase 2C ([ADR-0004](../adr/0004-transactional-outbox-and-at-least-once-messaging.md),
[ADR-0005](../adr/0005-shared-receipts-tenant-verification-and-least-privilege.md)). Metrics
and alerts: [observability runbook](observability.md). Commands use Windows PowerShell
against the local Compose stack; adapt hosts and credentials for other environments.
Never paste message bodies, tokens or credentials into tickets or chat.

## 1. Delivery model in one paragraph

A scan request commits a `scans` row and an `outbox_events` row together. The API's
publisher sends pending events to `sentinel.scan-requests` and marks them `PUBLISHED`
after the broker confirms. A worker records a receipt in PostgreSQL through
`worker.record_receipt`, which accepts the message only if it is byte-identical to the
committed outbox payload and matches the authoritative scan, project and organization,
and only then acknowledges. Delivery is **at-least-once**: duplicates are expected and
harmless, because acceptance is unique per `event_id` across all workers. Exactly-once
delivery is not guaranteed, and events are not ordered. A receipt means *accepted for
processing*, not *scanned*.

## 2. Provisioning least-privilege identities

Topology and runtime identities are provisioned by an administrator, never by the
services. With the Compose stack running and `.env` filled in (passwords must not start
with `-`):

```powershell
docker compose up --detach --wait
.\scripts\dev\provision.ps1          # Linux/macOS/CI: sh scripts/dev/provision.sh
# Then start the API (Flyway applies V005), and only then the workers.
```

Order matters: the API no longer declares the topology, so provisioning must precede its
first publish (otherwise publishes fail and count as attempts). The role script works
before or after the migrations (V005 and the script both create the group roles if
missing), but workers need V005 applied before they connect.

The scripts run, inside the containers, `infrastructure/docker/rabbitmq/provision.sh`
(imports `definitions.json` and creates the broker users) and
`infrastructure/docker/postgres/provision-roles.sh` (creates the login roles). Both are
idempotent; re-run them to rotate a password. Neither script prints a secret, and CI uses
only the placeholder values of `.env.example`.

**Credential exposure during provisioning (accepted, local scope):**

- Secrets reach the containers as environment variables of `docker compose exec -e NAME`,
  never as command-line arguments on the host.
- `rabbitmqctl add_user` / `change_password` receive the password as a **process
  argument inside the broker container** (reading it from standard input hung in
  testing). While the command runs, any process in that container, or a host user
  allowed to inspect container processes (`docker top`, root), can read it. RabbitMQ
  does not log the password.
- PostgreSQL receives the password inside an `ALTER ROLE … PASSWORD` statement over the
  local socket (psql reads it with `\getenv`, not from arguments). It is stored as a
  SCRAM hash, but it **would be written to the server log** if `log_statement` were set
  to `ddl`/`all` or the statement failed (`log_min_error_statement`). Keep the defaults
  while provisioning, and do not reuse these passwords.

For production, create users through a secrets-aware mechanism instead (for example a
pre-hashed `password_hash` in broker definitions and pre-hashed SCRAM verifiers), which
this phase does not implement.

| Identity | RabbitMQ configure / write / read | PostgreSQL |
|---|---|---|
| `sentinel-publisher` (API) | `^$` / `^sentinel\.scan-requests$` / `^$` | API uses the schema owner (see §10) |
| `sentinel-worker` | `^$` / `^sentinel\.scan-requests\.(dlx\|retry)$` / `^sentinel\.scan-requests\.worker$` | `sentinel_worker_app` ∈ `sentinel_worker`: EXECUTE `worker.record_receipt` only |
| `sentinel-operator` (on-call only) | `^$` / `^sentinel\.scan-requests$` / `^sentinel\.scan-requests\.dead-letter$` | `sentinel_operator_app` ∈ `sentinel_operator`: EXECUTE `ops.*` only |
| Broker admin (`SENTINEL_RABBITMQ_ADMIN_*`) | provisioning only | — |

No runtime user has a management tag or the configure permission, so none can declare,
delete or rebind topology. This is enforced by tests in both services and checked in CI
(`scripts/ci/verify-broker-permissions.sh`). The API defaults to
`sentinel.messaging.declare-topology=false`.

**Upgrading an existing local stack from Phase 2B.** In Phase 2B,
`SENTINEL_RABBITMQ_USERNAME/PASSWORD` were the broker administrator *and* the API's
identity. They now mean the publisher only. Do the steps in this order:

1. Stop the API and any worker. Leave the Compose stack (and its volumes) as they are.
2. In `.env`, **copy** the current `SENTINEL_RABBITMQ_USERNAME` and
   `SENTINEL_RABBITMQ_PASSWORD` values to the new `SENTINEL_RABBITMQ_ADMIN_USERNAME` and
   `SENTINEL_RABBITMQ_ADMIN_PASSWORD`. The broker volume keeps that administrator:
   `RABBITMQ_DEFAULT_*` applies only when the volume is first created. Compose refuses to
   start while `SENTINEL_RABBITMQ_ADMIN_PASSWORD` is unset.
3. Set `SENTINEL_RABBITMQ_USERNAME=sentinel-publisher` with a new password, and set the
   same pair in `SENTINEL_RABBITMQ_PUBLISHER_USERNAME/PASSWORD` (the API reads the first
   pair, the provisioning script the second).
4. Add the remaining new variables from `.env.example`: `SENTINEL_WORKER_RECEIPT_BACKEND`,
   `SENTINEL_WORKER_DB_*`, `SENTINEL_OPERATOR_*` and, optionally,
   `SENTINEL_WORKER_METRICS_*`. Keep the existing `SENTINEL_WORKER_RABBITMQ_*` user: the
   script resets its permissions to the exact pattern above.
5. `docker compose up --detach --wait` (recreates the containers with the new read-only
   mounts), then run the provisioning script. It uses `rabbitmqctl` inside the container
   and needs no AMQP credentials.
6. Start the API, then confirm `schema.worker_receipts = m2-phase2c` in
   `platform_metadata`, then start the workers.

The Phase 2B administrator keeps full broker rights and is now used only for
provisioning. Receipts in the old SQLite file are **not** migrated. A message still in
the queues that was already accepted under Phase 2B will be accepted once more in
PostgreSQL (one extra receipt; nothing is executed). Drain the work queue before
upgrading if that matters.

## 3. Signals to watch

See the [observability runbook](observability.md) for metric names and alert thresholds.
In logs, look for `outbox.retry_scheduled`, `outbox.failed`, `outbox.lease_lost` (API) and
`message.processed` with `outcome=dead_lettered` or `receipt_store.unavailable` (worker).

## 4. Pending events are not being published

1. Check broker reachability and the API logs for `outbox.retry_scheduled reason=…`:
   - `BROKER_UNAVAILABLE`: the broker is down or the publisher credentials are wrong;
   - `NACK`: the work queue is full (`x-max-length` with `reject-publish`). Scale workers
     or investigate why they are not consuming;
   - `UNROUTABLE`: topology missing (queue or binding deleted). Re-run the provisioning
     script; the API cannot (and must not) recreate topology itself;
   - `CONFIRM_TIMEOUT`: the broker is overloaded or the network is degraded.
2. Fix the cause. No action is needed on the events: they retry with exponential backoff
   (default 2 s doubling to 5 min, 8 attempts).

**Expired publisher claims** need no action. A claim is a lease. When a publisher dies,
its claims expire (`lease-duration`, default 60 s) and any publisher reclaims them
(`sentinel_outbox_leases_expired` returns to 0). An event whose final attempt was
abandoned becomes `FAILED` with `LEASE_EXPIRED` (§5).

```powershell
sentinel-worker outbox-summary      # pending, failed, expired_leases, oldest age (no payloads)
```

## 5. Recovering FAILED outbox events

FAILED events are never published automatically. Fix the cause first.
`UNKNOWN_EVENT_TYPE` means the running API cannot route the event, so deploy a version
that can. Then use the audited, bounded operator commands (operator database credentials
in `SENTINEL_OPERATOR_DB_*`):

```powershell
sentinel-worker outbox-list-failed --limit 20
sentinel-worker outbox-requeue-failed --operator alice --reason "INC-42 broker outage" --event-id <uuid>
sentinel-worker outbox-requeue-failed --operator alice --reason "INC-42 broker outage" --limit 10
```

Each requeued event is written to `ops.recovery_actions` (operator, reason, database user,
time, event id) in the same transaction, at most 100 per call. Requeueing is safe even if
the event reached the broker earlier: workers deduplicate by `event_id`. Do not update
`outbox_events` by hand; the operator role cannot, and direct changes are not audited.

## 6. Dead-lettered messages

Every message in `sentinel.scan-requests.dead-letter` keeps its **original body** and
properties. Worker dead letters carry `x-sentinel-dead-letter`
(`dead-letter-metadata.v1`). Broker dead letters from a consumer crash loop carry
`x-first-death-reason: delivery_limit`. The queue has an unlimited delivery limit (policy
`sentinel-dead-letter-retention`), so inspecting or failed replays never drop messages.

| `failure_code` / reason | Cause | Action |
|---|---|---|
| `MESSAGE_TOO_LARGE`, `INVALID_ENCODING`, `INVALID_JSON`, `SCHEMA_VIOLATION`, `PROPERTIES_MISMATCH` | Not produced by a compatible control plane | **Do not replay.** Investigate the producer and broker access. |
| `UNKNOWN_EVENT`, `DIGEST_MISMATCH`, `RELATIONSHIP_MISMATCH`, `EVENT_ID_CONFLICT` | The message does not match the committed outbox event: **possible forgery or tampering** | **Security event. Do not replay.** Compare `original_message_sha256` with `worker.delivery_rejections`, review broker users and credential exposure, preserve the message. |
| `TRANSIENT_RETRIES_EXHAUSTED` | Receipt store (PostgreSQL) unavailable for every retry | Fix the database, then replay. |
| `delivery_limit` (broker) | Consumers crashed repeatedly on this message | Fix the crash (worker logs, `correlation_id`), then replay. |

**Inspect** without consuming: `sentinel-worker dlq-depth`, or the management UI
(*Get messages*, ack mode *Nack message requeue true*).

**Replay** (operator credentials: `SENTINEL_OPERATOR_RABBITMQ_*` and `SENTINEL_OPERATOR_DB_*`):

```powershell
sentinel-worker dlq-replay --operator alice --reason "INC-43 database outage" --max-messages 10
```

Replay takes messages oldest first. For each message it **commits an audit row first**
(`ops.recovery_actions`: operator, reason, event id, message digest, failure code), then
republishes it persistently with publisher confirms to `sentinel.scan-requests` (dropping
the retry counter and broker death headers, adding `x-sentinel-replay-audit-id`), and
only then acknowledges the dead-letter copy. If the audit or the publish fails, the
message stays in the dead-letter queue and the run stops. Replay never bypasses
verification: a replayed message is checked by `worker.record_receipt` like any other.
An already accepted event becomes a duplicate, and a tampered message is dead-lettered
again. The queue is FIFO, so move security-relevant messages aside (management UI
*Move messages* to a quarantine queue created by an administrator) before replaying
those behind them.

**Discard** only after recording the `event_id`, `failure_code` and reason in the
incident log. Never discard tampering-class messages before the security review.

## 7. Worker restart, redelivery and duplicates

Workers are stateless; all deduplication state is in PostgreSQL. Restarting or replacing
a worker, or running several, is safe. Unacknowledged messages are redelivered to any
worker. A message whose receipt was committed before a crash is acknowledged as a
`duplicate`. Expected duplicate sources: publisher crash after the broker confirm, lease
takeover, consumer crash after commit, and replays.

## 8. Database outage

- **API:** scan requests fail (no partial state is committed). The publisher logs
  `outbox.run_failed` and resumes when the database returns. Gauges report NaN.
- **Worker:** `worker.record_receipt` cannot commit, so the message is **not
  acknowledged as accepted**. It goes to the retry queue (15 s), up to 5 retries, then to
  the dead-letter queue as `TRANSIENT_RETRIES_EXHAUSTED`. The consumer backs off between
  messages (1 s doubling to 10 s) to slow that drain. Connections use a 5 s connect
  timeout and 5 s statement and lock timeouts. A commit whose outcome is unknown (the
  connection was lost during `COMMIT`) is treated as a failure; the retry then reports
  `duplicate` if it had committed.
- **After recovery:** replay `TRANSIENT_RETRIES_EXHAUSTED` dead letters (§6).

## 9. RabbitMQ outage

- **API:** publications fail with `BROKER_UNAVAILABLE` or `CONFIRM_TIMEOUT`. Events stay
  `PENDING` in PostgreSQL with backoff and become `FAILED` after 8 attempts (about 10 min
  with defaults). Requeue them after recovery (§5). Scan creation is unaffected.
- **Worker:** the consumer stops and must be restarted (process supervisor). Unacked
  deliveries are redelivered after recovery and deduplicated.
- Quorum queues are durable; messages confirmed before the outage are not lost.

## 10. Known limitations

- **At-least-once delivery remains.** Each crash window costs at most a duplicate, which
  receipts absorb. Exactly-once *acceptance* per `event_id` is guaranteed by the database
  primary key, not by the broker.
- **Messages are authenticated against the database, not signed.** A forged or altered
  message is rejected unless the attacker can also write `outbox_events`.
- **Read includes purge.** RabbitMQ authorizes `queue.purge` with the read permission.
  The worker can purge the work queue and the operator can purge the dead-letter queue;
  vhost permissions cannot separate consuming from purging. Mitigations: operator
  credentials only for on-call staff, broker audit logs, and the outbox as the system of
  record (purged work can be re-published by requeueing outbox events).
- **Queue depths** are not visible to the least-privileged API identity; use the broker's
  Prometheus metrics.
- **The API still connects to PostgreSQL as the schema owner** (the Compose superuser
  locally), and `SECURITY DEFINER` functions run as the migration owner. A compromise of
  the API process therefore yields full control of the database, including receipts and
  audit rows. **This blocks real scanner execution (M3):** before scanners run, the API
  needs a separate runtime role (DML on its own tables only), and migrations and the
  definer functions need a dedicated non-superuser owner.
- **Audit is enforced by the tools, not by the broker.** The operator's broker
  credentials alone allow publishing to `sentinel.scan-requests`, consuming from or
  purging the dead-letter queue without an `ops.recovery_actions` row. Deduplication
  still holds: workers verify every message, including replays, against the outbox and
  receipts. The outbox requeue path is enforced in the database (the operator role has
  no table privileges).
- **Digest binding to `jsonb` rendering:** in-flight messages across a PostgreSQL major
  upgrade that changes `jsonb` text output would be rejected (fail closed); republish
  after the upgrade.
- `worker.delivery_rejections` and `ops.recovery_actions` grow without automatic
  retention; review and archive them periodically (no automated deletion of evidence).
- Retries use a fixed 15 s delay (retry-queue TTL); the in-process backoff only slows the
  drain.
- The SQLite receipt store (`SENTINEL_WORKER_RECEIPT_BACKEND=sqlite`, development only)
  deduplicates per host and performs no tenant verification. It is refused in `ci` and
  `production`.

## 11. Test infrastructure diagnostics

The worker's integration tests provision RabbitMQ and PostgreSQL with the production
scripts (`tests/integration/infrastructure.py`). Broker startup and provisioning are
wrapped in `tests/integration/broker_diagnostics.py`. On any failure they print a full
report (exception chain, Docker engine version, container state, last 400 broker log
lines, library versions) to stderr and write it to `$SENTINEL_TEST_DIAGNOSTICS_DIR`
(default `services/sentinel-worker/.test-diagnostics/`, git-ignored). The container
environment is excluded because it contains credentials.

**Investigated incident (M2 Phase 2B review):** an intermittent fixture failure was caused
by randomly generated passwords starting with `-`, which `rabbitmqctl` parses as an
option (exit code 64). Test passwords are hexadecimal, the provisioning script rejects
passwords starting with `-`, and command output is redacted.

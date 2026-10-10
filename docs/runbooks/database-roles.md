# Runbook: PostgreSQL roles, privileges and the V006 upgrade

Applies from Milestone 3, Phase 1 (Flyway `V006`, extended by `V007`). Design rationale:
[ADR-0006](../adr/0006-database-privilege-separation.md) and, for the execution protocol,
[ADR-0007](../adr/0007-database-authoritative-execution-leases.md).

## 1. Identities

| Role | Kind | Purpose | Privileges |
|---|---|---|---|
| cluster administrator (`SENTINEL_DB_ADMIN_USERNAME`) | superuser login | provisioning only | everything; never used by a service |
| `sentinel_owner` | NOLOGIN group | owns every object and every `SECURITY DEFINER` function | owner of `public`/`worker`/`ops`/`lifecycle` objects; `CREATE` on the database and schema `public`; no superuser, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS |
| `sentinel_migrator_app` (`SENTINEL_DB_MIGRATION_USERNAME`) | login | Flyway | member of `sentinel_owner` with `INHERIT FALSE, SET TRUE`: nothing until `SET ROLE sentinel_owner` |
| `sentinel_api` / `sentinel_api_app` (`SENTINEL_DB_USERNAME`) | group / login | API runtime | DML on control-plane tables (below); EXECUTE on the `lifecycle` control-plane functions; no DDL; no `worker`/`ops` access |
| `sentinel_worker` / `sentinel_worker_app` | group / login | worker | EXECUTE `worker.record_receipt`, `worker.claim_job`, `worker.heartbeat_job`, `worker.put_evidence`, `worker.submit_result` only; no table access |
| `sentinel_operator` / `sentinel_operator_app` | group / login | on-call recovery CLI | EXECUTE the audited `ops.*` functions only |

`PUBLIC` has no `CONNECT` on the database: only the provisioned logins can connect.

API privileges (`V006`, narrowed by `V007`):

| Table | Privileges |
|---|---|
| `platform_metadata` | SELECT |
| `organizations`, `projects` | SELECT, INSERT, UPDATE |
| `user_identities` | SELECT, INSERT |
| `organization_memberships` | SELECT, INSERT, UPDATE, DELETE |
| `scans` | SELECT, INSERT, UPDATE of `idempotency_key` and `request_fingerprint` only (key expiry; also permits the row lock that serializes planning with claims) |
| `scan_jobs` | SELECT, INSERT (planning); no UPDATE |
| `outbox_events` | SELECT, INSERT, UPDATE of publication-state columns only (never `payload`) |
| `lifecycle.execution_events` | SELECT (append-only audit trail; written only by the lifecycle functions) |
| functions | EXECUTE `lifecycle.supervise`, `lifecycle.complete_evaluation`, `lifecycle.cancel_scan`, `lifecycle.fail_scan`, `lifecycle.execution_summary`, `lifecycle.rejection_summary`, `evidence.list_result_artifacts`, `evidence.read_result_artifact`, `evidence.purge_expired` |
| `evidence.*`, `lifecycle.report_rejections` | none (functions only; no role can write evidence directly) |

No `DELETE` exists on scans, jobs, outbox events or execution events: security history is
never deleted by the API. Since `V007` the API changes execution state only through the
lifecycle functions, which enforce the state machine (no direct `UPDATE` of status,
decision, timestamps, attempts or leases).

## 2. Fresh installation (local Compose)

```powershell
Copy-Item .env.example .env            # replace every dev-only-change-me value
docker compose up --detach --wait
.\scripts\dev\provision.ps1            # roles, logins, ownership, broker users
# then start the API: Flyway migrates as the migrator login, the API runs as sentinel_api_app
```

The API refuses to start without `SENTINEL_DB_PASSWORD` (runtime) and
`SENTINEL_DB_MIGRATION_PASSWORD` (Flyway). In a deployment that runs migrations as a
separate step, start the long-running API with `SPRING_FLYWAY_ENABLED=false` so it never
holds the migration credentials.

## 3. Upgrading an installation created before V006

Before V006 the API and Flyway used the Compose superuser (`SENTINEL_DB_USERNAME`,
default `sentinel`), which owns every object. V006 **refuses to run** (and changes
nothing) until ownership has been transferred, so the order matters:

1. Stop the API and the workers.
2. In `.env`, move the old superuser credentials to the administrator variables and
   define the new logins:

   ```dotenv
   SENTINEL_DB_ADMIN_USERNAME=sentinel          # the former SENTINEL_DB_USERNAME
   SENTINEL_DB_ADMIN_PASSWORD=<former SENTINEL_DB_PASSWORD>
   SENTINEL_DB_USERNAME=sentinel_api_app
   SENTINEL_DB_PASSWORD=<new random secret>
   SENTINEL_DB_MIGRATION_USERNAME=sentinel_migrator_app
   SENTINEL_DB_MIGRATION_PASSWORD=<new random secret>
   ```

   The provisioning script refuses to run if a runtime login is the administrator, a
   superuser or a group role, so a forgotten `SENTINEL_DB_USERNAME=sentinel` cannot demote
   the administrator.
3. Back up the database (`docker compose exec postgres pg_dump ...`), as for any schema
   change.
4. Run `.\scripts\dev\provision.ps1` (or `sh scripts/dev/provision.sh`). It creates the roles and
   transfers ownership of every object in `public`, `worker` and `ops` (including
   `flyway_schema_history`) to `sentinel_owner`. Existing grants are preserved: PostgreSQL
   rewrites their grantor to the new owner.
5. Start the API. Flyway applies V006 as `sentinel_owner`.

`DatabaseUpgradePathIntegrationTests` exercises exactly this sequence on a database
migrated to V005 by a superuser, including the failure when step 4 is skipped.

### Rollback

V006 only grants privileges, revokes `PUBLIC` access and records metadata; it drops and
rewrites nothing. If the new identities cause problems, the API can temporarily be
pointed back at the administrator (`SENTINEL_DB_USERNAME`/`SENTINEL_DB_PASSWORD`) while
the problem is investigated. That restores the pre-V006 risk, so treat it as an incident.

## 4. Verification

```powershell
# Role attributes and memberships in the running stack (also run by CI).
sh scripts/ci/verify-database-roles.sh .env
```

Expected: every check `ok`. Table-level privileges are verified by
`DatabasePrivilegeIntegrationTests` (each login is denied DDL, deletion of security
history, updates of immutable columns, and access outside its schema).

Useful queries (as the administrator):

```sql
-- Objects not owned by sentinel_owner (must be empty)
SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle', 'evidence') AND c.relowner <> 'sentinel_owner'::regrole;

-- Memberships of the SentinelPipe group roles
SELECT roleid::regrole, member::regrole, inherit_option, set_option, admin_option
FROM pg_auth_members WHERE roleid::regrole::text LIKE 'sentinel\_%';
```

## 5. Rotating a password

Change the value in the secret store or `.env` and re-run the provisioning script
(idempotent), then restart the affected service. The script never prints passwords.
PostgreSQL itself could log the `ALTER ROLE ... PASSWORD` statement on error or under
non-default `log_statement` settings; keep statement logging off for the provisioning
session.

## 6. Adding database objects in later migrations

Every migration runs as `sentinel_owner`, so new objects are owned correctly. A
migration that adds a table or function must also:

- grant exactly the privileges the API, worker or operator need (column-level `UPDATE`
  where values must stay immutable);
- `REVOKE ALL ... FROM PUBLIC` on every new function. Since `V007` the global default
  privileges of `sentinel_owner` also withhold `EXECUTE` from `PUBLIC`. The per-schema
  form used in `V005`/`V006` cannot remove PostgreSQL's built-in default and had no effect;
  explicit revokes covered every function created before `V007`;
- give every `SECURITY DEFINER` function `SET search_path = pg_catalog, pg_temp` and fully
  qualified object names;
- extend `DatabasePrivilegeIntegrationTests`.

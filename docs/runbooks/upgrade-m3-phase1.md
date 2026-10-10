# Runbook: upgrading an installation to M3 Phase 1 (V006–V008)

Applies to installations created before M3 Phase 1 (Flyway V001–V005, M2 code). Each step
names what fails closed if it is skipped. Do not run any of this against an environment
without a backup.

| Migration | Changes | Reversible? |
|---|---|---|
| V006 | Grants and revocations only; refuses to run until `provision-roles.sh` has transferred ownership | Additive; the old superuser login still works for administration |
| V007 | Execution columns, `EVALUATING`, lifecycle functions; revokes the API's UPDATE on lifecycle columns | Forward-only (new constraints and functions); scans that were RUNNING get a deadline and an expired placeholder lease |
| V008 | Evidence schema, `job-result.v1` validation, `worker.submit_result`; **drops `worker.report_job`** | Forward-only; Slice 2 workers stop working |

## Ordering

1. **Stop** every worker process (`consume`, `execute`) and the API. Running scans
   continue safely after the upgrade: their leases expire and the supervisor reclaims them.
2. **Back up** the database (`pg_dump` as the administrator).
3. **Credentials** (database roles runbook, §3): move the old superuser to
   `SENTINEL_DB_ADMIN_*`, and set new `SENTINEL_DB_PASSWORD` (API) and
   `SENTINEL_DB_MIGRATION_PASSWORD` (Flyway) values. Use a different secret per login.
   Worker and operator logins keep their own secrets.
4. **Provision** roles and ownership: `.\scripts\dev\provision.ps1` (or `provision.sh`).
   *If skipped,* V006 refuses to run and nothing changes.
5. **Migrate**: start the API (Flyway applies V006, V007 and V008 as `sentinel_owner`), or
   run Flyway as a separate step and start the API with `SPRING_FLYWAY_ENABLED=false`.
6. **Worker hosts**: install the M3 Phase 1 worker, pull the sandbox image **by digest**
   (`docker pull alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8`),
   and run `sentinel-worker sandbox-check`. It must report `"healthy": true` with all 13
   controls. *If the image is missing,* `execute` exits with "unavailable" and never pulls.
7. **Start** the new workers.

`DatabaseUpgradePathIntegrationTests` exercises steps 4–5 from V005 and from V007, including
a legacy report and an in-flight lease surviving the V008 upgrade.

## Compatibility

- **A Slice 2 worker against V008** calls the dropped `worker.report_job`. That fails with
  "function does not exist", which the worker treats as a transient error. Its lease then
  expires, and a new worker retries the job. No result is accepted from it: the failure is
  closed, not corrupting. Do not mix worker versions longer than necessary.
- **An M2 worker (no `execute` command)** keeps working for message receipts
  (`worker.record_receipt` is unchanged).
- **Accepted V007 reports** stay unchanged (`result` is NULL). They cannot be resubmitted.

## Rollback

The migrations are forward-only. Rolling back the code to M2 or Slice 2 requires restoring
the backup from step 2. Do not reverse migrations by hand. As a temporary measure during an
incident, the API can be pointed at the administrator login (database roles runbook,
"Rollback"); that restores the pre-V006 risk and must be treated as an incident.

## After the upgrade

- **Evidence growth:** at most 8 MiB per lease, kept for `evidence-retention` (90 days by
  default) and then purged by the supervisor in batches of 100 per 5 s pass. Digests and
  results remain.
- **Orphaned sandboxes** are reaped by the next worker on the same host after expiry
  (timeout plus 60 s). See the execution runbook, §5.
- **Metrics** use closed label sets only; no identifiers, tokens or evidence are exported.

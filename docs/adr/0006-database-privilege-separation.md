# ADR-0006: Database privilege separation

- **Status:** Proposed (pending owner review)
- **Date:** 2026-10-10
- **Milestone:** M3 Phase 1
- **Amends:** the "API keeps connecting as the schema owner" consequence of
  [ADR-0005](0005-shared-receipts-tenant-verification-and-least-privilege.md)

## Context

Through M2 the API and Flyway connected to PostgreSQL as the same account. In local and
CI stacks that account is the container's superuser, so it also owned every table and
every `SECURITY DEFINER` function. A compromised API process, or a SQL injection in
it, therefore had full control of the database: it could rewrite outbox payloads that
workers verify messages against, delete receipts and audit rows, or alter the definer
functions that act as the worker's and operator's only interface. M3 starts executing
untrusted repository content and accepting worker results, so the control plane's own
database access must be narrowed first.

## Decision

1. **A dedicated, non-superuser owner.** `sentinel_owner` (NOLOGIN; no superuser,
   CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS) owns every object in the `public`,
   `worker` and `ops` schemas, including `flyway_schema_history`. Definer functions
   therefore run with the owner's object privileges, not with superuser powers.
2. **A separate migration login.** Flyway connects as `sentinel_migrator_app`, a member
   of `sentinel_owner` with `INHERIT FALSE, SET TRUE` (PostgreSQL 16+ membership
   options), and switches with `spring.flyway.init-sqls: SET ROLE sentinel_owner`. The
   login on its own can neither read nor create anything.
3. **A least-privileged API runtime role.** `sentinel_api` receives DML only on the
   tables the API uses. On `scans`, `scan_jobs` and `outbox_events`, `UPDATE` is granted
   per column: identifiers, commits, scanner types and published payloads cannot be
   rewritten after insertion. No `DELETE` on security history. No access to `worker` or
   `ops`.
4. **Provisioning owns cluster-level objects.** Roles, logins, database `CONNECT`
   (revoked from `PUBLIC`) and ownership transfer live in the administrative
   `provision-roles.sh`, run by the cluster administrator, like RabbitMQ provisioning.
   Migrations stay schema-scoped and need no `CREATEROLE`. The script refuses to turn
   the administrator, a superuser or a group role into a runtime login.
5. **Migrations verify instead of assuming.** V006 refuses to run unless it executes as
   `sentinel_owner`, the group roles exist, the owner holds no cluster privileges, and
   every application object already belongs to the owner. It then only grants, revokes
   `PUBLIC` access and sets default privileges, so it is safe on fresh and upgraded
   databases.
6. **Historical migrations are untouched.** V005's `CREATE ROLE` statements are guarded by
   `IF NOT EXISTS` and become no-ops once provisioning has created the roles.

> **Correction (V007).** The per-schema `ALTER DEFAULT PRIVILEGES ... IN SCHEMA ... REVOKE
> EXECUTE ON FUNCTIONS FROM PUBLIC` in V005 and V006 has no effect: PostgreSQL's built-in
> EXECUTE-to-PUBLIC default can only be removed with the global form. Every function up to
> V006 was protected by explicit revokes, which the tests verify. V007 adds the global
> form for `sentinel_owner`, and a regression test pins it.

## Consequences

- An API compromise is limited to the API's own DML. It can still insert or update
  lifecycle state it legitimately manages; the M3 execution protocol therefore keeps
  result acceptance inside definer functions with their own invariants rather than
  relying on API table privileges.
- Existing installations need a one-time, ordered upgrade (credentials moved to the
  administrator variables, provisioning, then V006); see
  [database roles runbook](../runbooks/database-roles.md). Skipping provisioning fails
  closed with an explicit error.
- Every later migration must grant privileges explicitly. Regression tests
  (`DatabasePrivilegeIntegrationTests`, `DatabaseUpgradePathIntegrationTests`) and the
  CI role check (`scripts/ci/verify-database-roles.sh`) keep that visible.
- Integration tests now run the application as the least-privileged login. Fixtures that
  need elevated rights use a separate, explicit superuser connection
  (`TestDatabaseAdmin`), so missing grants surface as test failures.
- If Flyway runs inside the API process, that process holds the migration credentials at
  startup. Deployments should run migrations as a separate step and start the API with
  `SPRING_FLYWAY_ENABLED=false`. The local development default keeps both in one process
  for convenience.

## Alternatives considered

- **Row-level security per tenant.** Deferred. The API is a multi-tenant service and
  enforces tenancy with membership checks; RLS would need a per-request tenant context
  in every session and adds little against an API compromise, which could set any
  context. It remains an option for worker- or tenant-facing database access later.
- **Create roles inside migrations.** Rejected: it requires `CREATEROLE` for the
  migration identity, which can create and alter other non-superuser roles, a much
  broader privilege than any migration needs.
- **`REASSIGN OWNED BY <administrator>`.** Rejected for the upgrade: the administrator also
  owns objects outside the application schemas (the database and system-level objects).
  The explicit, schema-scoped transfer touches only SentinelPipe objects.

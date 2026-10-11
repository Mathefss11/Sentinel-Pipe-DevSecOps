package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Upgrade path of an installation created before V006, when the migrations ran as the
 * superuser that owned every object: V006 refuses to run until provision-roles.sh has
 * transferred ownership, and then applies without touching existing data.
 */
class DatabaseUpgradePathIntegrationTests {

	private PostgreSQLContainer postgres;

	private TestDatabaseAdmin admin;

	@BeforeEach
	void startLegacyDatabase() {
		this.postgres = new PostgreSQLContainer(TestcontainersConfiguration.POSTGRES_IMAGE);
		this.postgres.start();
		this.admin = new TestDatabaseAdmin(this.postgres);
	}

	@AfterEach
	void stop() {
		this.postgres.stop();
	}

	private Flyway flyway(String user, String password, String target, String initSql) {
		var configuration = Flyway.configure()
			.dataSource(this.postgres.getJdbcUrl(), user, password)
			.locations("classpath:db/migration")
			.target(target);
		if (initSql != null) {
			configuration.initSql(initSql);
		}
		return configuration.load();
	}

	private Flyway migrator() {
		return flyway(DatabaseRoles.MIGRATOR_USER, DatabaseRoles.MIGRATOR_PASSWORD, "latest", "SET ROLE sentinel_owner");
	}

	@Test
	void legacyInstallationUpgradesAfterOwnershipTransfer() {
		// Pre-V006 installation: migrated by the superuser, with data.
		flyway(this.postgres.getUsername(), this.postgres.getPassword(), "5", null).migrate();
		JdbcTemplate jdbc = this.admin.jdbc();
		UUID organizationId = UUID.randomUUID();
		jdbc.update("INSERT INTO organizations (id, name, slug, version, created_at, updated_at)"
				+ " VALUES (?, 'Legacy', 'legacy', 0, now(), now())", organizationId);
		assertThat(jdbc.queryForObject("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'scans'::regclass",
				String.class))
			.isEqualTo(this.postgres.getUsername());

		DatabaseRoles.provision(this.postgres);
		MigrateResult result = migrator().migrate();

		assertThat(result.success).isTrue();
		// V006, V007, V008 and V009.
		assertThat(result.migrationsExecuted).isEqualTo(4);
		assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
				+ " WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle', 'evidence', 'policy')"
				+ " AND c.relowner <> 'sentinel_owner'::regrole",
				Long.class))
			.isZero();
		assertThat(jdbc.queryForObject("SELECT name FROM organizations WHERE id = ?", String.class, organizationId))
			.isEqualTo("Legacy");
		// Grants made by the former owner survive the transfer.
		assertThat(jdbc.queryForObject(
				"SELECT has_function_privilege('sentinel_worker', 'worker.record_receipt(jsonb)', 'EXECUTE')",
				Boolean.class))
			.isTrue();
		assertThat(migrator().validateWithResult().validationSuccessful).isTrue();
	}

	@Test
	void scansRunningBeforeV007AreBoundedByADeadlineAndTheirJobsRecovered() {
		// Pre-V007 state: a RUNNING scan and job written by the M2 lifecycle service (no lease).
		flyway(this.postgres.getUsername(), this.postgres.getPassword(), "5", null).migrate();
		JdbcTemplate jdbc = this.admin.jdbc();
		UUID organizationId = UUID.randomUUID();
		UUID projectId = UUID.randomUUID();
		UUID scanId = UUID.randomUUID();
		UUID jobId = UUID.randomUUID();
		jdbc.update("INSERT INTO organizations (id, name, slug, version, created_at, updated_at)"
				+ " VALUES (?, 'Legacy', 'legacy-run', 0, now(), now())", organizationId);
		jdbc.update("INSERT INTO projects (id, organization_id, name, repository_provider, repository_owner,"
				+ " repository_name, default_branch, enabled, version, created_at, updated_at)"
				+ " VALUES (?, ?, 'P', 'GITHUB', 'acme', 'repo', 'main', true, 0, now(), now())", projectId,
				organizationId);
		jdbc.update("INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type, execution_status,"
				+ " security_decision, version, requested_at, started_at, updated_at)"
				+ " VALUES (?, ?, repeat('a', 40), 'main', 'PUSH', 'RUNNING', 'PENDING', 1, now(), now(), now())",
				scanId, projectId);
		jdbc.update("INSERT INTO scan_jobs (id, scan_id, scanner_type, execution_status, attempt_count, version,"
				+ " created_at, started_at, updated_at) VALUES (?, ?, 'SEMGREP', 'RUNNING', 1, 1, now(), now(), now())",
				jobId, scanId);

		DatabaseRoles.provision(this.postgres);
		assertThat(migrator().migrate().success).isTrue();

		assertThat(jdbc.queryForObject("SELECT deadline_at = started_at + interval '15 minutes' FROM scans WHERE id = ?",
				Boolean.class, scanId))
			.isTrue();
		assertThat(jdbc.queryForMap("SELECT lease_epoch, lease_owner, lease_expires_at <= now() AS expired"
				+ " FROM scan_jobs WHERE id = ?", jobId))
			.containsEntry("lease_epoch", 1L)
			.containsEntry("lease_owner", "pre-v007")
			.containsEntry("expired", true);
		// The supervisor recovers the lease-less job like the job of a crashed worker.
		jdbc.queryForMap("SELECT * FROM lifecycle.supervise(100)");
		assertThat(jdbc.queryForMap("SELECT execution_status, failure_reason FROM scan_jobs WHERE id = ?", jobId))
			.containsEntry("execution_status", "QUEUED")
			.containsEntry("failure_reason", "LEASE_EXPIRED");
	}

	@Test
	void upgradingFromV007KeepsLegacyReportsAndInFlightLeasesUsable() {
		// A V007 installation with a scan whose two jobs are claimed; one already reported
		// through V007's report_job (no result document), the other still running.
		DatabaseRoles.provision(this.postgres);
		flyway(DatabaseRoles.MIGRATOR_USER, DatabaseRoles.MIGRATOR_PASSWORD, "7", "SET ROLE sentinel_owner")
			.migrate();
		JdbcTemplate jdbc = this.admin.jdbc();
		UUID organizationId = UUID.randomUUID();
		UUID projectId = UUID.randomUUID();
		UUID scanId = UUID.randomUUID();
		jdbc.update("INSERT INTO organizations (id, name, slug, version, created_at, updated_at)"
				+ " VALUES (?, 'V7', 'v7', 0, now(), now())", organizationId);
		jdbc.update("INSERT INTO projects (id, organization_id, name, repository_provider, repository_owner,"
				+ " repository_name, default_branch, enabled, version, created_at, updated_at)"
				+ " VALUES (?, ?, 'P', 'GITHUB', 'acme', 'repo', 'main', true, 0, now(), now())", projectId,
				organizationId);
		jdbc.update("INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type, execution_status,"
				+ " security_decision, version, requested_at, updated_at)"
				+ " VALUES (?, ?, repeat('a', 40), 'main', 'PUSH', 'QUEUED', 'PENDING', 0, now(), now())", scanId,
				projectId);
		for (String scanner : List.of("FIXTURE", "SEMGREP")) {
			jdbc.update("INSERT INTO scan_jobs (id, scan_id, scanner_type, execution_status, attempt_count, version,"
					+ " created_at, updated_at) VALUES (gen_random_uuid(), ?, ?, 'QUEUED', 0, 0, now(), now())", scanId,
					scanner);
		}
		JdbcTemplate worker = this.admin.connectAs(DatabaseRoles.WORKER_USER, DatabaseRoles.WORKER_PASSWORD);
		Map<String, Object> reported = worker.queryForMap(
				"SELECT job_id, lease_epoch, lease_token FROM worker.claim_job(ARRAY['FIXTURE'], ?)", scanId);
		Map<String, Object> running = worker.queryForMap(
				"SELECT job_id, scan_id, project_id, organization_id, commit_sha, attempt, lease_epoch, lease_token"
						+ " FROM worker.claim_job(ARRAY['SEMGREP'], ?)",
				scanId);
		assertThat(worker.queryForObject("SELECT worker.report_job(?, ?, ?, ?, 'COMPLETED')", String.class,
				reported.get("job_id"), scanId, reported.get("lease_epoch"), reported.get("lease_token")))
			.isEqualTo("ACCEPTED");

		// V008 and V009.
		assertThat(migrator().migrate().migrationsExecuted).isEqualTo(2);

		// The legacy report is kept as it was; report_job no longer exists.
		assertThat(jdbc.queryForMap("SELECT outcome, result FROM lifecycle.job_reports WHERE job_id = ?",
				reported.get("job_id")))
			.containsEntry("outcome", "COMPLETED")
			.containsEntry("result", null);
		assertThat(jdbc.queryForObject("SELECT to_regprocedure('worker.report_job(uuid,uuid,bigint,text,text,text)')",
				String.class))
			.isNull();
		// The in-flight lease completes through the V008 contract.
		String result = "{\"artifacts\":[],\"attempt\":%s,\"commit_sha\":\"%s\",\"failure_reason\":null,"
				.formatted(running.get("attempt"), running.get("commit_sha"))
				+ "\"finished_at\":\"2026-10-10T12:00:01Z\",\"job_id\":\"%s\",\"lease_epoch\":%s,"
					.formatted(running.get("job_id"), running.get("lease_epoch"))
				+ "\"organization_id\":\"%s\",\"outcome\":\"COMPLETED\",\"project_id\":\"%s\",\"scan_id\":\"%s\","
					.formatted(running.get("organization_id"), running.get("project_id"), running.get("scan_id"))
				+ "\"scanner_type\":\"SEMGREP\",\"schema_version\":1,\"started_at\":\"2026-10-10T12:00:00Z\"}";
		assertThat(worker.queryForObject("SELECT worker.submit_result(?, ?)", String.class,
				running.get("lease_token"), result))
			.isEqualTo("ACCEPTED");
		assertThat(jdbc.queryForObject("SELECT execution_status FROM scans WHERE id = ?", String.class, scanId))
			.isEqualTo("EVALUATING");
	}

	@Test
	void v006RefusesToRunWithoutProvisioning() {
		flyway(this.postgres.getUsername(), this.postgres.getPassword(), "5", null).migrate();

		assertThatThrownBy(() -> flyway(this.postgres.getUsername(), this.postgres.getPassword(), "latest", null)
			.migrate()).hasMessageContaining("V006 must run as sentinel_owner");
		assertThat(this.admin.jdbc()
			.queryForObject("SELECT count(*) FROM flyway_schema_history WHERE version = '6' AND success", Long.class))
			.isZero();
	}

	@Test
	void v006RefusesToRunWhileLegacyObjectsKeepTheirOwner() {
		flyway(this.postgres.getUsername(), this.postgres.getPassword(), "5", null).migrate();
		DatabaseRoles.provision(this.postgres);
		// Simulates an object created outside the provisioned ownership model.
		this.admin.jdbc().execute("CREATE TABLE public.stray_table (id int)");

		assertThatThrownBy(() -> migrator().migrate()).hasMessageContaining("objects not owned by sentinel_owner")
			.hasMessageContaining("stray_table");
	}

	@Test
	void freshInstallationMigratesEntirelyAsTheOwner() {
		DatabaseRoles.provision(this.postgres);

		assertThat(migrator().migrate().migrationsExecuted).isEqualTo(9);
		assertThat(this.admin.jdbc()
			.queryForObject("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'flyway_schema_history'::regclass",
					String.class))
			.isEqualTo("sentinel_owner");
	}

}

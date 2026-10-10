package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
		assertThat(result.migrationsExecuted).isEqualTo(3);
		assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
				+ " WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle', 'evidence')"
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

		assertThat(migrator().migrate().migrationsExecuted).isEqualTo(8);
		assertThat(this.admin.jdbc()
			.queryForObject("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'flyway_schema_history'::regclass",
					String.class))
			.isEqualTo("sentinel_owner");
	}

}

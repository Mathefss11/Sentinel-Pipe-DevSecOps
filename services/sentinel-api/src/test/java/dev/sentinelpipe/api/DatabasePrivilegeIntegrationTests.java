package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Regression tests for the database privilege model (Flyway V006 to V008,
 * provision-roles.sh).
 * Each identity connects with its real login and is denied everything outside its
 * purpose; catalog checks pin ownership and role attributes.
 */
class DatabasePrivilegeIntegrationTests extends AbstractIntegrationTest {

	/** SQLSTATE insufficient_privilege: "permission denied" and "must be owner" errors. */
	private static final String INSUFFICIENT_PRIVILEGE = "42501";

	@Autowired
	private TestDatabaseAdmin admin;

	@Autowired
	private PostgreSQLContainer postgres;

	private JdbcTemplate api() {
		return this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
	}

	private JdbcTemplate migrator() {
		return this.admin.connectAs(DatabaseRoles.MIGRATOR_USER, DatabaseRoles.MIGRATOR_PASSWORD);
	}

	private JdbcTemplate worker() {
		return this.admin.connectAs(DatabaseRoles.WORKER_USER, DatabaseRoles.WORKER_PASSWORD);
	}

	private JdbcTemplate operator() {
		return this.admin.connectAs(DatabaseRoles.OPERATOR_USER, DatabaseRoles.OPERATOR_PASSWORD);
	}

	private static void assertDenied(JdbcTemplate jdbc, String sql) {
		assertThatThrownBy(() -> jdbc.execute(sql)).as(sql)
			.isInstanceOf(DataAccessException.class)
			.satisfies((ex) -> assertThat(((DataAccessException) ex).getMostSpecificCause())
				.isInstanceOf(SQLException.class)
				.extracting((cause) -> ((SQLException) cause).getSQLState())
				.isEqualTo(INSUFFICIENT_PRIVILEGE));
	}

	// ---------------------------------------------------------------------------------
	// Ownership and role attributes
	// ---------------------------------------------------------------------------------

	@Test
	void everyApplicationObjectIsOwnedBySentinelOwner() {
		List<Map<String, Object>> owners = this.admin.jdbc().queryForList("""
				SELECT pg_get_userbyid(c.relowner) AS owner, count(*) AS objects
				FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle', 'evidence')
				GROUP BY 1
				UNION ALL
				SELECT pg_get_userbyid(p.proowner), count(*)
				FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
				WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle', 'evidence')
				GROUP BY 1
				UNION ALL
				SELECT pg_get_userbyid(nspowner), count(*) FROM pg_namespace
				WHERE nspname IN ('worker', 'ops', 'lifecycle', 'evidence') GROUP BY 1
				""");

		assertThat(owners).isNotEmpty().allSatisfy((row) -> assertThat(row).containsEntry("owner", "sentinel_owner"));
		assertThat(this.admin.jdbc()
			.queryForObject("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.flyway_schema_history'::regclass",
					String.class))
			.isEqualTo("sentinel_owner");
	}

	@Test
	void securityDefinerFunctionsRunAsANonSuperuser() {
		List<Map<String, Object>> definers = this.admin.jdbc().queryForList("""
				SELECT p.oid::regprocedure::text AS function, r.rolsuper, r.rolbypassrls, r.rolcreaterole
				FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
				WHERE p.prosecdef AND p.pronamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace)
				""");

		assertThat(definers).isNotEmpty().allSatisfy((row) -> assertThat(row).containsEntry("rolsuper", false)
			.containsEntry("rolbypassrls", false)
			.containsEntry("rolcreaterole", false));
	}

	@Test
	void groupRolesCannotLogInAndNoSentinelRoleIsPrivileged() {
		List<Map<String, Object>> roles = this.admin.jdbc().queryForList("""
				SELECT rolname, rolcanlogin, rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
				       AS privileged
				FROM pg_roles WHERE rolname LIKE 'sentinel\\_%' ORDER BY rolname
				""");

		assertThat(roles).extracting((row) -> row.get("rolname"))
			.contains("sentinel_owner", "sentinel_api", "sentinel_worker", "sentinel_operator", DatabaseRoles.API_USER,
					DatabaseRoles.MIGRATOR_USER, DatabaseRoles.WORKER_USER, DatabaseRoles.OPERATOR_USER);
		assertThat(roles).allSatisfy((row) -> assertThat(row).containsEntry("privileged", false));
		assertThat(roles).filteredOn((row) -> List.of("sentinel_owner", "sentinel_api", "sentinel_worker",
				"sentinel_operator").contains(row.get("rolname")))
			.hasSize(4)
			.allSatisfy((row) -> assertThat(row).containsEntry("rolcanlogin", false));
	}

	@Test
	void migratorMayOnlySwitchToTheOwnerAndInheritsNothing() {
		Map<String, Object> membership = this.admin.jdbc().queryForMap("""
				SELECT a.inherit_option, a.set_option, a.admin_option FROM pg_auth_members a
				WHERE a.roleid = 'sentinel_owner'::regrole AND a.member = ?::regrole
				""", DatabaseRoles.MIGRATOR_USER);
		assertThat(membership).containsEntry("inherit_option", false)
			.containsEntry("set_option", true)
			.containsEntry("admin_option", false);

		// Without SET ROLE the migrator login can neither read nor create anything.
		assertDenied(migrator(), "SELECT count(*) FROM scans");
		assertDenied(migrator(), "CREATE TABLE migrator_probe (id int)");
		// Only the migrator is a member of the owner role.
		assertThat(this.admin.jdbc()
			.queryForList("SELECT member::regrole::text FROM pg_auth_members WHERE roleid = 'sentinel_owner'::regrole",
					String.class))
			.containsExactly(DatabaseRoles.MIGRATOR_USER);
	}

	@Test
	void loginsOutsideTheSentinelGroupsCannotConnect() {
		String intruder = "intruder_" + UUID.randomUUID().toString().substring(0, 8);
		String password = "p" + UUID.randomUUID().toString().replace("-", "");
		this.admin.jdbc().execute("CREATE ROLE " + intruder + " LOGIN PASSWORD '" + password + "'");
		try {
			assertThat(this.admin.canConnect(intruder, password)).isFalse();
			assertThat(this.admin.canConnect(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD)).isTrue();
		}
		finally {
			this.admin.jdbc().execute("DROP ROLE " + intruder);
		}
	}

	@Test
	void noFunctionInTheApplicationSchemasIsExecutableByPublic() {
		List<String> publicFunctions = this.admin.jdbc().queryForList("""
				SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
				WHERE n.nspname IN ('public', 'worker', 'ops', 'lifecycle', 'evidence')
				  AND EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
				              WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
				""", String.class);

		assertThat(publicFunctions).isEmpty();
	}

	@Test
	void functionsCreatedByTheOwnerAreNotExecutableByPublicByDefault() {
		// V007 replaced the ineffective per-schema default with the global form.
		assertThat(this.admin.jdbc().queryForObject("""
				SELECT count(*) FROM pg_default_acl d
				WHERE d.defaclrole = 'sentinel_owner'::regrole AND d.defaclnamespace = 0 AND d.defaclobjtype = 'f'
				  AND NOT EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) a WHERE a.grantee = 0)
				""", Long.class))
			.isEqualTo(1);
	}

	@Test
	void onlyTheIntendedRolesMayExecuteTheLifecycleFunctions() {
		List<String> worker = List.of("sentinel_worker");
		List<String> api = List.of("sentinel_api");
		Map<String, List<String>> expected = Map.ofEntries(Map.entry("worker.claim_job(text[],uuid)", worker),
				Map.entry("worker.heartbeat_job(uuid,bigint,text)", worker),
				Map.entry("worker.put_evidence(uuid,bigint,text,text,text,bytea)", worker),
				Map.entry("worker.submit_result(text,text)", worker),
				Map.entry("evidence.list_result_artifacts(uuid)", api),
				Map.entry("evidence.read_result_artifact(uuid,bigint,text)", api),
				Map.entry("evidence.purge_expired(integer)", api), Map.entry("lifecycle.execution_summary()", api),
				Map.entry("lifecycle.rejection_summary()", api), Map.entry("lifecycle.supervise(integer)", api),
				Map.entry("lifecycle.complete_evaluation(uuid,text,text)", api),
				Map.entry("lifecycle.cancel_scan(uuid,text)", api), Map.entry("lifecycle.fail_scan(uuid)", api));
		for (Map.Entry<String, List<String>> function : expected.entrySet()) {
			assertThat(this.admin.jdbc().queryForList("""
					SELECT a.grantee::regrole::text FROM pg_proc p, aclexplode(p.proacl) a
					WHERE p.oid = ?::regprocedure AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner
					""", String.class, function.getKey()))
				.as(function.getKey())
				.containsExactlyElementsOf(function.getValue());
		}
		// Internal helpers: owner only.
		assertThat(this.admin.jdbc().queryForObject("""
				SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
				WHERE p.pronamespace = 'lifecycle'::regnamespace
				  AND p.proname IN ('log_event', 'retry_delay', 'settle_scan', 'end_unfinished_jobs', 'note_rejection',
				                    'lease_rejection', 'apply_job_outcome', 'validate_job_result')
				  AND a.grantee <> p.proowner
				""", Long.class))
			.isZero();
	}

	@Test
	void noRoleButTheOwnerCanWriteTheExecutionAuditTrail() {
		assertThat(this.admin.jdbc().queryForList("""
				SELECT DISTINCT a.grantee::regrole::text || ':' || a.privilege_type
				FROM pg_class c, aclexplode(c.relacl) a
				WHERE c.oid IN ('lifecycle.execution_events'::regclass, 'lifecycle.job_reports'::regclass,
				                'lifecycle.report_rejections'::regclass, 'evidence.objects'::regclass,
				                'evidence.job_artifacts'::regclass, 'evidence.result_artifacts'::regclass)
				  AND a.grantee <> c.relowner
				""", String.class))
			.containsExactly("sentinel_api:SELECT");
	}

	// ---------------------------------------------------------------------------------
	// API runtime identity
	// ---------------------------------------------------------------------------------

	@ParameterizedTest
	@ValueSource(strings = { "CREATE TABLE api_probe (id int)", "ALTER TABLE scans ADD COLUMN probe int",
			"DROP TABLE platform_metadata", "TRUNCATE outbox_events", "DELETE FROM scans", "DELETE FROM outbox_events",
			"DELETE FROM organizations", "DELETE FROM scan_jobs", "UPDATE user_identities SET subject = subject",
			"UPDATE platform_metadata SET metadata_value = 'x'", "UPDATE scans SET commit_sha = commit_sha",
			"UPDATE scans SET project_id = project_id", "UPDATE scan_jobs SET scanner_type = scanner_type",
			"UPDATE scan_jobs SET scan_id = scan_id", "UPDATE outbox_events SET payload = payload",
			"UPDATE outbox_events SET organization_id = organization_id", "SELECT * FROM worker.processing_receipts",
			"SELECT * FROM ops.recovery_actions", "SELECT worker.record_receipt('{}'::jsonb)",
			"SELECT * FROM ops.outbox_summary()", "SET ROLE sentinel_owner", "SET ROLE sentinel_worker",
			"CREATE SCHEMA api_probe",
			// V007: execution state changes only through the lifecycle functions.
			"UPDATE scans SET execution_status = execution_status", "UPDATE scans SET security_decision = 'PASS'",
			"UPDATE scans SET started_at = started_at", "UPDATE scans SET completed_at = completed_at",
			"UPDATE scans SET deadline_at = NULL", "UPDATE scans SET decision_reason = decision_reason",
			"UPDATE scans SET lease_duration_seconds = 600", "UPDATE scan_jobs SET execution_status = 'COMPLETED'",
			"UPDATE scan_jobs SET attempt_count = 0", "UPDATE scan_jobs SET lease_epoch = 0",
			"UPDATE scan_jobs SET lease_owner = 'sentinel_api_app'", "UPDATE scan_jobs SET lease_token_sha256 = NULL",
			"UPDATE scan_jobs SET lease_expires_at = now()", "UPDATE scan_jobs SET failure_reason = NULL",
			"INSERT INTO lifecycle.execution_events (scan_id, event_type, actor_type)"
					+ " VALUES (gen_random_uuid(), 'SCAN_STARTED', 'USER')",
			"UPDATE lifecycle.execution_events SET detail = NULL", "DELETE FROM lifecycle.execution_events",
			"SELECT * FROM lifecycle.job_reports", "SELECT * FROM worker.claim_job(ARRAY['FIXTURE'])",
			"SELECT * FROM worker.heartbeat_job(gen_random_uuid(), 1, repeat('a', 64))",
			"SELECT worker.submit_result(repeat('a', 64), '{}')",
			"SELECT * FROM worker.put_evidence(gen_random_uuid(), 1, repeat('a', 64), 'x', 'text/plain', ''::bytea)",
			// V008: evidence and rejection records only through functions; never writable.
			"SELECT * FROM evidence.objects", "SELECT * FROM evidence.job_artifacts",
			"SELECT * FROM evidence.result_artifacts", "UPDATE evidence.objects SET content = NULL",
			"DELETE FROM evidence.objects", "SELECT * FROM lifecycle.report_rejections",
			"DELETE FROM lifecycle.report_rejections",
			"SELECT lifecycle.validate_job_result('{}'::json)",
			"SELECT lifecycle.settle_scan(gen_random_uuid(), now(), 'USER', 'x')",
			"SELECT lifecycle.log_event(gen_random_uuid(), NULL, 'SCAN_STARTED', 'USER', 'x', NULL, NULL)",
			"SELECT lifecycle.end_unfinished_jobs(gen_random_uuid(), now(), 'FAILED', NULL, 'USER', 'x')" })
	void apiRuntimeIdentityIsDenied(String sql) {
		assertDenied(api(), sql);
	}

	@Test
	void apiRuntimeIdentityHasTheDataAccessItNeeds() {
		JdbcTemplate api = api();

		assertThat(api.queryForObject("SELECT count(*) FROM scans", Long.class)).isNotNull();
		assertThat(api.queryForObject("SELECT count(*) FROM outbox_events", Long.class)).isNotNull();
		assertThat(api.queryForObject("SELECT metadata_value FROM platform_metadata WHERE metadata_key = 'schema.database_roles'",
				String.class))
			.isEqualTo("m3-phase1");
		// Writable columns stay writable (no rows match; privileges are still checked).
		assertThat(api.update("UPDATE scans SET idempotency_key = NULL, request_fingerprint = NULL WHERE false"))
			.isZero();
		assertThat(api.update("UPDATE outbox_events SET status = status WHERE false")).isZero();
		assertThat(api.update("DELETE FROM organization_memberships WHERE false")).isZero();
		// Row locks that serialize planning with claims.
		assertThat(api.queryForList("SELECT id FROM scans WHERE false FOR UPDATE")).isEmpty();
		// Lifecycle changes go through the granted functions.
		assertThat(api.queryForObject("SELECT lifecycle.cancel_scan(gen_random_uuid(), 'user:probe')", String.class))
			.isEqualTo("NOT_FOUND");
		assertThat(api.queryForObject("SELECT lifecycle.fail_scan(gen_random_uuid())", String.class))
			.isEqualTo("NOT_FOUND");
		assertThat(api.queryForObject(
				"SELECT lifecycle.complete_evaluation(gen_random_uuid(), 'INCOMPLETE', 'POLICY_EVALUATION_UNAVAILABLE')",
				String.class))
			.isEqualTo("NOT_FOUND");
		assertThat(api.queryForMap("SELECT * FROM lifecycle.supervise(1)")).containsKey("leases_expired");
		assertThat(api.queryForObject("SELECT count(*) FROM lifecycle.execution_events", Long.class)).isNotNull();
		// V008: evidence of record, retention and metrics only through functions.
		assertThat(api.queryForList("SELECT * FROM evidence.list_result_artifacts(gen_random_uuid())")).isEmpty();
		assertThat(api.queryForList("SELECT * FROM evidence.read_result_artifact(gen_random_uuid(), 1, 'x')"))
			.isEmpty();
		assertThat(api.queryForObject("SELECT evidence.purge_expired(1)", Integer.class)).isNotNull();
		assertThat(api.queryForMap("SELECT * FROM lifecycle.execution_summary()")).containsKey("running_jobs");
		assertThat(api.queryForList("SELECT * FROM lifecycle.rejection_summary()")).isNotNull();
	}

	// ---------------------------------------------------------------------------------
	// Worker and operator identities
	// ---------------------------------------------------------------------------------

	@ParameterizedTest
	@ValueSource(strings = { "SELECT count(*) FROM scans", "SELECT count(*) FROM outbox_events",
			"SELECT count(*) FROM organizations", "SELECT count(*) FROM worker.processing_receipts",
			"INSERT INTO worker.processing_receipts (event_id) VALUES (gen_random_uuid())",
			"SELECT worker.note_rejection('{}'::jsonb, 'UNKNOWN_EVENT')", "SELECT * FROM ops.outbox_summary()",
			"SET ROLE sentinel_owner", "SET ROLE sentinel_api", "CREATE TABLE worker_probe (id int)",
			// V007: the worker reaches execution state only through its three functions.
			"SELECT count(*) FROM scan_jobs", "UPDATE scan_jobs SET execution_status = 'COMPLETED'",
			"SELECT count(*) FROM lifecycle.execution_events", "SELECT * FROM lifecycle.job_reports",
			"SELECT * FROM lifecycle.supervise(1)", "SELECT lifecycle.cancel_scan(gen_random_uuid(), 'x')",
			"SELECT lifecycle.complete_evaluation(gen_random_uuid(), 'PASS', 'POLICY_EVALUATED')",
			"SELECT lifecycle.settle_scan(gen_random_uuid(), now(), 'WORKER', 'x')",
			// V008: the worker writes evidence only through put_evidence and reads none back.
			"SELECT * FROM evidence.objects", "INSERT INTO evidence.objects (organization_id, sha256, size_bytes,"
					+ " retain_until) VALUES (gen_random_uuid(), repeat('a', 64), 0, now())",
			"SELECT * FROM evidence.job_artifacts", "SELECT evidence.purge_expired(1)",
			"SELECT * FROM evidence.read_result_artifact(gen_random_uuid(), 1, 'x')",
			"SELECT * FROM evidence.list_result_artifacts(gen_random_uuid())",
			"SELECT * FROM lifecycle.execution_summary()", "SELECT * FROM lifecycle.report_rejections",
			"SELECT lifecycle.note_rejection(gen_random_uuid(), gen_random_uuid(), 1, 1, 'RESULT', 'X')" })
	void workerIdentityIsDenied(String sql) {
		assertDenied(worker(), sql);
	}

	@ParameterizedTest
	@ValueSource(strings = { "SELECT count(*) FROM outbox_events", "SELECT count(*) FROM ops.recovery_actions",
			"UPDATE outbox_events SET status = 'PENDING'", "SELECT worker.record_receipt('{}'::jsonb)",
			"SET ROLE sentinel_owner", "CREATE TABLE operator_probe (id int)",
			"SELECT * FROM worker.claim_job(ARRAY['FIXTURE'])", "SELECT * FROM lifecycle.supervise(1)",
			"SELECT lifecycle.cancel_scan(gen_random_uuid(), 'x')", "SELECT worker.submit_result(repeat('a', 64), '{}')",
			"SELECT * FROM evidence.list_result_artifacts(gen_random_uuid())" })
	void operatorIdentityIsDenied(String sql) {
		assertDenied(operator(), sql);
	}

	@Test
	void workerAndOperatorKeepTheirFunctionAccess() {
		assertThatThrownBy(() -> worker().queryForObject("SELECT worker.record_receipt('{}'::jsonb)", String.class))
			// Reached the function body: rejected as invalid input, not for lack of privileges.
			.hasMessageContaining("invalid receipt document");
		assertThat(operator().queryForMap("SELECT * FROM ops.outbox_summary()")).containsKey("pending");
		assertThatThrownBy(() -> worker().queryForList("SELECT * FROM worker.claim_job(ARRAY['NOT_A_SCANNER'])"))
			.hasMessageContaining("invalid scanner types");
		assertThat(worker().queryForObject(
				"SELECT status FROM worker.heartbeat_job(gen_random_uuid(), 1, repeat('a', 64))", String.class))
			.isEqualTo("LEASE_LOST");
		assertThatThrownBy(() -> worker().queryForObject("SELECT worker.submit_result(repeat('a', 64), '{}')",
				String.class))
			.hasMessageContaining("invalid job result");
		assertThat(worker().queryForObject("SELECT status FROM worker.put_evidence(gen_random_uuid(), 1,"
				+ " repeat('a', 64), 'probe.json', 'application/json', '{}'::bytea)", String.class))
			.isEqualTo("REJECTED_UNKNOWN_JOB");
	}

	// ---------------------------------------------------------------------------------
	// Provisioning script safety
	// ---------------------------------------------------------------------------------

	@Test
	void provisioningIsIdempotent() {
		assertThat(DatabaseRoles.provision(this.postgres, Map.of("SENTINEL_DB_USERNAME", DatabaseRoles.API_USER))
			.getExitCode()).isZero();
		everyApplicationObjectIsOwnedBySentinelOwner();
		assertThat(this.admin.canConnect(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD)).isTrue();
	}

	@Test
	void provisioningRefusesToTurnTheAdministratorOrAGroupRoleIntoARuntimeLogin() {
		ExecResult administrator = DatabaseRoles.provision(this.postgres,
				Map.of("SENTINEL_DB_USERNAME", this.postgres.getUsername()));
		ExecResult groupRole = DatabaseRoles.provision(this.postgres,
				Map.of("SENTINEL_WORKER_DB_USERNAME", "sentinel_owner"));
		ExecResult shared = DatabaseRoles.provision(this.postgres,
				Map.of("SENTINEL_WORKER_DB_USERNAME", DatabaseRoles.API_USER));

		assertThat(administrator.getExitCode()).isNotZero();
		assertThat(administrator.getStderr()).contains("invalid login role configuration");
		assertThat(groupRole.getExitCode()).isNotZero();
		assertThat(shared.getExitCode()).isNotZero();
		assertThat(this.admin.jdbc()
			.queryForObject("SELECT rolsuper FROM pg_roles WHERE rolname = ?", Boolean.class, this.postgres.getUsername()))
			.isTrue();
		assertThat(this.admin.jdbc()
			.queryForObject("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'sentinel_owner'", Boolean.class))
			.isFalse();
	}

}

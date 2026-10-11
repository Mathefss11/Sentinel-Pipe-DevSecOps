package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.persistence.EntityManagerFactory;
import java.util.List;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

class FlywayMigrationIntegrationTests extends AbstractIntegrationTest {

	@Autowired
	private Flyway flyway;

	private JdbcTemplate jdbcTemplate;

	@Autowired
	void setDatabaseAdmin(TestDatabaseAdmin admin) {
		this.jdbcTemplate = admin.jdbc();
	}

	@Autowired
	private EntityManagerFactory entityManagerFactory;

	@Test
	void allMigrationsAreAppliedInOrderToAFreshDatabase() {
		List<Map<String, Object>> history = jdbcTemplate.queryForList(
				"SELECT script, success FROM flyway_schema_history WHERE version IS NOT NULL ORDER BY installed_rank");

		assertThat(history).extracting((row) -> row.get("script"))
			.containsExactly("V001__initial_schema.sql", "V002__core_domain.sql",
					"V003__identity_and_memberships.sql", "V004__transactional_outbox.sql",
					"V005__worker_receipts_and_operations.sql",
					"V006__least_privilege_database_roles.sql", "V007__execution_leases_and_lifecycle.sql",
					"V008__result_integrity_and_evidence.sql", "V009__security_policy_engine.sql");
		assertThat(history).allSatisfy((row) -> assertThat(row).containsEntry("success", true));
		assertThat(flyway.info().pending()).isEmpty();
	}

	@Test
	void appliedMigrationsMatchTheirChecksums() {
		// Fails if a previously applied migration file was edited.
		assertThat(flyway.validateWithResult().validationSuccessful).isTrue();
	}

	@Test
	void baselineMetadataIsRecorded() {
		String baseline = jdbcTemplate.queryForObject(
				"SELECT metadata_value FROM platform_metadata WHERE metadata_key = 'schema.baseline'", String.class);
		String coreDomain = jdbcTemplate.queryForObject(
				"SELECT metadata_value FROM platform_metadata WHERE metadata_key = 'schema.core_domain'", String.class);

		assertThat(baseline).isEqualTo("m1-foundation");
		assertThat(coreDomain).isEqualTo("m2-phase1");
		assertThat(jdbcTemplate.queryForObject(
				"SELECT metadata_value FROM platform_metadata WHERE metadata_key = 'schema.worker_receipts'",
				String.class))
			.isEqualTo("m2-phase2c");
	}

	@Test
	void workerAndOperatorObjectsLiveInTheirOwnSchemas() {
		List<String> tables = jdbcTemplate.queryForList("""
				SELECT table_schema || '.' || table_name FROM information_schema.tables
				WHERE table_schema IN ('worker', 'ops') ORDER BY 1
				""", String.class);

		assertThat(tables).containsExactly("ops.recovery_actions", "worker.delivery_rejections",
				"worker.processing_receipts");
	}

	@Test
	void privilegedFunctionsAreHardenedAndNotExecutableByPublic() {
		List<Map<String, Object>> functions = jdbcTemplate.queryForList("""
				SELECT n.nspname || '.' || p.proname AS name, p.prosecdef AS definer,
				       array_to_string(p.proconfig, ',') AS config,
				       EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
				               WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_execute
				FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
				WHERE n.nspname IN ('worker', 'ops', 'lifecycle', 'evidence', 'policy')
				""");
		// Internal helpers run with the privileges of the definer function that calls them.
		List<String> invokerHelpers = List.of("lifecycle.log_event", "lifecycle.retry_delay",
				"lifecycle.settle_scan", "lifecycle.end_unfinished_jobs", "lifecycle.note_rejection",
				"lifecycle.lease_rejection", "lifecycle.apply_job_outcome", "lifecycle.validate_job_result",
				"policy.validate_reasons", "policy.refuse_change", "policy.require_initial_state",
				"policy.require_evaluation_record");

		assertThat(functions).extracting((row) -> row.get("name"))
			.containsExactlyInAnyOrder("worker.note_rejection", "worker.record_receipt", "ops.outbox_summary",
					"ops.list_failed_outbox_events", "ops.requeue_failed_outbox_events",
					"ops.record_dead_letter_replay", "worker.claim_job", "worker.heartbeat_job", "worker.put_evidence",
					"worker.submit_result",
					"lifecycle.supervise", "lifecycle.complete_evaluation", "lifecycle.cancel_scan",
					"lifecycle.fail_scan", "lifecycle.log_event", "lifecycle.retry_delay", "lifecycle.settle_scan",
					"lifecycle.end_unfinished_jobs", "lifecycle.note_rejection", "lifecycle.lease_rejection",
					"lifecycle.apply_job_outcome", "lifecycle.validate_job_result", "lifecycle.execution_summary",
					"lifecycle.rejection_summary", "evidence.list_result_artifacts", "evidence.read_result_artifact",
					"evidence.purge_expired", "policy.refuse_change", "policy.create_policy_version",
					"policy.assign_project_policy", "policy.pin_scan_policy", "policy.evaluation_context",
					"policy.job_evidence", "policy.validate_reasons", "policy.record_evaluation",
					"policy.require_initial_state", "policy.require_evaluation_record");
		assertThat(functions).allSatisfy((row) -> {
			assertThat(row).containsEntry("definer", !invokerHelpers.contains(row.get("name")))
				.containsEntry("config", "search_path=pg_catalog, pg_temp")
				.containsEntry("public_execute", false);
		});
	}

	@Test
	void workerAndOperatorGroupRolesCannotLogIn() {
		List<Map<String, Object>> roles = jdbcTemplate.queryForList("""
				SELECT rolname, rolcanlogin, rolsuper FROM pg_roles
				WHERE rolname IN ('sentinel_worker', 'sentinel_operator') ORDER BY rolname
				""");

		assertThat(roles).hasSize(2).allSatisfy((row) -> {
			assertThat(row).containsEntry("rolcanlogin", false).containsEntry("rolsuper", false);
		});
		assertThat(jdbcTemplate.queryForObject(
				"SELECT has_table_privilege('sentinel_worker', 'public.scans', 'SELECT')", Boolean.class))
			.isFalse();
		assertThat(jdbcTemplate.queryForObject(
				"SELECT has_function_privilege('sentinel_worker', 'worker.record_receipt(jsonb)', 'EXECUTE')",
				Boolean.class))
			.isTrue();
	}

	@Test
	void hibernateValidatesButDoesNotModifySchema() {
		assertThat(entityManagerFactory.getProperties()).containsEntry("hibernate.hbm2ddl.auto", "validate");

		List<String> tables = jdbcTemplate.queryForList(
				"SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
				String.class);

		// Exactly the tables created by Flyway migrations; Hibernate creates none.
		assertThat(tables).containsExactly("flyway_schema_history", "organization_memberships", "organizations",
				"outbox_events", "platform_metadata", "projects", "scan_jobs", "scans", "user_identities");
	}

}

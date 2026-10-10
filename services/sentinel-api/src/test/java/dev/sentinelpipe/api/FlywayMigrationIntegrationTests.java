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

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private EntityManagerFactory entityManagerFactory;

	@Test
	void allMigrationsAreAppliedInOrderToAFreshDatabase() {
		List<Map<String, Object>> history = jdbcTemplate.queryForList(
				"SELECT script, success FROM flyway_schema_history WHERE version IS NOT NULL ORDER BY installed_rank");

		assertThat(history).extracting((row) -> row.get("script"))
			.containsExactly("V001__initial_schema.sql", "V002__core_domain.sql",
					"V003__identity_and_memberships.sql");
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
	}

	@Test
	void hibernateValidatesButDoesNotModifySchema() {
		assertThat(entityManagerFactory.getProperties()).containsEntry("hibernate.hbm2ddl.auto", "validate");

		List<String> tables = jdbcTemplate.queryForList(
				"SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
				String.class);

		// Exactly the tables created by Flyway migrations; Hibernate creates none.
		assertThat(tables).containsExactly("flyway_schema_history", "organization_memberships", "organizations",
				"platform_metadata", "projects", "scan_jobs", "scans", "user_identities");
	}

}

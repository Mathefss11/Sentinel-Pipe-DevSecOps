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
	void initialMigrationIsAppliedSuccessfully() {
		List<Map<String, Object>> history = jdbcTemplate.queryForList(
				"SELECT script, success FROM flyway_schema_history WHERE version IS NOT NULL ORDER BY installed_rank");

		assertThat(history).hasSize(1);
		assertThat(history.getFirst()).containsEntry("script", "V001__initial_schema.sql")
			.containsEntry("success", true);
		assertThat(flyway.info().pending()).isEmpty();
	}

	@Test
	void baselineMetadataIsRecorded() {
		String baseline = jdbcTemplate.queryForObject(
				"SELECT metadata_value FROM platform_metadata WHERE metadata_key = 'schema.baseline'", String.class);

		assertThat(baseline).isEqualTo("m1-foundation");
	}

	@Test
	void hibernateValidatesButDoesNotModifySchema() {
		assertThat(entityManagerFactory.getProperties()).containsEntry("hibernate.hbm2ddl.auto", "validate");

		List<String> tables = jdbcTemplate.queryForList(
				"SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
				String.class);

		assertThat(tables).containsExactly("flyway_schema_history", "platform_metadata");
	}

}

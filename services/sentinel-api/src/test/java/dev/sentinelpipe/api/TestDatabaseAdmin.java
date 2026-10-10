package dev.sentinelpipe.api;

import java.sql.DriverManager;
import java.sql.SQLException;
import org.postgresql.Driver;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Superuser access to the test database, for fixtures and assertions only (seeding
 * inconsistent rows, deleting events between tests, reading catalog state). The
 * application under test never uses it: it connects as the least-privileged
 * {@link DatabaseRoles#API_USER}.
 * <p>
 * Deliberately not a {@code JdbcOperations} or {@code DataSource} bean, so Spring Boot's
 * auto-configured, least-privileged {@code JdbcTemplate} and {@code DataSource} remain the
 * application's only ones.
 */
public final class TestDatabaseAdmin {

	private final JdbcTemplate jdbc;

	private final PostgreSQLContainer postgres;

	TestDatabaseAdmin(PostgreSQLContainer postgres) {
		this.postgres = postgres;
		this.jdbc = new JdbcTemplate(
				new SimpleDriverDataSource(new Driver(), postgres.getJdbcUrl(), postgres.getUsername(),
						postgres.getPassword()));
	}

	public JdbcTemplate jdbc() {
		return this.jdbc;
	}

	/** A template connected as {@code user}, for privilege tests. */
	public JdbcTemplate connectAs(String user, String password) {
		return new JdbcTemplate(new SimpleDriverDataSource(new Driver(), this.postgres.getJdbcUrl(), user, password));
	}

	/** A raw connection as {@code user}, for tests that control transactions themselves. */
	public java.sql.Connection openConnection(String user, String password) throws SQLException {
		return DriverManager.getConnection(this.postgres.getJdbcUrl(), user, password);
	}

	/** Verifies that {@code user} can open a connection at all. */
	public boolean canConnect(String user, String password) {
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), user, password)) {
			return connection.isValid(5);
		}
		catch (SQLException ex) {
			return false;
		}
	}

}

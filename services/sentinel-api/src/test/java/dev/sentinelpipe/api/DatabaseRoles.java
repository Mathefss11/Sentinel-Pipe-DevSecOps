package dev.sentinelpipe.api;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.ExecConfig;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

/**
 * Database identities for integration tests, created by the production provisioning script
 * ({@code infrastructure/docker/postgres/provision-roles.sh}) exactly as operators run it.
 * The application connects as {@link #API_USER} and migrates as {@link #MIGRATOR_USER};
 * the container's superuser is used only by test fixtures ({@link TestDatabaseAdmin}).
 * <p>
 * Passwords are random per test JVM and passed to the script as environment variables.
 */
public final class DatabaseRoles {

	public static final String MIGRATOR_USER = "sentinel_migrator_app";

	public static final String API_USER = "sentinel_api_app";

	public static final String WORKER_USER = "sentinel_worker_app";

	public static final String OPERATOR_USER = "sentinel_operator_app";

	public static final String MIGRATOR_PASSWORD = newPassword();

	public static final String API_PASSWORD = newPassword();

	public static final String WORKER_PASSWORD = newPassword();

	public static final String OPERATOR_PASSWORD = newPassword();

	private static final Path SCRIPT = Path.of("..", "..", "infrastructure", "docker", "postgres", "provision-roles.sh")
		.toAbsolutePath()
		.normalize();

	private static final String CONTAINER_SCRIPT = "/etc/sentinelpipe/postgres/provision-roles.sh";

	private DatabaseRoles() {
	}

	private static String newPassword() {
		return "t" + UUID.randomUUID().toString().replace("-", "");
	}

	/** Runs the provisioning script in a started container. */
	static void provision(PostgreSQLContainer postgres) {
		provision(postgres, Map.of());
	}

	/**
	 * Runs the provisioning script with additional or overriding environment variables and
	 * returns its result (callers that expect a failure inspect it).
	 */
	public static ExecResult provision(PostgreSQLContainer postgres, Map<String, String> overrides) {
		postgres.copyFileToContainer(MountableFile.forHostPath(SCRIPT), CONTAINER_SCRIPT);
		Map<String, String> environment = new HashMap<>(Map.of("SENTINEL_DB_MIGRATION_USERNAME", MIGRATOR_USER,
				"SENTINEL_DB_MIGRATION_PASSWORD", MIGRATOR_PASSWORD, "SENTINEL_DB_USERNAME", API_USER,
				"SENTINEL_DB_PASSWORD", API_PASSWORD, "SENTINEL_WORKER_DB_USERNAME", WORKER_USER,
				"SENTINEL_WORKER_DB_PASSWORD", WORKER_PASSWORD, "SENTINEL_OPERATOR_DB_USERNAME", OPERATOR_USER,
				"SENTINEL_OPERATOR_DB_PASSWORD", OPERATOR_PASSWORD));
		environment.putAll(overrides);
		try {
			ExecResult result = postgres.execInContainer(ExecConfig.builder()
				.command(new String[] { "sh", CONTAINER_SCRIPT })
				.envVars(environment)
				.build());
			if (overrides.isEmpty() && result.getExitCode() != 0) {
				throw new IllegalStateException("provision-roles.sh failed: " + result.getStderr());
			}
			return result;
		}
		catch (java.io.IOException ex) {
			throw new IllegalStateException("provision-roles.sh could not be executed", ex);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("interrupted while provisioning database roles", ex);
		}
	}

}

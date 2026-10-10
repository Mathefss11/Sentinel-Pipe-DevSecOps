package dev.sentinelpipe.api;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.rabbitmq.RabbitMQContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration test infrastructure. Images are pinned to the same digests as the
 * repository's {@code compose.yaml} so tests and local development run identical images.
 * Testcontainers does not accept the combined {@code name:tag@digest} form, so the
 * images are referenced by digest only.
 * <p>
 * PostgreSQL is provisioned like a deployment ({@link DatabaseRoles}): the application
 * runs as the least-privileged API login and Flyway as the migrator login (switching to
 * {@code sentinel_owner}). The container superuser is reachable only through
 * {@link TestDatabaseAdmin}. A {@code @ServiceConnection} is therefore not used for
 * PostgreSQL: it would connect the application as the superuser.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

	// postgres:18.6-alpine
	static final DockerImageName POSTGRES_IMAGE = DockerImageName
		.parse("postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873");

	// rabbitmq:4.3.6-management-alpine
	static final DockerImageName RABBITMQ_IMAGE = DockerImageName
		.parse("rabbitmq@sha256:3ef7f7e89fed709a78f79b8b5f4e30e1312a1d4089da752e23595566d9d61a95");

	@Bean
	PostgreSQLContainer postgresContainer() {
		PostgreSQLContainer postgres = new PostgreSQLContainer(POSTGRES_IMAGE);
		// Roles must exist before Flyway runs, so the container is started here.
		postgres.start();
		DatabaseRoles.provision(postgres);
		return postgres;
	}

	@Bean
	DynamicPropertyRegistrar databaseConnections(PostgreSQLContainer postgres) {
		return (registry) -> {
			registry.add("spring.datasource.url", postgres::getJdbcUrl);
			registry.add("spring.datasource.username", () -> DatabaseRoles.API_USER);
			registry.add("spring.datasource.password", () -> DatabaseRoles.API_PASSWORD);
			registry.add("spring.flyway.user", () -> DatabaseRoles.MIGRATOR_USER);
			registry.add("spring.flyway.password", () -> DatabaseRoles.MIGRATOR_PASSWORD);
		};
	}

	@Bean
	TestDatabaseAdmin testDatabaseAdmin(PostgreSQLContainer postgres) {
		return new TestDatabaseAdmin(postgres);
	}

	@Bean
	@ServiceConnection
	RabbitMQContainer rabbitContainer() {
		return new RabbitMQContainer(RABBITMQ_IMAGE);
	}

}

package dev.sentinelpipe.api;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.rabbitmq.RabbitMQContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration test infrastructure. Images are pinned to the same digests as the
 * repository's {@code compose.yaml} so tests and local development run identical images.
 * Testcontainers does not accept the combined {@code name:tag@digest} form, so the
 * images are referenced by digest only.
 */
@TestConfiguration(proxyBeanMethods = false)
class TestcontainersConfiguration {

	// postgres:18.6-alpine
	static final DockerImageName POSTGRES_IMAGE = DockerImageName
		.parse("postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873");

	// rabbitmq:4.3.6-management-alpine
	static final DockerImageName RABBITMQ_IMAGE = DockerImageName
		.parse("rabbitmq@sha256:3ef7f7e89fed709a78f79b8b5f4e30e1312a1d4089da752e23595566d9d61a95");

	@Bean
	@ServiceConnection
	PostgreSQLContainer postgresContainer() {
		return new PostgreSQLContainer(POSTGRES_IMAGE);
	}

	@Bean
	@ServiceConnection
	RabbitMQContainer rabbitContainer() {
		return new RabbitMQContainer(RABBITMQ_IMAGE);
	}

}

package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;

/**
 * With Prometheus explicitly exposed on a separate loopback management port, the scrape
 * endpoint is reachable there (and only there), and carries no identifiers.
 * {@link AutoConfigureMetrics} re-enables metrics export, which Spring Boot tests disable
 * by default.
 */
@AutoConfigureMetrics
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = { "management.server.port=0", "management.server.address=127.0.0.1",
				"management.endpoints.web.exposure.include=health,prometheus",
				"sentinel.messaging.declare-topology=true", "sentinel.messaging.outbox.publisher-enabled=false" })
@Import(TestcontainersConfiguration.class)
class PrometheusEndpointIntegrationTests {

	@LocalServerPort
	private int serverPort;

	@LocalManagementPort
	private int managementPort;

	private final HttpClient client = HttpClient.newHttpClient();

	private HttpResponse<String> get(int port, String path) throws Exception {
		return this.client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
				HttpResponse.BodyHandlers.ofString());
	}

	@Test
	void scrapeIsServedOnTheManagementPortWithOperationalMetrics() throws Exception {
		HttpResponse<String> scrape = get(this.managementPort, "/actuator/prometheus");

		assertThat(scrape.statusCode()).isEqualTo(200);
		assertThat(scrape.body()).contains("sentinel_outbox_events", "sentinel_outbox_oldest_pending_age_seconds",
				"sentinel_outbox_leases_expired")
			.doesNotContainPattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
	}

	@Test
	void scrapeIsNotServedOnTheApplicationPortAndOtherEndpointsStayClosed() throws Exception {
		assertThat(get(this.serverPort, "/actuator/prometheus").statusCode()).isNotEqualTo(200);
		assertThat(get(this.managementPort, "/actuator/env").statusCode()).isNotEqualTo(200);
		assertThat(get(this.managementPort, "/actuator/health").statusCode()).isEqualTo(200);
	}

}

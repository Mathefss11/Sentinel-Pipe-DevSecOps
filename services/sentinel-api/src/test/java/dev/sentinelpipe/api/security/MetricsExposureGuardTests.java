package dev.sentinelpipe.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;

class MetricsExposureGuardTests {

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
		.withUserConfiguration(MetricsExposureGuard.class);

	@Test
	void healthOnlyExposureNeedsNoSeparatePort() {
		assertThatCode(() -> MetricsExposureGuard.verify(Set.of("health"), null, null, null))
			.doesNotThrowAnyException();
		this.contextRunner.run((context) -> assertThat(context).hasNotFailed());
	}

	@ParameterizedTest
	@ValueSource(strings = { "prometheus", "*" })
	void prometheusOnTheApplicationPortIsRejected(String endpoint) {
		assertThatThrownBy(() -> MetricsExposureGuard.verify(Set.of("health", endpoint), null, null, "127.0.0.1"))
			.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> MetricsExposureGuard.verify(Set.of(endpoint), "8080", "8080", "127.0.0.1"))
			.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> MetricsExposureGuard.verify(Set.of(endpoint), null, "8080", "127.0.0.1"))
			.as("default server port")
			.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> MetricsExposureGuard.verify(Set.of(endpoint), "8080", "-1", "127.0.0.1"))
			.isInstanceOf(IllegalStateException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "0.0.0.0", "::", "192.168.1.10", "localhost", "" })
	void prometheusOnANonLoopbackManagementAddressIsRejected(String address) {
		assertThatThrownBy(() -> MetricsExposureGuard.verify(Set.of("prometheus"), "8080", "9464", address))
			.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> MetricsExposureGuard.verify(Set.of("prometheus"), "8080", "9464", null))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void prometheusOnASeparateLoopbackPortIsAccepted() {
		assertThatCode(() -> MetricsExposureGuard.verify(Set.of("health", "prometheus"), "8080", "9464", "127.0.0.1"))
			.doesNotThrowAnyException();
		assertThatCode(() -> MetricsExposureGuard.verify(Set.of("prometheus"), "0", "0", "::1"))
			.as("random ports")
			.doesNotThrowAnyException();
	}

	@Test
	void contextFailsWhenPrometheusIsExposedUnsafely() {
		this.contextRunner.withPropertyValues("management.endpoints.web.exposure.include=health,prometheus")
			.run((context) -> assertThat(context).hasFailed());
		this.contextRunner
			.withPropertyValues("management.endpoints.web.exposure.include=health,prometheus",
					"management.server.port=9464", "management.server.address=0.0.0.0")
			.run((context) -> assertThat(context).hasFailed());
		this.contextRunner
			.withPropertyValues("management.endpoints.web.exposure.include=health, PROMETHEUS",
					"management.server.port=9464", "management.server.address=127.0.0.1")
			.run((context) -> assertThat(context).hasNotFailed());
	}

	@Test
	void scrapeMatcherOnlyMatchesGetOnTheManagementPort() {
		MockEnvironment environment = new MockEnvironment().withProperty("management.server.port", "9464");
		var matcher = MetricsExposureGuard.prometheusScrape(environment);

		assertThat(matcher.matches(request("GET", "/actuator/prometheus", 9464))).isTrue();
		assertThat(matcher.matches(request("GET", "/actuator/prometheus", 8080))).isFalse();
		assertThat(matcher.matches(request("POST", "/actuator/prometheus", 9464))).isFalse();
		assertThat(matcher.matches(request("GET", "/actuator/env", 9464))).isFalse();
		assertThat(MetricsExposureGuard.prometheusScrape(new MockEnvironment())
			.matches(request("GET", "/actuator/prometheus", 8080))).isFalse();
	}

	private static MockHttpServletRequest request(String method, String uri, int localPort) {
		MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
		request.setLocalPort(localPort);
		return request;
	}

}

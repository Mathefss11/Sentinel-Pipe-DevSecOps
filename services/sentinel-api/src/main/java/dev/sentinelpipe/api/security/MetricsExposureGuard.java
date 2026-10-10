package dev.sentinelpipe.api.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Fail-fast guard for the Prometheus scrape endpoint.
 *
 * <p>
 * Metrics are not exposed over HTTP by default (only health is). Exposing
 * {@code prometheus} (or {@code *}) through {@code management.endpoints.web.exposure.include}
 * is permitted only when Actuator runs on a <b>separate management port</b>
 * ({@code management.server.port}, different from {@code server.port}) bound to a
 * <b>literal loopback address</b> ({@code management.server.address}). The scrape
 * endpoint is unauthenticated, so network placement is its access control: a scraper
 * must run on the same host or reach it through an authenticated tunnel or sidecar.
 * Metrics carry no identifiers, payloads or credentials.
 */
@Configuration(proxyBeanMethods = false)
public class MetricsExposureGuard implements InitializingBean {

	static final String EXPOSURE_PROPERTY = "management.endpoints.web.exposure.include";

	private final Environment environment;

	MetricsExposureGuard(Environment environment) {
		this.environment = environment;
	}

	@Override
	public void afterPropertiesSet() {
		verify(exposed(this.environment), this.environment.getProperty("server.port"),
				this.environment.getProperty("management.server.port"),
				this.environment.getProperty("management.server.address"));
	}

	static Set<String> exposed(Environment environment) {
		return Binder.get(environment)
			.bind(EXPOSURE_PROPERTY, Bindable.setOf(String.class))
			.orElse(Set.of())
			.stream()
			.map((id) -> id.strip().toLowerCase(Locale.ROOT))
			.collect(Collectors.toSet());
	}

	static void verify(Set<String> exposed, String serverPort, String managementPort, String managementAddress) {
		if (!exposed.contains("prometheus") && !exposed.contains("*")) {
			return;
		}
		String management = (managementPort != null) ? managementPort.strip() : "";
		String server = (serverPort != null && !serverPort.isBlank()) ? serverPort.strip() : "8080";
		// Port 0 means "a random free port": distinct from the server's random port.
		if (management.isEmpty() || management.equals("-1") || (!management.equals("0") && management.equals(server))) {
			throw new IllegalStateException("Exposing the prometheus endpoint requires a separate "
					+ "management.server.port. See docs/runbooks/observability.md.");
		}
		if (!DomainApiExposureGuard.isLiteralLoopbackAddress(managementAddress)) {
			throw new IllegalStateException("Exposing the prometheus endpoint requires management.server.address "
					+ "to be a literal loopback IP address. See docs/runbooks/observability.md.");
		}
	}

	/**
	 * Matches GET scrape requests to {@code /actuator/prometheus} received on the
	 * management port (the bound port, also when configured as 0 for a random port).
	 * Matches nothing when no separate management port is configured.
	 */
	static RequestMatcher prometheusScrape(Environment environment) {
		String basePath = environment.getProperty("management.endpoints.web.base-path", "/actuator");
		return (HttpServletRequest request) -> {
			Integer configured = environment.getProperty("management.server.port", Integer.class);
			if (configured == null || configured < 0) {
				return false;
			}
			int port = environment.getProperty("local.management.port", Integer.class, configured);
			return port > 0 && request.getLocalPort() == port && "GET".equals(request.getMethod())
					&& (basePath + "/prometheus").equals(request.getRequestURI());
		};
	}

}

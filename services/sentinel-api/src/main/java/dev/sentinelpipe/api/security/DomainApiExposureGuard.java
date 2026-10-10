package dev.sentinelpipe.api.security;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Fail-fast guard for the unauthenticated, development-only domain REST API.
 *
 * <p>
 * Active only when {@code sentinel.domain-api.enabled=true}. Startup is aborted unless:
 * <ul>
 * <li>{@code server.address} is explicitly set to a literal loopback IP address
 * ({@code 127.0.0.0/8} or {@code ::1}). Host names are rejected because their resolution
 * is environment-dependent;</li>
 * <li>no production-like profile ({@code prod}, {@code production}) is active.</li>
 * </ul>
 *
 * <p>
 * This is a development safety net, not an access control mechanism: any local process
 * (or a reverse proxy on the same host) can still reach a loopback-bound server.
 * Production-grade authentication and tenant authorization are required before the
 * domain API may be exposed. See ADR-0002.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnDomainApiEnabled
public class DomainApiExposureGuard implements InitializingBean {

	public static final String ENABLED_PROPERTY = "sentinel.domain-api.enabled";

	static final List<String> FORBIDDEN_PROFILES = List.of("prod", "production");

	private static final Logger log = LoggerFactory.getLogger(DomainApiExposureGuard.class);

	private static final Pattern IPV4_LOOPBACK = Pattern
		.compile("^127\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){2}$");

	private static final List<String> IPV6_LOOPBACK = List.of("::1", "[::1]", "0:0:0:0:0:0:0:1");

	private final Environment environment;

	DomainApiExposureGuard(Environment environment) {
		this.environment = environment;
	}

	@Override
	public void afterPropertiesSet() {
		verify(this.environment.getProperty("server.address"), this.environment.getActiveProfiles());
		log.warn("The UNAUTHENTICATED development domain API is enabled ({}=true) on loopback address {}. "
				+ "Never expose it to untrusted networks.", ENABLED_PROPERTY,
				this.environment.getProperty("server.address"));
	}

	static void verify(String serverAddress, String[] activeProfiles) {
		if (!isLiteralLoopbackAddress(serverAddress)) {
			throw new IllegalStateException(ENABLED_PROPERTY + "=true requires server.address to be a literal "
					+ "loopback IP address (for example 127.0.0.1). The domain API has no authentication.");
		}
		boolean productionProfile = Arrays.stream(activeProfiles)
			.map((profile) -> profile.toLowerCase(Locale.ROOT))
			.anyMatch(FORBIDDEN_PROFILES::contains);
		if (productionProfile) {
			throw new IllegalStateException(
					ENABLED_PROPERTY + "=true is not permitted with a production profile. "
							+ "The domain API has no authentication.");
		}
	}

	static boolean isLiteralLoopbackAddress(String address) {
		if (address == null) {
			return false;
		}
		String candidate = address.strip();
		return IPV4_LOOPBACK.matcher(candidate).matches() || IPV6_LOOPBACK.contains(candidate);
	}

}

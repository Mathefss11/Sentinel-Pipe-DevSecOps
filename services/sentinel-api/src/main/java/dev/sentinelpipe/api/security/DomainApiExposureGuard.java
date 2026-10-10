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
 * Fail-fast guard for the development-stage domain REST API.
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
 * Requests are authenticated (JWT) and authorized (organization memberships) since M2
 * Phase 2A (ADR-0003). The loopback restriction remains as defense in depth until the
 * remaining production controls (audit, rate limiting, hardened deployment) exist. It is
 * not itself an access control mechanism. See ADR-0002.
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
		log.warn("The development-stage domain API is enabled ({}=true) on loopback address {}. "
				+ "It is not yet approved for exposure to untrusted networks.", ENABLED_PROPERTY,
				this.environment.getProperty("server.address"));
	}

	static void verify(String serverAddress, String[] activeProfiles) {
		if (!isLiteralLoopbackAddress(serverAddress)) {
			throw new IllegalStateException(ENABLED_PROPERTY + "=true requires server.address to be a literal "
					+ "loopback IP address (for example 127.0.0.1). See ADR-0002.");
		}
		boolean productionProfile = Arrays.stream(activeProfiles)
			.map((profile) -> profile.toLowerCase(Locale.ROOT))
			.anyMatch(FORBIDDEN_PROFILES::contains);
		if (productionProfile) {
			throw new IllegalStateException(
					ENABLED_PROPERTY + "=true is not permitted with a production profile. "
							+ "See ADR-0002.");
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

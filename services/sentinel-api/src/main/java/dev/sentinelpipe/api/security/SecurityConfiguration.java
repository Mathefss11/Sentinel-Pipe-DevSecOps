package dev.sentinelpipe.api.security;

import jakarta.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.json.JsonMapper;

/**
 * HTTP security for the control plane. Default deny in every mode.
 *
 * <ul>
 * <li><b>Domain API disabled</b> (default): only the Actuator health endpoints are
 * reachable; every other request is rejected with 403. No authentication mechanism is
 * configured at all.</li>
 * <li><b>Domain API enabled</b>: {@code /api/**} requires a valid bearer access token
 * (OAuth 2.0 Resource Server, JWT); health stays public; everything else is denied.
 * Organization-level authorization is enforced per request against server-side
 * memberships (see {@code dev.sentinelpipe.api.authorization.AccessControl}).</li>
 * </ul>
 *
 * The API is stateless: no sessions, no cookies, no form or basic login. CSRF protection
 * is therefore not applicable and disabled; browsers cannot attach bearer tokens
 * automatically.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableConfigurationProperties(SentinelSecurityProperties.class)
class SecurityConfiguration {

	private static final String[] HEALTH_ENDPOINTS = { "/actuator/health", "/actuator/health/**" };

	@Bean
	@ConditionalOnDomainApiEnabled
	JwtDecoder jwtDecoder(SentinelSecurityProperties properties) {
		return JwtDecoderFactory.create(properties.getJwt());
	}

	@Bean
	@ConditionalOnDomainApiEnabled
	SecurityFilterChain domainApiSecurityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder, JsonMapper jsonMapper)
			throws Exception {
		statelessApi(http);
		var entryPoint = ProblemSecurityHandlers.bearerEntryPoint(jsonMapper);
		var accessDenied = ProblemSecurityHandlers.accessDeniedHandler(jsonMapper);
		http.authorizeHttpRequests((requests) -> requests.dispatcherTypeMatchers(DispatcherType.ERROR)
			.permitAll()
			.requestMatchers(HttpMethod.GET, HEALTH_ENDPOINTS)
			.permitAll()
			.requestMatchers("/api/**")
			.authenticated()
			.anyRequest()
			.denyAll())
			.oauth2ResourceServer((resourceServer) -> resourceServer.jwt((jwt) -> jwt.decoder(jwtDecoder))
				.authenticationEntryPoint(entryPoint)
				.accessDeniedHandler(accessDenied))
			.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(entryPoint)
				.accessDeniedHandler(accessDenied));
		return http.build();
	}

	@Bean
	@ConditionalOnBooleanProperty(name = DomainApiExposureGuard.ENABLED_PROPERTY, havingValue = false,
			matchIfMissing = true)
	SecurityFilterChain defaultDenySecurityFilterChain(HttpSecurity http, JsonMapper jsonMapper) throws Exception {
		statelessApi(http);
		http.authorizeHttpRequests((requests) -> requests.dispatcherTypeMatchers(DispatcherType.ERROR)
			.permitAll()
			.requestMatchers(HttpMethod.GET, HEALTH_ENDPOINTS)
			.permitAll()
			.anyRequest()
			.denyAll())
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(ProblemSecurityHandlers.denyEntryPoint(jsonMapper))
				.accessDeniedHandler(ProblemSecurityHandlers.accessDeniedHandler(jsonMapper)));
		return http.build();
	}

	private static void statelessApi(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.logout(AbstractHttpConfigurer::disable)
			.requestCache(AbstractHttpConfigurer::disable)
			.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
	}

}

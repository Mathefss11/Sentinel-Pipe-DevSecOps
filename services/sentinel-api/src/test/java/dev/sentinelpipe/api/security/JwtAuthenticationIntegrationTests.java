package dev.sentinelpipe.api.security;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import java.time.Instant;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * Token validation through the real filter chain and production decoder configuration.
 */
class JwtAuthenticationIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final String ME = "/api/v1/me";

	@Test
	void validTokenAuthenticatesTheCaller() throws Exception {
		this.anonymousMvc.perform(get(ME).header(HttpHeaders.AUTHORIZATION, TestJwts.bearer("alice")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.issuer").value(TestJwts.ISSUER))
			.andExpect(jsonPath("$.subject").value("alice"))
			.andExpect(jsonPath("$.platformAdmin").value(false))
			.andExpect(jsonPath("$.memberships").isEmpty());
	}

	/** RFC 7515 media-type comparison is case-insensitive; the full media type is equivalent. */
	@ParameterizedTest
	@org.junit.jupiter.params.provider.ValueSource(strings = { "at+jwt", "AT+JWT", "application/at+jwt" })
	void acceptsRfc9068AccessTokenTypeVariants(String type) throws Exception {
		this.anonymousMvc
			.perform(get(ME).header(HttpHeaders.AUTHORIZATION, TestJwts.token("alice").type(type).bearer()))
			.andExpect(status().isOk());
	}

	@Test
	void missingTokenIsUnauthorizedWithProblemDetails() throws Exception {
		this.anonymousMvc.perform(get(ME))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:unauthorized"))
			.andExpect(jsonPath("$.status").value(401));
	}

	static Stream<Arguments> invalidTokens() {
		Instant now = Instant.now();
		return Stream.of(Arguments.of("expired", TestJwts.token("alice").expiresAt(now.minusSeconds(120)).serialize()),
				Arguments.of("not yet valid", TestJwts.token("alice").notBefore(now.plusSeconds(600)).serialize()),
				Arguments.of("missing exp", TestJwts.token("alice").withoutExpiry().serialize()),
				Arguments.of("wrong issuer",
						TestJwts.token("alice").issuer("https://evil.example/realms/test").serialize()),
				Arguments.of("issuer with trailing slash", TestJwts.token("alice").issuer(TestJwts.ISSUER + "/").serialize()),
				Arguments.of("wrong audience", TestJwts.token("alice").audience("another-api").serialize()),
				Arguments.of("ID token type", TestJwts.token("alice").type("JWT").serialize()),
				Arguments.of("missing typ", TestJwts.token("alice").type(null).serialize()),
				Arguments.of("signed by another key", TestJwts.token("alice").signedWithForeignKey().serialize()),
				Arguments.of("unsigned alg none", TestJwts.unsigned("alice")),
				Arguments.of("HS256 with the public key as secret", TestJwts.hmacSignedWithPublicKey("alice")),
				Arguments.of("missing sub", TestJwts.token(null).serialize()),
				Arguments.of("blank sub", TestJwts.token("   ").serialize()),
				Arguments.of("control characters in sub", TestJwts.token("alice\nadmin").serialize()),
				Arguments.of("overlong sub", TestJwts.token("a".repeat(256)).serialize()),
				Arguments.of("tampered payload", tamper(TestJwts.token("alice").serialize())),
				Arguments.of("garbage", "not.a.jwt"));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("invalidTokens")
	void invalidTokensAreRejectedWithoutRevealingTheReason(String description, String token) throws Exception {
		this.anonymousMvc.perform(get(ME).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""))
			.andExpect(jsonPath("$.detail").value("A valid bearer access token is required."))
			.andExpect(content().string(not(containsString("expired"))))
			.andExpect(content().string(not(containsString("Jwt"))));
	}

	@Test
	void tokenAcceptedOnlyFromTheAuthorizationHeader() throws Exception {
		String token = TestJwts.token("alice").serialize();
		this.anonymousMvc.perform(get(ME).param("access_token", token)).andExpect(status().isUnauthorized());
		this.anonymousMvc.perform(get(ME).header(HttpHeaders.AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void tokenClaimsCannotGrantRolesOrTenantAccess() throws Exception {
		String token = TestJwts.token("claims-attacker")
			.claim("roles", java.util.List.of("OWNER", "PLATFORM_ADMIN"))
			.claim("org_id", "00000000-0000-0000-0000-000000000000")
			.claim("scope", "admin")
			.bearer();

		this.anonymousMvc.perform(get(ME).header(HttpHeaders.AUTHORIZATION, token))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.platformAdmin").value(false))
			.andExpect(jsonPath("$.memberships").isEmpty());
		this.anonymousMvc
			.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/organizations")
				.header(HttpHeaders.AUTHORIZATION, token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"name\": \"x\", \"slug\": \"%s\"}".formatted(uniqueSlug("claims"))))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("platform-admin-required"));
	}

	@Test
	void healthStaysPublicAndOtherPathsAreDenied() throws Exception {
		this.anonymousMvc.perform(get("/actuator/health")).andExpect(status().isOk());
		this.anonymousMvc.perform(get("/actuator/env").header(HttpHeaders.AUTHORIZATION, TestJwts.bearer("alice")))
			.andExpect(status().isForbidden());
		this.anonymousMvc.perform(get("/internal/anything")).andExpect(status().isUnauthorized());
	}

	@Test
	void noSessionIsCreated() throws Exception {
		this.anonymousMvc.perform(get(ME).header(HttpHeaders.AUTHORIZATION, TestJwts.bearer("alice")))
			.andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
	}

	private static String tamper(String jwt) {
		String[] parts = jwt.split("\\.");
		String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]),
				java.nio.charset.StandardCharsets.UTF_8)
			.replace("\"alice\"", "\"bob\"");
		return parts[0] + "."
				+ java.util.Base64.getUrlEncoder()
					.withoutPadding()
					.encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8))
				+ "." + parts[2];
	}

}

package dev.sentinelpipe.api.security;

import dev.sentinelpipe.api.identity.IdentityClaims;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * Builds the access-token decoder from {@link SentinelSecurityProperties}.
 *
 * <p>
 * Every accepted token must:
 * <ul>
 * <li>be a JWS signed with an allow-listed <b>asymmetric</b> algorithm and verified with
 * the identity provider's public keys (unsigned and HMAC tokens are rejected);</li>
 * <li>carry an allow-listed JOSE {@code typ} header ({@code at+jwt} by default, so ID
 * tokens are not accepted as access tokens);</li>
 * <li>have exactly the configured {@code iss}, contain the configured audience in
 * {@code aud}, and carry an {@code exp} claim that has not passed;</li>
 * <li>have a valid {@code sub} claim.</li>
 * </ul>
 * Misconfiguration fails application startup.
 */
final class JwtDecoderFactory {

	private static final Set<SignatureAlgorithm> ASYMMETRIC_ALGORITHMS = Set.of(SignatureAlgorithm.RS256,
			SignatureAlgorithm.RS384, SignatureAlgorithm.RS512, SignatureAlgorithm.ES256, SignatureAlgorithm.ES384,
			SignatureAlgorithm.ES512, SignatureAlgorithm.PS256, SignatureAlgorithm.PS384, SignatureAlgorithm.PS512);

	private static final Duration JWK_SET_TIMEOUT = Duration.ofSeconds(5);

	private JwtDecoderFactory() {
	}

	static NimbusJwtDecoder create(SentinelSecurityProperties.Jwt properties) {
		validate(properties);
		Set<SignatureAlgorithm> algorithms = algorithms(properties);
		NimbusJwtDecoder decoder;
		if (properties.getJwkSetUri() != null) {
			decoder = NimbusJwtDecoder.withJwkSetUri(properties.getJwkSetUri().toString())
				.restOperations(jwkSetClient())
				.jwsAlgorithms((allowed) -> {
					allowed.clear();
					allowed.addAll(algorithms);
				})
				// The `typ` header is checked by JwtTypeValidator below.
				.validateType(false)
				.build();
		}
		else {
			if (algorithms.stream().anyMatch((algorithm) -> !algorithm.getName().startsWith("RS"))) {
				throw new IllegalStateException(
						"sentinel.security.jwt.public-key-location supports RSA keys with RS256/RS384/RS512 only");
			}
			decoder = NimbusJwtDecoder.withPublicKey(readRsaPublicKey(properties))
				.signatureAlgorithm(algorithms.iterator().next())
				.validateType(false)
				.build();
		}
		decoder.setJwtValidator(validator(properties));
		return decoder;
	}

	static OAuth2TokenValidator<Jwt> validator(SentinelSecurityProperties.Jwt properties) {
		JwtTimestampValidator timestamps = new JwtTimestampValidator(properties.getClockSkew());
		timestamps.setAllowEmptyExpiryClaim(false);
		List<String> tokenTypes = new ArrayList<>();
		for (String type : properties.getTokenTypes()) {
			tokenTypes.add(type);
			tokenTypes.add("application/" + type);
		}
		JwtTypeValidator types = new JwtTypeValidator(tokenTypes);
		types.setAllowEmpty(false);
		return new DelegatingOAuth2TokenValidator<>(List.of(types, timestamps,
				new JwtIssuerValidator(properties.getIssuer()), new JwtAudienceValidator(properties.getAudience()),
				new JwtClaimValidator<String>("sub", IdentityClaims::isValidSubject)));
	}

	static void validate(SentinelSecurityProperties.Jwt properties) {
		String prefix = "sentinel.security.jwt.";
		if (properties.getIssuer() == null || properties.getIssuer().isBlank()) {
			throw new IllegalStateException(prefix + "issuer must be set when the domain API is enabled");
		}
		if (properties.getAudience() == null || properties.getAudience().isBlank()) {
			throw new IllegalStateException(prefix + "audience must be set when the domain API is enabled");
		}
		boolean hasJwkSet = properties.getJwkSetUri() != null;
		boolean hasPublicKey = properties.getPublicKeyLocation() != null;
		if (hasJwkSet == hasPublicKey) {
			throw new IllegalStateException(
					"Exactly one of " + prefix + "jwk-set-uri and " + prefix + "public-key-location must be set");
		}
		if (hasJwkSet && !isAllowedJwkSetUri(properties.getJwkSetUri())) {
			throw new IllegalStateException(
					prefix + "jwk-set-uri must use https (plain http is only allowed for loopback addresses)");
		}
		if (properties.getTokenTypes() == null || properties.getTokenTypes().isEmpty()) {
			throw new IllegalStateException(prefix + "token-types must not be empty");
		}
		if (properties.getClockSkew() == null || properties.getClockSkew().isNegative()
				|| properties.getClockSkew().toSeconds() > 300) {
			throw new IllegalStateException(prefix + "clock-skew must be between 0 and 5 minutes");
		}
		algorithms(properties);
	}

	static boolean isAllowedJwkSetUri(URI uri) {
		String scheme = (uri.getScheme() != null) ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
		if (scheme.equals("https")) {
			return uri.getHost() != null;
		}
		return scheme.equals("http") && DomainApiExposureGuard.isLiteralLoopbackAddress(uri.getHost());
	}

	/** Bounded timeouts, so a slow identity provider cannot exhaust request threads. */
	private static RestTemplate jwkSetClient() {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(JWK_SET_TIMEOUT);
		requestFactory.setReadTimeout(JWK_SET_TIMEOUT);
		return new RestTemplate(requestFactory);
	}

	private static Set<SignatureAlgorithm> algorithms(SentinelSecurityProperties.Jwt properties) {
		if (properties.getJwsAlgorithms() == null || properties.getJwsAlgorithms().isEmpty()) {
			throw new IllegalStateException("sentinel.security.jwt.jws-algorithms must not be empty");
		}
		Set<SignatureAlgorithm> algorithms = new LinkedHashSet<>();
		for (String name : properties.getJwsAlgorithms()) {
			SignatureAlgorithm algorithm = SignatureAlgorithm.from(name);
			if (algorithm == null || !ASYMMETRIC_ALGORITHMS.contains(algorithm)) {
				throw new IllegalStateException(
						"Unsupported JWS algorithm '" + name + "': only asymmetric RS/ES/PS algorithms are allowed");
			}
			algorithms.add(algorithm);
		}
		return algorithms;
	}

	private static RSAPublicKey readRsaPublicKey(SentinelSecurityProperties.Jwt properties) {
		try (InputStream input = properties.getPublicKeyLocation().getInputStream()) {
			String pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
			String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");
			byte[] der = Base64.getDecoder().decode(base64);
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
		}
		catch (IOException | java.security.GeneralSecurityException | IllegalArgumentException
				| ClassCastException ex) {
			throw new IllegalStateException(
					"sentinel.security.jwt.public-key-location must contain a PEM-encoded RSA public key", ex);
		}
	}

}

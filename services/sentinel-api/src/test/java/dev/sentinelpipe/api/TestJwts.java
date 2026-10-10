package dev.sentinelpipe.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test-only access tokens.
 *
 * <p>
 * The signing key pair is generated in memory when the test JVM starts; no private key is
 * stored in the repository. Only the public key is written to a temporary PEM file, which
 * the application loads through {@code sentinel.security.jwt.public-key-location}, so the
 * production decoder and validators are exercised unchanged. Token claims are
 * deterministic apart from times relative to "now".
 */
public final class TestJwts {

	public static final String ISSUER = "https://idp.sentinelpipe.test/realms/test";

	public static final String AUDIENCE = "sentinel-api";

	/** Configured in {@code sentinel.security.platform-admin-subjects} for tests. */
	public static final String PLATFORM_ADMIN = "platform-admin";

	private static final RSAKey SIGNING_KEY = generateKey("test-signing-key");

	private static final RSAKey FOREIGN_KEY = generateKey("attacker-key");

	private static final Path PUBLIC_KEY_FILE = writePublicKey();

	private TestJwts() {
	}

	public static String publicKeyLocation() {
		return PUBLIC_KEY_FILE.toUri().toString();
	}

	public static Builder token(String subject) {
		return new Builder(subject);
	}

	/** A complete {@code Authorization} header value for a valid token. */
	public static String bearer(String subject) {
		return "Bearer " + token(subject).serialize();
	}

	/** {@code alg: none}: structurally a JWT, but unsigned. */
	public static String unsigned(String subject) {
		Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
		String header = encoder.encodeToString("{\"alg\":\"none\",\"typ\":\"at+jwt\"}".getBytes(StandardCharsets.UTF_8));
		Map<String, Object> claims = token(subject).claims().toJSONObject();
		String payload = encoder.encodeToString(
				com.nimbusds.jose.util.JSONObjectUtils.toJSONString(claims).getBytes(StandardCharsets.UTF_8));
		return header + "." + payload + ".";
	}

	/**
	 * Algorithm-confusion attack: HS256 using the server's <em>public</em> key bytes as the
	 * HMAC secret.
	 */
	public static String hmacSignedWithPublicKey(String subject) {
		try {
			SignedJWT jwt = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("at+jwt")).build(),
					token(subject).claims());
			jwt.sign(new MACSigner(SIGNING_KEY.toRSAPublicKey().getEncoded()));
			return jwt.serialize();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private String type = "at+jwt";

		private RSAKey key = SIGNING_KEY;

		private Builder(String subject) {
			Instant now = Instant.now();
			this.claims.put("iss", ISSUER);
			this.claims.put("aud", List.of(AUDIENCE));
			if (subject != null) {
				this.claims.put("sub", subject);
			}
			this.claims.put("iat", Date.from(now));
			this.claims.put("exp", Date.from(now.plusSeconds(300)));
		}

		public Builder issuer(String issuer) {
			this.claims.put("iss", issuer);
			return this;
		}

		public Builder audience(String... audience) {
			this.claims.put("aud", List.of(audience));
			return this;
		}

		public Builder expiresAt(Instant expiresAt) {
			this.claims.put("exp", Date.from(expiresAt));
			return this;
		}

		public Builder withoutExpiry() {
			this.claims.remove("exp");
			return this;
		}

		public Builder notBefore(Instant notBefore) {
			this.claims.put("nbf", Date.from(notBefore));
			return this;
		}

		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/** JOSE {@code typ} header; {@code null} omits it. */
		public Builder type(String type) {
			this.type = type;
			return this;
		}

		public Builder signedWithForeignKey() {
			this.key = FOREIGN_KEY;
			return this;
		}

		JWTClaimsSet claims() {
			JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
			this.claims.forEach(builder::claim);
			return builder.build();
		}

		public String serialize() {
			JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(this.key.getKeyID());
			if (this.type != null) {
				header.type(new JOSEObjectType(this.type));
			}
			try {
				SignedJWT jwt = new SignedJWT(header.build(), claims());
				jwt.sign(new RSASSASigner(this.key));
				return jwt.serialize();
			}
			catch (JOSEException ex) {
				throw new IllegalStateException(ex);
			}
		}

		public String bearer() {
			return "Bearer " + serialize();
		}

	}

	private static RSAKey generateKey(String keyId) {
		try {
			return new RSAKeyGenerator(2048).keyID(keyId).generate();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static Path writePublicKey() {
		try {
			byte[] der = SIGNING_KEY.toRSAPublicKey().getEncoded();
			String pem = "-----BEGIN PUBLIC KEY-----\n"
					+ Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
					+ "\n-----END PUBLIC KEY-----\n";
			Path file = Files.createTempFile("sentinel-test-jwt-public", ".pem");
			file.toFile().deleteOnExit();
			Files.writeString(file, pem, StandardCharsets.US_ASCII);
			return file;
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

}

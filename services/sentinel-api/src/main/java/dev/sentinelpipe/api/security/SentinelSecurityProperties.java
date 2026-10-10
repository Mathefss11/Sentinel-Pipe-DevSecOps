package dev.sentinelpipe.api.security;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

/**
 * Identity and authorization settings ({@code sentinel.security.*}).
 *
 * <p>
 * Nothing here is a secret: the signing keys are public keys published by the identity
 * provider. There is deliberately no shared-secret (HMAC) option.
 */
@ConfigurationProperties("sentinel.security")
public class SentinelSecurityProperties {

	private final Jwt jwt = new Jwt();

	/**
	 * Token subjects (of the configured issuer) allowed to create organizations. A
	 * platform administrator has no access to existing organizations; the creator of an
	 * organization becomes its first OWNER. See the bootstrap procedure in the README.
	 */
	private List<String> platformAdminSubjects = new ArrayList<>();

	public Jwt getJwt() {
		return this.jwt;
	}

	public List<String> getPlatformAdminSubjects() {
		return this.platformAdminSubjects;
	}

	public void setPlatformAdminSubjects(List<String> platformAdminSubjects) {
		this.platformAdminSubjects = platformAdminSubjects;
	}

	public static class Jwt {

		/** Exact expected value of the {@code iss} claim. */
		private String issuer;

		/** Value that must be contained in the {@code aud} claim. */
		private String audience;

		/** The identity provider's JWK Set endpoint. HTTPS required (HTTP on loopback only). */
		private URI jwkSetUri;

		/** Alternative to {@code jwk-set-uri}: a PEM-encoded RSA public key. */
		private Resource publicKeyLocation;

		/** Accepted asymmetric JWS algorithms. */
		private Set<String> jwsAlgorithms = Set.of("RS256");

		/** Accepted values of the JOSE {@code typ} header (RFC 9068 access tokens by default). */
		private Set<String> tokenTypes = Set.of("at+jwt");

		/** Tolerated clock skew for {@code exp}, {@code nbf} and {@code iat}. */
		private Duration clockSkew = Duration.ofSeconds(30);

		public String getIssuer() {
			return this.issuer;
		}

		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

		public String getAudience() {
			return this.audience;
		}

		public void setAudience(String audience) {
			this.audience = audience;
		}

		public URI getJwkSetUri() {
			return this.jwkSetUri;
		}

		public void setJwkSetUri(URI jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
		}

		public Resource getPublicKeyLocation() {
			return this.publicKeyLocation;
		}

		public void setPublicKeyLocation(Resource publicKeyLocation) {
			this.publicKeyLocation = publicKeyLocation;
		}

		public Set<String> getJwsAlgorithms() {
			return this.jwsAlgorithms;
		}

		public void setJwsAlgorithms(Set<String> jwsAlgorithms) {
			this.jwsAlgorithms = jwsAlgorithms;
		}

		public Set<String> getTokenTypes() {
			return this.tokenTypes;
		}

		public void setTokenTypes(Set<String> tokenTypes) {
			this.tokenTypes = tokenTypes;
		}

		public Duration getClockSkew() {
			return this.clockSkew;
		}

		public void setClockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
		}

	}

}

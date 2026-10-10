package dev.sentinelpipe.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.TestJwts;
import java.net.URI;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.DefaultResourceLoader;

/** Fail-fast validation of the identity configuration. */
class JwtDecoderFactoryTests {

	private static SentinelSecurityProperties.Jwt valid() {
		SentinelSecurityProperties.Jwt jwt = new SentinelSecurityProperties.Jwt();
		jwt.setIssuer("https://idp.example.com/realms/sentinel");
		jwt.setAudience("sentinel-api");
		jwt.setJwkSetUri(URI.create("https://idp.example.com/realms/sentinel/protocol/openid-connect/certs"));
		return jwt;
	}

	@Test
	void acceptsACompleteConfiguration() {
		assertThatCode(() -> JwtDecoderFactory.validate(valid())).doesNotThrowAnyException();
		assertThat(JwtDecoderFactory.create(valid())).isNotNull();
	}

	@Test
	void requiresIssuerAndAudience() {
		SentinelSecurityProperties.Jwt noIssuer = valid();
		noIssuer.setIssuer(" ");
		SentinelSecurityProperties.Jwt noAudience = valid();
		noAudience.setAudience(null);

		assertThatThrownBy(() -> JwtDecoderFactory.validate(noIssuer)).hasMessageContaining("issuer");
		assertThatThrownBy(() -> JwtDecoderFactory.validate(noAudience)).hasMessageContaining("audience");
	}

	@Test
	void requiresExactlyOneKeySource() {
		SentinelSecurityProperties.Jwt none = valid();
		none.setJwkSetUri(null);
		SentinelSecurityProperties.Jwt both = valid();
		both.setPublicKeyLocation(new ByteArrayResource(new byte[0]));

		assertThatThrownBy(() -> JwtDecoderFactory.validate(none)).hasMessageContaining("Exactly one");
		assertThatThrownBy(() -> JwtDecoderFactory.validate(both)).hasMessageContaining("Exactly one");
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://idp.example.com/certs", "ftp://idp.example.com/certs", "file:///etc/keys",
			"http://localhost/certs", "https:///certs" })
	void rejectsInsecureJwkSetUris(String uri) {
		SentinelSecurityProperties.Jwt jwt = valid();
		jwt.setJwkSetUri(URI.create(uri));

		assertThatThrownBy(() -> JwtDecoderFactory.validate(jwt)).hasMessageContaining("jwk-set-uri");
	}

	@Test
	void allowsPlainHttpOnlyForLiteralLoopbackIdentityProviders() {
		SentinelSecurityProperties.Jwt jwt = valid();
		jwt.setJwkSetUri(URI.create("http://127.0.0.1:8180/realms/dev/protocol/openid-connect/certs"));

		assertThatCode(() -> JwtDecoderFactory.validate(jwt)).doesNotThrowAnyException();
	}

	@ParameterizedTest
	@ValueSource(strings = { "HS256", "HS512", "none", "RS1", "unknown" })
	void rejectsSymmetricOrUnknownAlgorithms(String algorithm) {
		SentinelSecurityProperties.Jwt jwt = valid();
		jwt.setJwsAlgorithms(Set.of(algorithm));

		assertThatThrownBy(() -> JwtDecoderFactory.validate(jwt)).hasMessageContaining("algorithm");
	}

	@Test
	void boundsClockSkewAndRequiresTokenTypes() {
		SentinelSecurityProperties.Jwt skew = valid();
		skew.setClockSkew(Duration.ofMinutes(10));
		SentinelSecurityProperties.Jwt types = valid();
		types.setTokenTypes(Set.of());

		assertThatThrownBy(() -> JwtDecoderFactory.validate(skew)).hasMessageContaining("clock-skew");
		assertThatThrownBy(() -> JwtDecoderFactory.validate(types)).hasMessageContaining("token-types");
	}

	@Test
	void rejectsUnreadablePublicKeys() {
		SentinelSecurityProperties.Jwt jwt = valid();
		jwt.setJwkSetUri(null);
		jwt.setPublicKeyLocation(new ByteArrayResource("-----BEGIN PUBLIC KEY-----\nnot-a-key\n".getBytes()));

		assertThatThrownBy(() -> JwtDecoderFactory.create(jwt)).hasMessageContaining("public-key-location");
	}

	@Test
	void loadsAPemPublicKey() {
		SentinelSecurityProperties.Jwt jwt = valid();
		jwt.setJwkSetUri(null);
		jwt.setPublicKeyLocation(new DefaultResourceLoader().getResource(TestJwts.publicKeyLocation()));

		assertThat(JwtDecoderFactory.create(jwt).decode(TestJwts.token("alice")
			.issuer(jwt.getIssuer())
			.audience(jwt.getAudience())
			.serialize()).getSubject()).isEqualTo("alice");
	}

	@Test
	void applicationFailsToStartWhenTheDomainApiIsEnabledWithoutIdentityConfiguration() {
		new ApplicationContextRunner().withUserConfiguration(SecurityConfigurationProbe.class)
			.withPropertyValues("sentinel.domain-api.enabled=true")
			.run((context) -> assertThat(context).hasFailed()
				.getFailure()
				.rootCause()
				.hasMessageContaining("sentinel.security.jwt.issuer"));
	}

	@org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
	@org.springframework.boot.context.properties.EnableConfigurationProperties(SentinelSecurityProperties.class)
	static class SecurityConfigurationProbe {

		@org.springframework.context.annotation.Bean
		@ConditionalOnDomainApiEnabled
		org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder(SentinelSecurityProperties properties) {
			return JwtDecoderFactory.create(properties.getJwt());
		}

	}

}

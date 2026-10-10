package dev.sentinelpipe.api.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.identity.AuthenticatedPrincipal;
import dev.sentinelpipe.api.security.SentinelSecurityProperties;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Platform administrators are matched on the exact (issuer, subject) pair. Subjects are
 * opaque, issuer-scoped identifiers; e-mail addresses or user names are never used.
 */
class PlatformAdministratorTests {

	private static final String ISSUER = "https://idp.example.com/realms/sentinel";

	private final AccessControl accessControl = new AccessControl(null, null, null, properties());

	private static SentinelSecurityProperties properties() {
		SentinelSecurityProperties properties = new SentinelSecurityProperties();
		properties.getJwt().setIssuer(ISSUER);
		properties.setPlatformAdminSubjects(List.of("8f14e45f-ceea-467a-9b36-0d3c3a2f1e11"));
		return properties;
	}

	@Test
	void matchesTheExactIssuerAndSubject() {
		assertThat(this.accessControl
			.isPlatformAdmin(new AuthenticatedPrincipal(ISSUER, "8f14e45f-ceea-467a-9b36-0d3c3a2f1e11"))).isTrue();
	}

	@Test
	void rejectsTheSameSubjectFromAnotherIssuer() {
		assertThat(this.accessControl.isPlatformAdmin(
				new AuthenticatedPrincipal("https://evil.example/realms/sentinel", "8f14e45f-ceea-467a-9b36-0d3c3a2f1e11")))
			.isFalse();
		assertThat(this.accessControl
			.isPlatformAdmin(new AuthenticatedPrincipal(ISSUER + "/", "8f14e45f-ceea-467a-9b36-0d3c3a2f1e11")))
			.isFalse();
	}

	@Test
	void rejectsSimilarOrCaseVariantSubjects() {
		for (String subject : List.of("8F14E45F-CEEA-467A-9B36-0D3C3A2F1E11", "8f14e45f-ceea-467a-9b36-0d3c3a2f1e11 ",
				"8f14e45f", "admin@example.com", "")) {
			assertThat(this.accessControl.isPlatformAdmin(new AuthenticatedPrincipal(ISSUER, subject))).as(subject)
				.isFalse();
		}
	}

	@Test
	void nobodyIsAPlatformAdministratorWhenNoneIsConfigured() {
		SentinelSecurityProperties properties = properties();
		properties.setPlatformAdminSubjects(List.of());
		AccessControl unconfigured = new AccessControl(null, null, null, properties);

		assertThat(unconfigured.isPlatformAdmin(new AuthenticatedPrincipal(ISSUER, "8f14e45f-ceea-467a-9b36-0d3c3a2f1e11")))
			.isFalse();
	}

}

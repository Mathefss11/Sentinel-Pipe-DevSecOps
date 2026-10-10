package dev.sentinelpipe.api.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.common.DomainValidationException;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OrganizationTests {

	private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");

	@Test
	void createsOrganizationWithServerGeneratedIdentityAndTimestamps() {
		Organization organization = Organization.create("  Acme Security  ", "acme-security", NOW);

		assertThat(organization.getId()).isNotNull();
		assertThat(organization.getName()).isEqualTo("Acme Security");
		assertThat(organization.getSlug()).isEqualTo("acme-security");
		assertThat(organization.getCreatedAt()).isEqualTo(NOW);
		assertThat(organization.getUpdatedAt()).isEqualTo(NOW);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "Acme", "acme_security", "-acme", "acme-", "acme--security", "acme security",
			"acme.security", "ácme" })
	void rejectsInvalidSlugs(String slug) {
		assertThatThrownBy(() -> Organization.create("Acme", slug, NOW)).isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("slug");
	}

	@Test
	void slugLengthIsBounded() {
		assertThat(Organization.create("Acme", "a".repeat(63), NOW).getSlug()).hasSize(63);
		assertThatThrownBy(() -> Organization.create("Acme", "a".repeat(64), NOW))
			.isInstanceOf(DomainValidationException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "   ", "line\nbreak", "null\u0000byte", "escape\u001b[31m" })
	void rejectsBlankNamesAndControlCharacters(String name) {
		assertThatThrownBy(() -> Organization.create(name, "acme", NOW)).isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("name");
	}

	@Test
	void nameLengthIsBounded() {
		assertThatThrownBy(() -> Organization.create("x".repeat(101), "acme", NOW))
			.isInstanceOf(DomainValidationException.class);
	}

}

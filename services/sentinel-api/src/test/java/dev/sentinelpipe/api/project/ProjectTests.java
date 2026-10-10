package dev.sentinelpipe.api.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.common.DomainValidationException;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ProjectTests {

	private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");

	private static final UUID ORGANIZATION_ID = UUID.randomUUID();

	private static Project register(String owner, String name) {
		return Project.register(ORGANIZATION_ID, "Payments", RepositoryProvider.GITHUB, owner, name, "main", NOW);
	}

	@Test
	void normalizesRepositoryIdentityToLowercase() {
		Project project = register("Acme-Corp", "Payments.Service_v2");

		assertThat(project.getRepositoryOwner()).isEqualTo("acme-corp");
		assertThat(project.getRepositoryName()).isEqualTo("payments.service_v2");
		assertThat(project.getOrganizationId()).isEqualTo(ORGANIZATION_ID);
		assertThat(project.isEnabled()).isTrue();
		assertThat(project.getId()).isNotNull();
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "-acme", "acme-", "ac--me", "acme_corp", "acme.corp", "acme/corp", "acme corp",
			"https://github.com/acme", "git@github.com:acme", "../acme", "ácme" })
	void rejectsInvalidOwners(String owner) {
		assertThatThrownBy(() -> register(owner, "repo")).isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("repositoryOwner");
	}

	@Test
	void ownerLengthIsBounded() {
		assertThat(register("a".repeat(39), "repo").getRepositoryOwner()).hasSize(39);
		assertThatThrownBy(() -> register("a".repeat(40), "repo")).isInstanceOf(DomainValidationException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", ".", "..", "repo.git", "Repo.GIT", "repo/name", "../etc", "repo name",
			"https://github.com/acme/repo", "repo?x=1", "repo#frag", "repo%2f", "rëpo" })
	void rejectsInvalidRepositoryNames(String name) {
		assertThatThrownBy(() -> register("acme", name)).isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("repositoryName");
	}

	@Test
	void acceptsDotPrefixedRepositoryNamesUsedByGitHub() {
		assertThat(register("acme", ".github").getRepositoryName()).isEqualTo(".github");
	}

	@Test
	void rejectsInvalidDefaultBranch() {
		assertThatThrownBy(() -> Project.register(ORGANIZATION_ID, "Payments", RepositoryProvider.GITHUB, "acme",
				"repo", "refs/heads/main", NOW))
			.isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("defaultBranch");
	}

	@Test
	void requiresAProvider() {
		assertThatThrownBy(
				() -> Project.register(ORGANIZATION_ID, "Payments", null, "acme", "repo", "main", NOW))
			.isInstanceOf(DomainValidationException.class);
	}

}

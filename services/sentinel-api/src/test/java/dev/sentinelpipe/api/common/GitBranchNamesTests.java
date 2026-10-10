package dev.sentinelpipe.api.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GitBranchNamesTests {

	@ParameterizedTest
	@ValueSource(strings = { "main", "develop", "feature/login", "release-1.2.3", "fix_bug", "user/name/topic",
			"v1.0.x", "Feature/CamelCase", "a" })
	void acceptsConventionalBranchNames(String name) {
		assertThat(GitBranchNames.isValid(name)).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "-leading-dash", "/leading-slash", "trailing-slash/", "double..dot", "double//slash",
			".hidden", "dir/.hidden", "name.lock", "dir/name.lock/x", "refs/heads/main", "HEAD", "trailing-dot.",
			"with space", "tilde~1", "caret^", "colon:x", "question?", "star*", "bracket[", "back\\slash", "at@{1}",
			"new\nline", "tab\tname", "ünicode", "semi;colon", "$(cmd)", "`cmd`" })
	void rejectsUnsafeOrAmbiguousNames(String name) {
		assertThat(GitBranchNames.isValid(name)).isFalse();
	}

	@Test
	void rejectsNullAndOverlongNames() {
		assertThat(GitBranchNames.isValid(null)).isFalse();
		assertThat(GitBranchNames.isValid("a".repeat(255))).isTrue();
		assertThat(GitBranchNames.isValid("a".repeat(256))).isFalse();
	}

	@Test
	void requireReportsTheField() {
		assertThatThrownBy(() -> GitBranchNames.require("branch", "a..b")).isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("branch");
	}

}

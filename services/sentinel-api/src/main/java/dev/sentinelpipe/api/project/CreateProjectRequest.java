package dev.sentinelpipe.api.project;

import dev.sentinelpipe.api.common.DisplayNames;
import dev.sentinelpipe.api.common.GitBranchName;
import dev.sentinelpipe.api.common.GitBranchNames;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

record CreateProjectRequest(
		@NotBlank @Size(max = DisplayNames.MAX_LENGTH) @Pattern(regexp = DisplayNames.NO_CONTROL_CHARACTERS_REGEX,
				message = "must not contain control characters") String name,
		@NotNull RepositoryProvider repositoryProvider,
		@NotNull @Size(min = 1, max = GitHubRepositoryNames.OWNER_MAX_LENGTH) @Pattern(
				regexp = GitHubRepositoryNames.OWNER_INPUT_REGEX,
				message = "must be letters, digits or single hyphens, not starting or ending with a hyphen") String repositoryOwner,
		@NotNull @Size(min = 1, max = GitHubRepositoryNames.NAME_MAX_LENGTH) @Pattern(
				regexp = GitHubRepositoryNames.NAME_INPUT_REGEX,
				message = "must contain only letters, digits, '.', '_' or '-'") String repositoryName,
		@NotNull @Size(max = GitBranchNames.MAX_LENGTH) @GitBranchName String defaultBranch) {
}

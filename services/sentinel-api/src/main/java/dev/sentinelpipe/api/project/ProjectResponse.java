package dev.sentinelpipe.api.project;

import java.time.Instant;
import java.util.UUID;

record ProjectResponse(UUID id, UUID organizationId, String name, RepositoryProvider repositoryProvider,
		String repositoryOwner, String repositoryName, String defaultBranch, boolean enabled, Instant createdAt,
		Instant updatedAt) {

	static ProjectResponse from(Project project) {
		return new ProjectResponse(project.getId(), project.getOrganizationId(), project.getName(),
				project.getRepositoryProvider(), project.getRepositoryOwner(), project.getRepositoryName(),
				project.getDefaultBranch(), project.isEnabled(), project.getCreatedAt(), project.getUpdatedAt());
	}

}

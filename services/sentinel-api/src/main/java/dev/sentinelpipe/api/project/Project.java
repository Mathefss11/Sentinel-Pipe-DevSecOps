package dev.sentinelpipe.api.project;

import dev.sentinelpipe.api.common.DisplayNames;
import dev.sentinelpipe.api.common.DomainValidationException;
import dev.sentinelpipe.api.common.GitBranchNames;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A repository registered for security scanning. Belongs to exactly one organization;
 * the organization is referenced by identifier, not by object association.
 */
@Entity
@Table(name = "projects")
public class Project {

	@Id
	private UUID id;

	@Version
	private Long version;

	@Column(name = "organization_id", nullable = false, updatable = false)
	private UUID organizationId;

	@Column(nullable = false, length = 100)
	private String name;

	@Enumerated(EnumType.STRING)
	@Column(name = "repository_provider", nullable = false, length = 20, updatable = false)
	private RepositoryProvider repositoryProvider;

	@Column(name = "repository_owner", nullable = false, length = 39, updatable = false)
	private String repositoryOwner;

	@Column(name = "repository_name", nullable = false, length = 100, updatable = false)
	private String repositoryName;

	@Column(name = "default_branch", nullable = false, length = 255)
	private String defaultBranch;

	@Column(nullable = false)
	private boolean enabled;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	protected Project() {
		// for JPA
	}

	public static Project register(UUID organizationId, String name, RepositoryProvider provider,
			String repositoryOwner, String repositoryName, String defaultBranch, Instant now) {
		Objects.requireNonNull(organizationId, "organizationId");
		Objects.requireNonNull(now, "now");
		if (provider != RepositoryProvider.GITHUB) {
			throw new DomainValidationException("repositoryProvider", "must be GITHUB");
		}
		Project project = new Project();
		project.id = UUID.randomUUID();
		project.organizationId = organizationId;
		project.name = DisplayNames.normalize("name", name);
		project.repositoryProvider = provider;
		project.repositoryOwner = GitHubRepositoryNames.normalizeOwner(repositoryOwner);
		project.repositoryName = GitHubRepositoryNames.normalizeName(repositoryName);
		project.defaultBranch = GitBranchNames.require("defaultBranch", defaultBranch);
		project.enabled = true;
		project.createdAt = now;
		project.updatedAt = now;
		return project;
	}

	public UUID getId() {
		return this.id;
	}

	public UUID getOrganizationId() {
		return this.organizationId;
	}

	public String getName() {
		return this.name;
	}

	public RepositoryProvider getRepositoryProvider() {
		return this.repositoryProvider;
	}

	public String getRepositoryOwner() {
		return this.repositoryOwner;
	}

	public String getRepositoryName() {
		return this.repositoryName;
	}

	public String getDefaultBranch() {
		return this.defaultBranch;
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public Instant getCreatedAt() {
		return this.createdAt;
	}

	public Instant getUpdatedAt() {
		return this.updatedAt;
	}

}

package dev.sentinelpipe.api.project;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.ConstraintViolations;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.common.Timestamps;
import dev.sentinelpipe.api.organization.OrganizationService;
import java.time.Clock;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProjectService {

	static final String REPOSITORY_ALREADY_REGISTERED = "repository-already-registered";

	static final String PROJECT_DISABLED = "project-disabled";

	private static final Sort LIST_ORDER = Sort.by(Sort.Order.asc("createdAt"), Sort.Order.asc("id"));

	private final ProjectRepository projects;

	private final OrganizationService organizationService;

	private final Clock clock;

	ProjectService(ProjectRepository projects, OrganizationService organizationService, Clock clock) {
		this.projects = projects;
		this.organizationService = organizationService;
		this.clock = clock;
	}

	@Transactional
	public Project register(UUID organizationId, String name, RepositoryProvider provider, String repositoryOwner,
			String repositoryName, String defaultBranch) {
		this.organizationService.requireExists(organizationId);
		Project project = Project.register(organizationId, name, provider, repositoryOwner, repositoryName,
				defaultBranch, Timestamps.now(this.clock));
		if (this.projects.existsByOrganizationIdAndRepositoryProviderAndRepositoryOwnerAndRepositoryName(
				organizationId, project.getRepositoryProvider(), project.getRepositoryOwner(),
				project.getRepositoryName())) {
			throw repositoryAlreadyRegistered();
		}
		try {
			return this.projects.saveAndFlush(project);
		}
		catch (DataIntegrityViolationException ex) {
			if (ConstraintViolations.isViolationOf(ex, "uq_projects_organization_repository")) {
				throw repositoryAlreadyRegistered();
			}
			throw ex;
		}
	}

	@Transactional(readOnly = true)
	public Project get(UUID projectId) {
		return this.projects.findById(projectId)
			.orElseThrow(() -> new ResourceNotFoundException("Project", projectId));
	}

	@Transactional(readOnly = true)
	public Page<Project> listByOrganization(UUID organizationId, int page, int size) {
		this.organizationService.requireExists(organizationId);
		return this.projects.findByOrganizationId(organizationId, PageRequest.of(page, size, LIST_ORDER));
	}

	/** Returns the project if it exists and accepts new scan requests. */
	@Transactional(readOnly = true)
	public Project requireAcceptingScans(UUID projectId) {
		Project project = get(projectId);
		if (!project.isEnabled()) {
			throw new ConflictException(PROJECT_DISABLED, "The project is disabled and does not accept scans.");
		}
		return project;
	}

	@Transactional(readOnly = true)
	public void requireExists(UUID projectId) {
		if (!this.projects.existsById(projectId)) {
			throw new ResourceNotFoundException("Project", projectId);
		}
	}

	private static ConflictException repositoryAlreadyRegistered() {
		return new ConflictException(REPOSITORY_ALREADY_REGISTERED,
				"This repository is already registered in the organization.");
	}

}

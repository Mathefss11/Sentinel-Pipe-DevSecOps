package dev.sentinelpipe.api.project;

import dev.sentinelpipe.api.common.PageResponse;
import dev.sentinelpipe.api.common.Pagination;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1", produces = MediaType.APPLICATION_JSON_VALUE)
class ProjectController {

	private final ProjectService projectService;

	ProjectController(ProjectService projectService) {
		this.projectService = projectService;
	}

	@PostMapping(path = "/organizations/{organizationId}/projects", consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<ProjectResponse> create(@PathVariable("organizationId") UUID organizationId,
			@Valid @RequestBody CreateProjectRequest request) {
		Project project = this.projectService.register(organizationId, request.name(), request.repositoryProvider(),
				request.repositoryOwner(), request.repositoryName(), request.defaultBranch());
		return ResponseEntity.created(URI.create("/api/v1/projects/" + project.getId()))
			.body(ProjectResponse.from(project));
	}

	@GetMapping("/organizations/{organizationId}/projects")
	PageResponse<ProjectResponse> list(@PathVariable("organizationId") UUID organizationId,
			@RequestParam(name = "page", defaultValue = Pagination.DEFAULT_PAGE) @Min(0) @Max(Pagination.MAX_PAGE) int page,
			@RequestParam(name = "size", defaultValue = Pagination.DEFAULT_SIZE) @Min(1) @Max(Pagination.MAX_SIZE) int size) {
		return PageResponse.of(this.projectService.listByOrganization(organizationId, page, size),
				ProjectResponse::from);
	}

	@GetMapping("/projects/{projectId}")
	ProjectResponse get(@PathVariable("projectId") UUID projectId) {
		return ProjectResponse.from(this.projectService.get(projectId));
	}

}

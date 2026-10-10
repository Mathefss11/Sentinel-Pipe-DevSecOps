package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.authorization.AccessControl;
import dev.sentinelpipe.api.authorization.OrganizationPermission;
import dev.sentinelpipe.api.common.PageResponse;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.identity.CurrentPrincipal;
import dev.sentinelpipe.api.identity.UserIdentityService;
import dev.sentinelpipe.api.project.ProjectService;
import dev.sentinelpipe.api.common.Pagination;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scan request, read and cancellation endpoints. Execution transitions are not exposed:
 * they belong to authenticated workers and the supervisor (see {@link ScanLifecycleService}
 * and ADR-0007).
 */
@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1", produces = MediaType.APPLICATION_JSON_VALUE)
class ScanController {

	static final String IDEMPOTENCY_KEY_HEADER = "Idempotency-Key";

	static final String IDEMPOTENT_REPLAYED_HEADER = "Idempotent-Replayed";

	private final ScanService scanService;

	private final ProjectService projectService;

	private final AccessControl accessControl;

	private final ScanLifecycleService lifecycle;

	private final CurrentPrincipal currentPrincipal;

	private final UserIdentityService identities;

	ScanController(ScanService scanService, ProjectService projectService, AccessControl accessControl,
			ScanLifecycleService lifecycle, CurrentPrincipal currentPrincipal, UserIdentityService identities) {
		this.scanService = scanService;
		this.projectService = projectService;
		this.accessControl = accessControl;
		this.lifecycle = lifecycle;
		this.currentPrincipal = currentPrincipal;
		this.identities = identities;
	}

	/** Authorizes against the organization that owns the project; 404 for non-members. */
	private void requireOnProject(UUID projectId, OrganizationPermission permission) {
		UUID organizationId = this.projectService.get(projectId).getOrganizationId();
		this.accessControl.require(organizationId, permission, "Project", projectId);
	}

	/** Returns 202: the scan is queued, not performed, by this request. */
	@PostMapping(path = "/projects/{projectId}/scans", consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<ScanResponse> request(@PathVariable("projectId") UUID projectId,
			@RequestHeader(name = IDEMPOTENCY_KEY_HEADER, required = false) @Pattern(
					regexp = ScanService.IDEMPOTENCY_KEY_REGEX,
					message = "must be 1-128 characters: letters, digits, '.', '_', ':' or '-'") String idempotencyKey,
			@Valid @RequestBody CreateScanRequest request) {
		// Authorization precedes idempotent replay: a key never reveals another tenant's scan.
		requireOnProject(projectId, OrganizationPermission.REQUEST_SCAN);
		ScanService.ScanRequestOutcome outcome = this.scanService.requestScan(projectId, request.commitSha(),
				request.branch(), request.triggerType(), idempotencyKey);
		ScanResponse body = ScanResponse.from(outcome.details());
		return ResponseEntity.accepted()
			.location(URI.create("/api/v1/scans/" + body.id()))
			.header(IDEMPOTENT_REPLAYED_HEADER, Boolean.toString(outcome.replayed()))
			.body(body);
	}

	@GetMapping("/scans/{scanId}")
	ScanResponse get(@PathVariable("scanId") UUID scanId) {
		ScanDetails details = this.scanService.get(scanId);
		UUID organizationId = this.projectService.get(details.scan().getProjectId()).getOrganizationId();
		this.accessControl.require(organizationId, OrganizationPermission.VIEW_SCANS, "Scan", scanId);
		return ScanResponse.from(details);
	}

	/**
	 * Cancels a scan of the project (MEMBER or above). Idempotent: cancelling a cancelled
	 * scan returns it unchanged. A scan of another project, including one in another
	 * organization, is reported as not found. A COMPLETED or FAILED scan cannot be
	 * cancelled (409). Running workers stop at their next heartbeat.
	 */
	@PostMapping("/projects/{projectId}/scans/{scanId}/cancel")
	ScanResponse cancel(@PathVariable("projectId") UUID projectId, @PathVariable("scanId") UUID scanId) {
		requireOnProject(projectId, OrganizationPermission.CANCEL_SCAN);
		if (!this.scanService.get(scanId).scan().getProjectId().equals(projectId)) {
			throw new ResourceNotFoundException("Scan", scanId);
		}
		// The audited actor is the caller's server-side identity, never a request value.
		UUID actor = this.identities.find(this.currentPrincipal.require())
			.orElseThrow(() -> new ResourceNotFoundException("Scan", scanId))
			.getId();
		this.lifecycle.cancelScan(scanId, "user:" + actor);
		return ScanResponse.from(this.scanService.get(scanId));
	}

	@GetMapping("/projects/{projectId}/scans")
	PageResponse<ScanResponse> list(@PathVariable("projectId") UUID projectId,
			@RequestParam(name = "page", defaultValue = Pagination.DEFAULT_PAGE) @Min(0) @Max(Pagination.MAX_PAGE) int page,
			@RequestParam(name = "size", defaultValue = Pagination.DEFAULT_SIZE) @Min(1) @Max(Pagination.MAX_SIZE) int size) {
		requireOnProject(projectId, OrganizationPermission.VIEW_SCANS);
		return PageResponse.of(this.scanService.listByProject(projectId, page, size), ScanResponse::from);
	}

}

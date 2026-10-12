package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.authorization.AccessControl;
import dev.sentinelpipe.api.authorization.OrganizationPermission;
import dev.sentinelpipe.api.common.PageResponse;
import dev.sentinelpipe.api.common.Pagination;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.identity.CurrentPrincipal;
import dev.sentinelpipe.api.identity.UserIdentityService;
import dev.sentinelpipe.api.project.ProjectService;
import dev.sentinelpipe.api.scan.ScanService;
import dev.sentinelpipe.api.scanjob.ScannerType;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Security exceptions with independent approval and the effective security gate
 * (ADR-0015). Every operation authorizes the caller for the organization that owns the scan
 * before reading anything; non-members receive the same 404 as for a scan that does not
 * exist, and a request of another scan is 404. Requester and actor identities are always
 * the caller's server-side identity, never a request value. No operation changes the scan,
 * its decision, its evidence or its evaluations, and none starts a scanner.
 */
@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1/scans/{scanId}", produces = MediaType.APPLICATION_JSON_VALUE)
class ExceptionController {

	/** Text without control characters or line separators, and no leading or trailing whitespace. */
	static final String TEXT = "^\\S(?:[^\\p{Cc}\\p{Zl}\\p{Zp}]*\\S)?$";

	record CreateExceptionRequest(@NotNull ScannerType scanner,
			@NotNull @Pattern(regexp = "^[0-9a-f]{64}$") String findingFingerprint,
			@NotNull @Size(min = 20, max = 2000) @Pattern(regexp = TEXT) String justification,
			@NotNull Instant expiresAt) {
	}

	record ExceptionDecisionRequest(@NotNull @Size(min = 1, max = 1000) @Pattern(regexp = TEXT) String rationale) {
	}

	record FindingResponse(String fingerprint, String ruleId, String category, String scannerSeverity) {
	}

	record TransitionResponse(int sequence, String fromState, String toState, String actor, String actorRole,
			String rationale, Instant occurredAt) {
	}

	record ExceptionResponse(UUID id, UUID scanId, UUID projectId, UUID evaluationId, UUID policyVersionId,
			String policySha256, String engineVersion, String scannerType, UUID jobId, long leaseEpoch,
			String artifactSha256, String resultSha256, FindingResponse finding, String justification,
			String requestedBy, Instant requestedAt, Instant expiresAt, String state, String status,
			Instant statusAsOf, List<TransitionResponse> transitions) {

		static ExceptionResponse from(ExceptionRequestService.ExceptionRecord r) {
			return new ExceptionResponse(r.id(), r.scanId(), r.projectId(), r.evaluationId(), r.policyVersionId(),
					r.policySha256(), r.engineVersion(), r.scannerType(), r.jobId(), r.leaseEpoch(), r.artifactSha256(),
					r.resultSha256(), new FindingResponse(r.fingerprint(), r.ruleId(), r.category(), r.scannerSeverity()),
					r.justification(), r.requestedBy(), r.requestedAt(), r.expiresAt(), r.state(), r.status(),
					r.statusAsOf(),
					r.transitions()
						.stream()
						.map((t) -> new TransitionResponse(t.sequence(), t.fromState(), t.toState(), t.actor(),
								t.actorRole(), t.rationale(), t.occurredAt()))
						.toList());
		}

	}

	record GateReasonResponse(String code, String scanner, Long observed, Long limit) {
	}

	record AppliedExceptionResponse(UUID id, String scannerType, String findingFingerprint, Instant expiresAt) {
	}

	record EffectiveGateResponse(UUID scanId, String executionStatus, String originalDecision, UUID evaluationId,
			String effectiveDecision, boolean exceptionBased, List<GateReasonResponse> reasons,
			List<AppliedExceptionResponse> appliedExceptions, Instant evaluatedAt, Instant validUntil) {

		static EffectiveGateResponse from(EffectiveGateService.EffectiveGate gate) {
			return new EffectiveGateResponse(gate.scanId(), gate.executionStatus(), gate.originalDecision(),
					gate.evaluationId(), gate.effectiveDecision().name(), gate.exceptionBased(),
					gate.reasons()
						.stream()
						.map((r) -> new GateReasonResponse(r.code().name(),
								(r.scanner() != null) ? r.scanner().name() : null, r.observed(), r.limit()))
						.toList(),
					gate.appliedExceptions()
						.stream()
						.map((a) -> new AppliedExceptionResponse(a.id(), a.scannerType().name(), a.fingerprint(),
								a.expiresAt()))
						.toList(),
					gate.evaluatedAt(), gate.validUntil());
		}

	}

	private final ExceptionRequestService exceptions;

	private final EffectiveGateService gates;

	private final ProjectService projects;

	private final ScanService scans;

	private final AccessControl accessControl;

	private final CurrentPrincipal currentPrincipal;

	private final UserIdentityService identities;

	ExceptionController(ExceptionRequestService exceptions, EffectiveGateService gates, ProjectService projects,
			ScanService scans, AccessControl accessControl, CurrentPrincipal currentPrincipal,
			UserIdentityService identities) {
		this.exceptions = exceptions;
		this.gates = gates;
		this.projects = projects;
		this.scans = scans;
		this.accessControl = accessControl;
		this.currentPrincipal = currentPrincipal;
		this.identities = identities;
	}

	/**
	 * Requests an exception for one blocking finding of the scan's original FAIL evaluation
	 * (ADMIN or above). It has no effect until another OWNER approves it.
	 */
	@PostMapping(path = "/exceptions", consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<ExceptionResponse> request(@PathVariable("scanId") UUID scanId,
			@Valid @RequestBody CreateExceptionRequest request) {
		UUID organizationId = requireOnScan(scanId, OrganizationPermission.REQUEST_EXCEPTIONS);
		UUID id = this.exceptions.request(scanId, request.scanner(), request.findingFingerprint(),
				request.justification(), request.expiresAt(), actor(organizationId));
		return ResponseEntity.created(URI.create("/api/v1/scans/" + scanId + "/exceptions/" + id))
			.body(read(scanId, id));
	}

	@GetMapping("/exceptions")
	PageResponse<ExceptionResponse> list(@PathVariable("scanId") UUID scanId,
			@RequestParam(name = "page", defaultValue = Pagination.DEFAULT_PAGE) @Min(0) @Max(Pagination.MAX_PAGE) int page,
			@RequestParam(name = "size", defaultValue = Pagination.DEFAULT_SIZE) @Min(1) @Max(Pagination.MAX_SIZE) int size) {
		requireOnScan(scanId, OrganizationPermission.VIEW_SCANS);
		return PageResponse.of(this.exceptions.list(scanId, page, size), ExceptionResponse::from);
	}

	/** One request with its immutable transition history. */
	@GetMapping("/exceptions/{exceptionId}")
	ExceptionResponse get(@PathVariable("scanId") UUID scanId, @PathVariable("exceptionId") UUID exceptionId) {
		requireOnScan(scanId, OrganizationPermission.VIEW_SCANS);
		return read(scanId, exceptionId);
	}

	/** Approves another person's request (OWNER; never the requester). */
	@PostMapping(path = "/exceptions/{exceptionId}/approve", consumes = MediaType.APPLICATION_JSON_VALUE)
	ExceptionResponse approve(@PathVariable("scanId") UUID scanId, @PathVariable("exceptionId") UUID exceptionId,
			@Valid @RequestBody ExceptionDecisionRequest request) {
		return transition(scanId, exceptionId, ExceptionRequestService.Action.APPROVE,
				OrganizationPermission.DECIDE_EXCEPTIONS, request);
	}

	/** Rejects another person's request (OWNER; never the requester). */
	@PostMapping(path = "/exceptions/{exceptionId}/reject", consumes = MediaType.APPLICATION_JSON_VALUE)
	ExceptionResponse reject(@PathVariable("scanId") UUID scanId, @PathVariable("exceptionId") UUID exceptionId,
			@Valid @RequestBody ExceptionDecisionRequest request) {
		return transition(scanId, exceptionId, ExceptionRequestService.Action.REJECT,
				OrganizationPermission.DECIDE_EXCEPTIONS, request);
	}

	/** Withdraws one's own pending request (its requester, ADMIN or above). */
	@PostMapping(path = "/exceptions/{exceptionId}/withdraw", consumes = MediaType.APPLICATION_JSON_VALUE)
	ExceptionResponse withdraw(@PathVariable("scanId") UUID scanId, @PathVariable("exceptionId") UUID exceptionId,
			@Valid @RequestBody ExceptionDecisionRequest request) {
		return transition(scanId, exceptionId, ExceptionRequestService.Action.WITHDRAW,
				OrganizationPermission.REQUEST_EXCEPTIONS, request);
	}

	/** Revokes an approved exception; it stops applying immediately (OWNER). */
	@PostMapping(path = "/exceptions/{exceptionId}/revoke", consumes = MediaType.APPLICATION_JSON_VALUE)
	ExceptionResponse revoke(@PathVariable("scanId") UUID scanId, @PathVariable("exceptionId") UUID exceptionId,
			@Valid @RequestBody ExceptionDecisionRequest request) {
		return transition(scanId, exceptionId, ExceptionRequestService.Action.REVOKE,
				OrganizationPermission.DECIDE_EXCEPTIONS, request);
	}

	/**
	 * The effective security gate, computed now from the original decision and the active
	 * exceptions. Never cached: an expired or revoked exception stops applying on the next
	 * request.
	 */
	@GetMapping("/gate")
	ResponseEntity<EffectiveGateResponse> gate(@PathVariable("scanId") UUID scanId) {
		requireOnScan(scanId, OrganizationPermission.VIEW_SCANS);
		return ResponseEntity.ok()
			.cacheControl(CacheControl.noStore())
			.body(EffectiveGateResponse.from(this.gates.compute(scanId)));
	}

	private ExceptionResponse transition(UUID scanId, UUID exceptionId, ExceptionRequestService.Action action,
			OrganizationPermission permission, ExceptionDecisionRequest request) {
		UUID organizationId = requireOnScan(scanId, permission);
		this.exceptions.transition(scanId, exceptionId, action, actor(organizationId), request.rationale());
		return read(scanId, exceptionId);
	}

	private ExceptionResponse read(UUID scanId, UUID exceptionId) {
		return ExceptionResponse.from(this.exceptions.find(scanId, exceptionId)
			.orElseThrow(() -> new ResourceNotFoundException("SecurityException", exceptionId)));
	}

	/** Authorizes against the organization that owns the scan; 404 for non-members. */
	private UUID requireOnScan(UUID scanId, OrganizationPermission permission) {
		UUID projectId = this.scans.get(scanId).scan().getProjectId();
		UUID organizationId = this.projects.get(projectId).getOrganizationId();
		this.accessControl.require(organizationId, permission, "Scan", scanId);
		return organizationId;
	}

	/** The audited actor is the caller's server-side identity, never a request value. */
	private String actor(UUID organizationId) {
		UUID identity = this.identities.find(this.currentPrincipal.require())
			.orElseThrow(() -> new ResourceNotFoundException("Organization", organizationId))
			.getId();
		return "user:" + identity;
	}

}

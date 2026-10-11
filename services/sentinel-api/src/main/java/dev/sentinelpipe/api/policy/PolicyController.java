package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.authorization.AccessControl;
import dev.sentinelpipe.api.authorization.OrganizationPermission;
import dev.sentinelpipe.api.common.InvalidDocumentException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.identity.CurrentPrincipal;
import dev.sentinelpipe.api.identity.UserIdentityService;
import dev.sentinelpipe.api.project.ProjectService;
import dev.sentinelpipe.api.scan.ScanService;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

/**
 * Policy versions, project activation and scan evaluation records (ADR-0013). Every
 * operation authorizes the caller for the organization that owns the resource before
 * reading it; non-members receive the same 404 as for a resource that does not exist.
 * Evaluation is not exposed: it is performed by the supervisor, never on request.
 */
@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1", produces = MediaType.APPLICATION_JSON_VALUE)
class PolicyController {

	record PolicyVersionResponse(UUID id, UUID policyId, UUID organizationId, String name, int version,
			int schemaVersion, String definitionSha256, JsonNode definition, Instant createdAt) {

		static PolicyVersionResponse from(PolicyService.PolicyVersion version) {
			return new PolicyVersionResponse(version.id(), version.policyId(), version.organizationId(), version.name(),
					version.version(), version.schemaVersion(), version.definitionSha256(),
					CanonicalJson.parse(version.definition()), version.createdAt());
		}

	}

	record AssignProjectPolicyRequest(@NotNull UUID policyVersionId) {
	}

	record ProjectPolicyResponse(UUID projectId, UUID policyVersionId, UUID policyId, String name, int version,
			String definitionSha256, Instant assignedAt) {

		static ProjectPolicyResponse from(PolicyService.ActivePolicy active) {
			PolicyService.PolicyVersion version = active.policyVersion();
			return new ProjectPolicyResponse(active.projectId(), version.id(), version.policyId(), version.name(),
					version.version(), version.definitionSha256(), active.assignedAt());
		}

	}

	record EvidenceResponse(UUID jobId, String scannerType, long leaseEpoch, String name, String sha256,
			String resultSha256) {
	}

	record PolicyEvaluationResponse(UUID id, UUID scanId, UUID projectId, UUID policyVersionId, String policySha256,
			String engineVersion, String decision, int violationCount, int incompleteCount, JsonNode reasons,
			List<EvidenceResponse> evidence, Instant evaluatedAt, Instant recordedAt) {

		static PolicyEvaluationResponse from(PolicyService.EvaluationRecord record) {
			return new PolicyEvaluationResponse(record.id(), record.scanId(), record.projectId(),
					record.policyVersionId(), record.policySha256(), record.engineVersion(), record.decision(),
					record.violationCount(), record.incompleteCount(), CanonicalJson.parse(record.reasons()),
					record.evidence()
						.stream()
						.map((e) -> new EvidenceResponse(e.jobId(), e.scannerType(), e.leaseEpoch(), e.name(),
								e.sha256(), e.resultSha256()))
						.toList(),
					record.evaluatedAsOf(), record.recordedAt());
		}

	}

	private final PolicyService policies;

	private final ProjectService projects;

	private final ScanService scans;

	private final AccessControl accessControl;

	private final CurrentPrincipal currentPrincipal;

	private final UserIdentityService identities;

	PolicyController(PolicyService policies, ProjectService projects, ScanService scans, AccessControl accessControl,
			CurrentPrincipal currentPrincipal, UserIdentityService identities) {
		this.policies = policies;
		this.projects = projects;
		this.scans = scans;
		this.accessControl = accessControl;
		this.currentPrincipal = currentPrincipal;
		this.identities = identities;
	}

	/**
	 * Creates a new immutable version of the policy named in the definition (ADMIN or
	 * above). The body is the policy.v1 document itself; it is read with a size bound and
	 * parsed strictly here, not by the general request mapper, so oversized bodies are never
	 * buffered and duplicate keys are refused.
	 */
	@PostMapping(path = "/organizations/{organizationId}/policies", consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<PolicyVersionResponse> create(@PathVariable("organizationId") UUID organizationId,
			InputStream body) throws IOException {
		this.accessControl.requireOnOrganization(organizationId, OrganizationPermission.MANAGE_POLICIES);
		PolicyService.PolicyVersion created = this.policies.createVersion(organizationId, boundedUtf8(body),
				actor(organizationId));
		return ResponseEntity.created(URI.create("/api/v1/policy-versions/" + created.id()))
			.body(PolicyVersionResponse.from(created));
	}

	@GetMapping("/policy-versions/{policyVersionId}")
	PolicyVersionResponse get(@PathVariable("policyVersionId") UUID policyVersionId) {
		PolicyService.PolicyVersion version = this.policies.findVersion(policyVersionId)
			.orElseThrow(() -> new ResourceNotFoundException("PolicyVersion", policyVersionId));
		this.accessControl.require(version.organizationId(), OrganizationPermission.VIEW_POLICIES, "PolicyVersion",
				policyVersionId);
		return PolicyVersionResponse.from(version);
	}

	/**
	 * Puts a policy version of the project's organization in force for the project (OWNER).
	 * Scans requested afterwards are evaluated against it; earlier scans keep the version
	 * they were pinned to.
	 */
	@PutMapping(path = "/projects/{projectId}/policy", consumes = MediaType.APPLICATION_JSON_VALUE)
	ProjectPolicyResponse activate(@PathVariable("projectId") UUID projectId,
			@Valid @RequestBody AssignProjectPolicyRequest request) {
		UUID organizationId = this.projects.get(projectId).getOrganizationId();
		this.accessControl.require(organizationId, OrganizationPermission.ACTIVATE_POLICY, "Project", projectId);
		return ProjectPolicyResponse
			.from(this.policies.activate(projectId, request.policyVersionId(), actor(organizationId)));
	}

	@GetMapping("/projects/{projectId}/policy")
	ProjectPolicyResponse active(@PathVariable("projectId") UUID projectId) {
		UUID organizationId = this.projects.get(projectId).getOrganizationId();
		this.accessControl.require(organizationId, OrganizationPermission.VIEW_POLICIES, "Project", projectId);
		return ProjectPolicyResponse.from(this.policies.activePolicy(projectId)
			.orElseThrow(() -> new ResourceNotFoundException("ProjectPolicy", projectId)));
	}

	@GetMapping("/scans/{scanId}/evaluation")
	PolicyEvaluationResponse evaluation(@PathVariable("scanId") UUID scanId) {
		UUID projectId = this.scans.get(scanId).scan().getProjectId();
		UUID organizationId = this.projects.get(projectId).getOrganizationId();
		this.accessControl.require(organizationId, OrganizationPermission.VIEW_SCANS, "Scan", scanId);
		return PolicyEvaluationResponse.from(this.policies.evaluation(scanId)
			.orElseThrow(() -> new ResourceNotFoundException("PolicyEvaluation", scanId)));
	}

	/**
	 * Reads at most {@link PolicyDocuments#MAX_BYTES} bytes of strict UTF-8: a larger body is
	 * refused without buffering it.
	 */
	private static String boundedUtf8(InputStream body) throws IOException {
		byte[] bytes = body.readNBytes(PolicyDocuments.MAX_BYTES + 1);
		if (bytes.length > PolicyDocuments.MAX_BYTES) {
			throw new InvalidDocumentException("definition", "must not exceed " + PolicyDocuments.MAX_BYTES + " bytes");
		}
		try {
			return StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT)
				.decode(ByteBuffer.wrap(bytes))
				.toString();
		}
		catch (CharacterCodingException ex) {
			throw new InvalidDocumentException("definition", "must be UTF-8");
		}
	}

	/** The audited actor is the caller's server-side identity, never a request value. */
	private String actor(UUID organizationId) {
		UUID identity = this.identities.find(this.currentPrincipal.require())
			.orElseThrow(() -> new ResourceNotFoundException("Organization", organizationId))
			.getId();
		return "user:" + identity;
	}

}

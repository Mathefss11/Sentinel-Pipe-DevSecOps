package dev.sentinelpipe.api.authorization;

import dev.sentinelpipe.api.authorization.MembershipDtos.CreateMembershipRequest;
import dev.sentinelpipe.api.authorization.MembershipDtos.MembershipResponse;
import dev.sentinelpipe.api.authorization.MembershipDtos.UpdateMembershipRequest;
import dev.sentinelpipe.api.common.PageResponse;
import dev.sentinelpipe.api.common.Pagination;
import dev.sentinelpipe.api.identity.CurrentPrincipal;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1/organizations/{organizationId}/members", produces = MediaType.APPLICATION_JSON_VALUE)
class MembershipController {

	private final MembershipService membershipService;

	private final AccessControl accessControl;

	private final CurrentPrincipal currentPrincipal;

	MembershipController(MembershipService membershipService, AccessControl accessControl,
			CurrentPrincipal currentPrincipal) {
		this.membershipService = membershipService;
		this.accessControl = accessControl;
		this.currentPrincipal = currentPrincipal;
	}

	@GetMapping
	PageResponse<MembershipResponse> list(@PathVariable("organizationId") UUID organizationId,
			@RequestParam(name = "page", defaultValue = Pagination.DEFAULT_PAGE) @Min(0) @Max(Pagination.MAX_PAGE) int page,
			@RequestParam(name = "size", defaultValue = Pagination.DEFAULT_SIZE) @Min(1) @Max(Pagination.MAX_SIZE) int size) {
		this.accessControl.requireOnOrganization(organizationId, OrganizationPermission.VIEW_MEMBERS);
		return PageResponse.of(this.membershipService.list(organizationId, page, size), MembershipResponse::from);
	}

	@GetMapping("/{membershipId}")
	MembershipResponse get(@PathVariable("organizationId") UUID organizationId,
			@PathVariable("membershipId") UUID membershipId) {
		this.accessControl.require(organizationId, OrganizationPermission.VIEW_MEMBERS, "Membership", membershipId);
		return MembershipResponse.from(this.membershipService.get(organizationId, membershipId));
	}

	@PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<MembershipResponse> grant(@PathVariable("organizationId") UUID organizationId,
			@Valid @RequestBody CreateMembershipRequest request) {
		MembershipResponse body = MembershipResponse.from(this.membershipService.grant(organizationId,
				this.currentPrincipal.require(), request.subject(), request.role()));
		return ResponseEntity
			.created(URI.create("/api/v1/organizations/" + organizationId + "/members/" + body.id()))
			.body(body);
	}

	@PutMapping(path = "/{membershipId}", consumes = MediaType.APPLICATION_JSON_VALUE)
	MembershipResponse changeRole(@PathVariable("organizationId") UUID organizationId,
			@PathVariable("membershipId") UUID membershipId, @Valid @RequestBody UpdateMembershipRequest request) {
		return MembershipResponse.from(this.membershipService.changeRole(organizationId, membershipId,
				this.currentPrincipal.require(), request.role()));
	}

	@DeleteMapping("/{membershipId}")
	ResponseEntity<Void> revoke(@PathVariable("organizationId") UUID organizationId,
			@PathVariable("membershipId") UUID membershipId) {
		this.membershipService.revoke(organizationId, membershipId, this.currentPrincipal.require());
		return ResponseEntity.noContent().build();
	}

}

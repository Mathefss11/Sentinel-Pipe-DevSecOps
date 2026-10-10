package dev.sentinelpipe.api.authorization;

import dev.sentinelpipe.api.authorization.MembershipDtos.CurrentUserResponse;
import dev.sentinelpipe.api.authorization.MembershipDtos.CurrentUserResponse.OrganizationAccess;
import dev.sentinelpipe.api.identity.AuthenticatedPrincipal;
import dev.sentinelpipe.api.identity.CurrentPrincipal;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** The authenticated caller's identity and organization roles. */
@RestController
@ConditionalOnDomainApiEnabled
class CurrentUserController {

	private final CurrentPrincipal currentPrincipal;

	private final MembershipService membershipService;

	private final AccessControl accessControl;

	CurrentUserController(CurrentPrincipal currentPrincipal, MembershipService membershipService,
			AccessControl accessControl) {
		this.currentPrincipal = currentPrincipal;
		this.membershipService = membershipService;
		this.accessControl = accessControl;
	}

	@GetMapping(path = "/api/v1/me", produces = MediaType.APPLICATION_JSON_VALUE)
	CurrentUserResponse me() {
		AuthenticatedPrincipal principal = this.currentPrincipal.require();
		return new CurrentUserResponse(principal.issuer(), principal.subject(),
				this.accessControl.isPlatformAdmin(principal),
				this.membershipService.membershipsOf(principal)
					.stream()
					.map((membership) -> new OrganizationAccess(membership.getOrganizationId(), membership.getRole()))
					.toList());
	}

}

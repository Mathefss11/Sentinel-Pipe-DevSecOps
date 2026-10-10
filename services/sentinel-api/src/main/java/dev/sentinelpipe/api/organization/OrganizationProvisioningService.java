package dev.sentinelpipe.api.organization;

import dev.sentinelpipe.api.authorization.MembershipService;
import dev.sentinelpipe.api.identity.AuthenticatedPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates an organization and makes its creator the first OWNER, atomically. An
 * organization therefore never exists without an owner. Callers must have verified that
 * the creator is a platform administrator.
 */
@Service
class OrganizationProvisioningService {

	private final OrganizationService organizationService;

	private final MembershipService membershipService;

	OrganizationProvisioningService(OrganizationService organizationService, MembershipService membershipService) {
		this.organizationService = organizationService;
		this.membershipService = membershipService;
	}

	@Transactional
	Organization create(String name, String slug, AuthenticatedPrincipal creator) {
		Organization organization = this.organizationService.create(name, slug);
		this.membershipService.bootstrapOwner(organization.getId(), creator);
		return organization;
	}

}

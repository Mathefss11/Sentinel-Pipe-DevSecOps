package dev.sentinelpipe.api.authorization;

import dev.sentinelpipe.api.common.ForbiddenException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.identity.AuthenticatedPrincipal;
import dev.sentinelpipe.api.identity.CurrentPrincipal;
import dev.sentinelpipe.api.identity.UserIdentityService;
import dev.sentinelpipe.api.security.SentinelSecurityProperties;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Organization-level authorization for the current request.
 *
 * <p>
 * Decisions are based only on server-side membership rows for the token's
 * {@code (iss, sub)}; organization or role claims in tokens are ignored. A caller with no
 * membership in the owning organization receives the same 404 as for a resource that does
 * not exist, so knowing a UUID neither grants access nor confirms existence. A member
 * whose role is too low receives 403.
 */
@Service
public class AccessControl {

	static final String INSUFFICIENT_ROLE = "insufficient-role";

	static final String PLATFORM_ADMIN_REQUIRED = "platform-admin-required";

	private final CurrentPrincipal currentPrincipal;

	private final UserIdentityService identities;

	private final MembershipRepository memberships;

	private final SentinelSecurityProperties properties;

	AccessControl(CurrentPrincipal currentPrincipal, UserIdentityService identities,
			MembershipRepository memberships, SentinelSecurityProperties properties) {
		this.currentPrincipal = currentPrincipal;
		this.identities = identities;
		this.memberships = memberships;
		this.properties = properties;
	}

	/**
	 * Requires {@code permission} in the organization that owns the requested resource.
	 * @param resourceType reported in the 404 when the caller is not a member, e.g.
	 * {@code "Project"}
	 * @param resourceId the requested resource (not necessarily the organization)
	 */
	@Transactional(readOnly = true)
	public OrganizationRole require(UUID organizationId, OrganizationPermission permission, String resourceType,
			UUID resourceId) {
		OrganizationRole role = roleIn(organizationId)
			.orElseThrow(() -> new ResourceNotFoundException(resourceType, resourceId));
		if (!permission.isGrantedTo(role)) {
			throw new ForbiddenException(INSUFFICIENT_ROLE, "Your organization role does not permit this operation.");
		}
		return role;
	}

	/** Requires {@code permission} on the organization itself. */
	@Transactional(readOnly = true)
	public OrganizationRole requireOnOrganization(UUID organizationId, OrganizationPermission permission) {
		return require(organizationId, permission, "Organization", organizationId);
	}

	/** Only configured platform administrators may create organizations. */
	public AuthenticatedPrincipal requirePlatformAdmin() {
		AuthenticatedPrincipal principal = this.currentPrincipal.require();
		if (!isPlatformAdmin(principal)) {
			throw new ForbiddenException(PLATFORM_ADMIN_REQUIRED,
					"Only platform administrators can create organizations.");
		}
		return principal;
	}

	public boolean isPlatformAdmin(AuthenticatedPrincipal principal) {
		String issuer = this.properties.getJwt().getIssuer();
		return issuer != null && issuer.equals(principal.issuer())
				&& this.properties.getPlatformAdminSubjects().contains(principal.subject());
	}

	private Optional<OrganizationRole> roleIn(UUID organizationId) {
		AuthenticatedPrincipal principal = this.currentPrincipal.require();
		return this.identities.find(principal)
			.flatMap((identity) -> this.memberships.findByOrganizationIdAndUserIdentityId(organizationId,
					identity.getId()))
			.map(OrganizationMembership::getRole);
	}

}

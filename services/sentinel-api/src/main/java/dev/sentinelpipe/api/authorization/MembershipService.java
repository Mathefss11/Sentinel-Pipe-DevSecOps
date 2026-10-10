package dev.sentinelpipe.api.authorization;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.ConstraintViolations;
import dev.sentinelpipe.api.common.ForbiddenException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.common.Timestamps;
import dev.sentinelpipe.api.identity.AuthenticatedPrincipal;
import dev.sentinelpipe.api.identity.UserIdentity;
import dev.sentinelpipe.api.identity.UserIdentityService;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Organization membership management.
 *
 * <p>
 * Escalation rules, enforced while holding a row lock on the organization:
 * <ul>
 * <li>only OWNER and ADMIN can manage memberships;</li>
 * <li>an ADMIN can only grant, change to, or manage MEMBER and VIEWER; only an OWNER can
 * grant or manage OWNER and ADMIN;</li>
 * <li>nobody can change or revoke their own membership, so nobody can escalate
 * themselves, and the acting OWNER always remains, so an organization never loses its
 * last OWNER;</li>
 * <li>the target identity is given only by subject; the issuer is always the caller's
 * (validated) issuer, and organization and role come from the path and the server-side
 * rules, never from token claims.</li>
 * </ul>
 */
@Service
public class MembershipService {

	static final String MEMBERSHIP_EXISTS = "membership-already-exists";

	static final String ROLE_ESCALATION = "role-escalation";

	static final String SELF_MODIFICATION = "self-modification";

	private static final Sort LIST_ORDER = Sort.by(Sort.Order.asc("createdAt"), Sort.Order.asc("id"));

	/** A membership together with the identity it belongs to. */
	public record MemberView(OrganizationMembership membership, UserIdentity identity) {
	}

	private final MembershipRepository memberships;

	private final UserIdentityService identities;

	private final Clock clock;

	MembershipService(MembershipRepository memberships, UserIdentityService identities, Clock clock) {
		this.memberships = memberships;
		this.identities = identities;
		this.clock = clock;
	}

	/**
	 * Makes the creator of a new organization its first OWNER. Must run in the same
	 * transaction that creates the organization. Callers must have verified that the
	 * principal is a platform administrator.
	 */
	@Transactional
	public OrganizationMembership bootstrapOwner(UUID organizationId, AuthenticatedPrincipal creator) {
		UserIdentity identity = this.identities.findOrCreate(creator.issuer(), creator.subject());
		return this.memberships.saveAndFlush(OrganizationMembership.grant(organizationId, identity.getId(),
				OrganizationRole.OWNER, null, Timestamps.now(this.clock)));
	}

	@Transactional
	public MemberView grant(UUID organizationId, AuthenticatedPrincipal principal, String subject,
			OrganizationRole role) {
		OrganizationMembership actor = lockAndRequireManager(organizationId, principal);
		requireCanManage(actor, role);
		UserIdentity target = this.identities.findOrCreate(principal.issuer(), subject);
		if (target.getId().equals(actor.getUserIdentityId())) {
			throw selfModification();
		}
		if (this.memberships.findByOrganizationIdAndUserIdentityId(organizationId, target.getId()).isPresent()) {
			throw membershipExists();
		}
		try {
			OrganizationMembership membership = this.memberships.saveAndFlush(OrganizationMembership
				.grant(organizationId, target.getId(), role, actor.getUserIdentityId(), Timestamps.now(this.clock)));
			return new MemberView(membership, target);
		}
		catch (DataIntegrityViolationException ex) {
			if (ConstraintViolations.isViolationOf(ex, "uq_organization_memberships_organization_user")) {
				throw membershipExists();
			}
			throw ex;
		}
	}

	@Transactional
	public MemberView changeRole(UUID organizationId, UUID membershipId, AuthenticatedPrincipal principal,
			OrganizationRole newRole) {
		OrganizationMembership actor = lockAndRequireManager(organizationId, principal);
		OrganizationMembership target = requireTarget(organizationId, membershipId, actor);
		requireCanManage(actor, target.getRole());
		requireCanManage(actor, newRole);
		target.changeRole(newRole, Timestamps.now(this.clock));
		this.memberships.flush();
		requireAnOwnerRemains(organizationId);
		return new MemberView(target, identity(target));
	}

	@Transactional
	public void revoke(UUID organizationId, UUID membershipId, AuthenticatedPrincipal principal) {
		OrganizationMembership actor = lockAndRequireManager(organizationId, principal);
		OrganizationMembership target = requireTarget(organizationId, membershipId, actor);
		requireCanManage(actor, target.getRole());
		this.memberships.delete(target);
		this.memberships.flush();
		requireAnOwnerRemains(organizationId);
	}

	@Transactional(readOnly = true)
	public MemberView get(UUID organizationId, UUID membershipId) {
		OrganizationMembership membership = this.memberships.findByIdAndOrganizationId(membershipId, organizationId)
			.orElseThrow(() -> new ResourceNotFoundException("Membership", membershipId));
		return new MemberView(membership, identity(membership));
	}

	/** Callers must have verified {@link OrganizationPermission#VIEW_MEMBERS}. */
	@Transactional(readOnly = true)
	public Page<MemberView> list(UUID organizationId, int page, int size) {
		Page<OrganizationMembership> members = this.memberships.findByOrganizationId(organizationId,
				PageRequest.of(page, size, LIST_ORDER));
		Map<UUID, UserIdentity> identitiesById = this.identities
			.findAllById(members.getContent().stream().map(OrganizationMembership::getUserIdentityId).toList());
		return members.map((membership) -> new MemberView(membership,
				identitiesById.get(membership.getUserIdentityId())));
	}

	/** The caller's own memberships, for {@code GET /api/v1/me}. */
	@Transactional(readOnly = true)
	public List<OrganizationMembership> membershipsOf(AuthenticatedPrincipal principal) {
		return this.identities.find(principal)
			.map((identity) -> this.memberships.findByUserIdentityIdOrderByCreatedAtAsc(identity.getId()))
			.orElse(List.of());
	}

	private OrganizationMembership lockAndRequireManager(UUID organizationId, AuthenticatedPrincipal principal) {
		this.memberships.lockOrganization(organizationId)
			.orElseThrow(() -> new ResourceNotFoundException("Organization", organizationId));
		// Re-read the actor's membership under the lock: a concurrent change may have
		// demoted or removed the actor since the request started.
		OrganizationMembership actor = this.identities.find(principal)
			.flatMap((identity) -> this.memberships.findByOrganizationIdAndUserIdentityId(organizationId,
					identity.getId()))
			.orElseThrow(() -> new ResourceNotFoundException("Organization", organizationId));
		if (!OrganizationPermission.MANAGE_MEMBERS.isGrantedTo(actor.getRole())) {
			throw new ForbiddenException(AccessControl.INSUFFICIENT_ROLE,
					"Your organization role does not permit this operation.");
		}
		return actor;
	}

	private OrganizationMembership requireTarget(UUID organizationId, UUID membershipId,
			OrganizationMembership actor) {
		OrganizationMembership target = this.memberships.findByIdAndOrganizationId(membershipId, organizationId)
			.orElseThrow(() -> new ResourceNotFoundException("Membership", membershipId));
		if (target.getUserIdentityId().equals(actor.getUserIdentityId())) {
			throw selfModification();
		}
		return target;
	}

	private static void requireCanManage(OrganizationMembership actor, OrganizationRole role) {
		if (!actor.getRole().canManage(role)) {
			throw new ForbiddenException(ROLE_ESCALATION,
					"Your organization role cannot grant or manage the " + role + " role.");
		}
	}

	private void requireAnOwnerRemains(UUID organizationId) {
		if (this.memberships.countByOrganizationIdAndRole(organizationId, OrganizationRole.OWNER) < 1) {
			throw new ConflictException("last-owner", "An organization must keep at least one OWNER.");
		}
	}

	private UserIdentity identity(OrganizationMembership membership) {
		return this.identities.findAllById(List.of(membership.getUserIdentityId()))
			.get(membership.getUserIdentityId());
	}

	private static ForbiddenException selfModification() {
		return new ForbiddenException(SELF_MODIFICATION, "You cannot grant, change or revoke your own membership.");
	}

	private static ConflictException membershipExists() {
		return new ConflictException(MEMBERSHIP_EXISTS, "This user is already a member of the organization.");
	}

}

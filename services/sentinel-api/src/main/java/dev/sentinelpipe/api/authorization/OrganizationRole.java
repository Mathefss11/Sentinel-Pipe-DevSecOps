package dev.sentinelpipe.api.authorization;

import java.util.EnumSet;
import java.util.Set;

/**
 * Organization roles, ordered from most to least privileged. Roles are hierarchical: a
 * role includes every permission of the roles below it.
 */
public enum OrganizationRole {

	/** Full control, including managing other OWNERs and ADMINs. */
	OWNER(4),

	/** Manages projects and MEMBER/VIEWER memberships. */
	ADMIN(3),

	/** Requests scans. */
	MEMBER(2),

	/** Read-only access. */
	VIEWER(1);

	private final int rank;

	OrganizationRole(int rank) {
		this.rank = rank;
	}

	/** Whether this role has at least the privileges of {@code required}. */
	public boolean includes(OrganizationRole required) {
		return this.rank >= required.rank;
	}

	/**
	 * Roles this role may grant to others, and memberships (by their current role) it may
	 * modify or revoke. Only an OWNER can grant or manage OWNER and ADMIN; an ADMIN can
	 * only manage MEMBER and VIEWER. Nobody can grant a role above their own.
	 */
	public Set<OrganizationRole> manageableRoles() {
		return switch (this) {
			case OWNER -> EnumSet.allOf(OrganizationRole.class);
			case ADMIN -> EnumSet.of(MEMBER, VIEWER);
			case MEMBER, VIEWER -> EnumSet.noneOf(OrganizationRole.class);
		};
	}

	public boolean canManage(OrganizationRole role) {
		return manageableRoles().contains(role);
	}

}

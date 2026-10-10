package dev.sentinelpipe.api.authorization;

/**
 * Organization-scoped permissions and the least-privileged role that holds each one. This
 * enum is the single source of truth for the authorization matrix documented in the
 * README and in ADR-0003.
 */
public enum OrganizationPermission {

	VIEW_ORGANIZATION(OrganizationRole.VIEWER),

	VIEW_PROJECTS(OrganizationRole.VIEWER),

	VIEW_SCANS(OrganizationRole.VIEWER),

	REQUEST_SCAN(OrganizationRole.MEMBER),

	CANCEL_SCAN(OrganizationRole.MEMBER),

	REGISTER_PROJECT(OrganizationRole.ADMIN),

	VIEW_MEMBERS(OrganizationRole.ADMIN),

	MANAGE_MEMBERS(OrganizationRole.ADMIN);

	private final OrganizationRole minimumRole;

	OrganizationPermission(OrganizationRole minimumRole) {
		this.minimumRole = minimumRole;
	}

	public OrganizationRole minimumRole() {
		return this.minimumRole;
	}

	public boolean isGrantedTo(OrganizationRole role) {
		return role.includes(this.minimumRole);
	}

}

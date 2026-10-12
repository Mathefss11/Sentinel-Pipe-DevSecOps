package dev.sentinelpipe.api.authorization;

/**
 * Organization-scoped permissions and the least-privileged role that holds each one. This
 * enum is the single source of truth for the authorization matrix documented in the
 * README and in ADR-0003.
 */
public enum OrganizationPermission {

	VIEW_ORGANIZATION(OrganizationRole.VIEWER),

	VIEW_PROJECTS(OrganizationRole.VIEWER),

	/** Scans, including their policy evaluation records. */
	VIEW_SCANS(OrganizationRole.VIEWER),

	/** Policy versions and the policy active for a project. */
	VIEW_POLICIES(OrganizationRole.VIEWER),

	REQUEST_SCAN(OrganizationRole.MEMBER),

	CANCEL_SCAN(OrganizationRole.MEMBER),

	REGISTER_PROJECT(OrganizationRole.ADMIN),

	VIEW_MEMBERS(OrganizationRole.ADMIN),

	MANAGE_MEMBERS(OrganizationRole.ADMIN),

	/** Create new (immutable) policy versions; this does not put them in force. */
	MANAGE_POLICIES(OrganizationRole.ADMIN),

	/**
	 * Re-evaluate a completed scan's evidence of record under an explicit policy version
	 * (ADR-0014). The result is an additional, non-gating record: it never changes a scan's
	 * decision, so it does not require ACTIVATE_POLICY.
	 */
	REEVALUATE_SCANS(OrganizationRole.ADMIN),

	/**
	 * Put a policy version in force for a project. Owner-only: activation can weaken the
	 * security gate, so drafting (ADMIN) and activation are separate permissions.
	 */
	ACTIVATE_POLICY(OrganizationRole.OWNER);

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

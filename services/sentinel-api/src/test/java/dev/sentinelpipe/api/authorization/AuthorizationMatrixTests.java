package dev.sentinelpipe.api.authorization;

import static dev.sentinelpipe.api.authorization.OrganizationRole.ADMIN;
import static dev.sentinelpipe.api.authorization.OrganizationRole.MEMBER;
import static dev.sentinelpipe.api.authorization.OrganizationRole.OWNER;
import static dev.sentinelpipe.api.authorization.OrganizationRole.VIEWER;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Pins the documented authorization matrix (README, ADR-0003). Changing a permission must
 * be a deliberate change to this test.
 */
class AuthorizationMatrixTests {

	@Test
	void permissionMatrixIsExactlyAsDocumented() {
		Map<OrganizationPermission, Set<OrganizationRole>> expected = Map.ofEntries(
				Map.entry(OrganizationPermission.VIEW_ORGANIZATION, EnumSet.of(OWNER, ADMIN, MEMBER, VIEWER)),
				Map.entry(OrganizationPermission.VIEW_PROJECTS, EnumSet.of(OWNER, ADMIN, MEMBER, VIEWER)),
				Map.entry(OrganizationPermission.VIEW_SCANS, EnumSet.of(OWNER, ADMIN, MEMBER, VIEWER)),
				Map.entry(OrganizationPermission.VIEW_POLICIES, EnumSet.of(OWNER, ADMIN, MEMBER, VIEWER)),
				Map.entry(OrganizationPermission.REQUEST_SCAN, EnumSet.of(OWNER, ADMIN, MEMBER)),
				Map.entry(OrganizationPermission.CANCEL_SCAN, EnumSet.of(OWNER, ADMIN, MEMBER)),
				Map.entry(OrganizationPermission.REGISTER_PROJECT, EnumSet.of(OWNER, ADMIN)),
				Map.entry(OrganizationPermission.VIEW_MEMBERS, EnumSet.of(OWNER, ADMIN)),
				Map.entry(OrganizationPermission.MANAGE_MEMBERS, EnumSet.of(OWNER, ADMIN)),
				// M4: drafting a policy version and putting it in force are separate duties.
				Map.entry(OrganizationPermission.MANAGE_POLICIES, EnumSet.of(OWNER, ADMIN)),
				// M4 Phase 2: historical re-evaluation is non-gating (ADR-0014).
				Map.entry(OrganizationPermission.REEVALUATE_SCANS, EnumSet.of(OWNER, ADMIN)),
				Map.entry(OrganizationPermission.ACTIVATE_POLICY, EnumSet.of(OWNER)));

		assertThat(expected.keySet()).containsExactlyInAnyOrder(OrganizationPermission.values());
		for (OrganizationPermission permission : OrganizationPermission.values()) {
			for (OrganizationRole role : OrganizationRole.values()) {
				assertThat(permission.isGrantedTo(role)).as("%s granted to %s", permission, role)
					.isEqualTo(expected.get(permission).contains(role));
			}
		}
	}

	@Test
	void rolesCanOnlyManageRolesBelowOrEqualToOwnerPrivilege() {
		assertThat(OWNER.manageableRoles()).containsExactlyInAnyOrder(OWNER, ADMIN, MEMBER, VIEWER);
		assertThat(ADMIN.manageableRoles()).containsExactlyInAnyOrder(MEMBER, VIEWER);
		assertThat(MEMBER.manageableRoles()).isEmpty();
		assertThat(VIEWER.manageableRoles()).isEmpty();
		for (OrganizationRole role : OrganizationRole.values()) {
			for (OrganizationRole managed : role.manageableRoles()) {
				assertThat(role.includes(managed)).as("%s must not manage a higher role %s", role, managed).isTrue();
			}
		}
	}

	@Test
	void membershipsCannotBeSelfGranted() {
		java.util.UUID user = java.util.UUID.randomUUID();
		org.assertj.core.api.Assertions
			.assertThatThrownBy(() -> OrganizationMembership.grant(java.util.UUID.randomUUID(), user, ADMIN, user,
					java.time.Instant.now()))
			.isInstanceOf(IllegalArgumentException.class);
	}

}

package dev.sentinelpipe.api.authorization;

import dev.sentinelpipe.api.identity.IdentityClaims;
import dev.sentinelpipe.api.identity.UserIdentity;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Request and response bodies of the membership and current-user endpoints. */
final class MembershipDtos {

	private MembershipDtos() {
	}

	/**
	 * Grants a role to the user with this token subject (of the caller's issuer). There is
	 * intentionally no issuer, organization or grantor field.
	 */
	record CreateMembershipRequest(
			@NotNull @Size(min = 1, max = UserIdentity.SUBJECT_MAX_LENGTH) @Pattern(
					regexp = IdentityClaims.SUBJECT_REGEX,
					message = "must not be blank or contain control characters") String subject,
			@NotNull OrganizationRole role) {
	}

	record UpdateMembershipRequest(@NotNull OrganizationRole role) {
	}

	record MembershipResponse(UUID id, UUID organizationId, String issuer, String subject, OrganizationRole role,
			Instant createdAt, Instant updatedAt) {

		static MembershipResponse from(MembershipService.MemberView view) {
			OrganizationMembership membership = view.membership();
			return new MembershipResponse(membership.getId(), membership.getOrganizationId(),
					view.identity().getIssuer(), view.identity().getSubject(), membership.getRole(),
					membership.getCreatedAt(), membership.getUpdatedAt());
		}

	}

	record CurrentUserResponse(String issuer, String subject, boolean platformAdmin,
			List<OrganizationAccess> memberships) {

		record OrganizationAccess(UUID organizationId, OrganizationRole role) {
		}

	}

}

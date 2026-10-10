package dev.sentinelpipe.api.organization;

import java.time.Instant;
import java.util.UUID;

record OrganizationResponse(UUID id, String name, String slug, Instant createdAt, Instant updatedAt) {

	static OrganizationResponse from(Organization organization) {
		return new OrganizationResponse(organization.getId(), organization.getName(), organization.getSlug(),
				organization.getCreatedAt(), organization.getUpdatedAt());
	}

}

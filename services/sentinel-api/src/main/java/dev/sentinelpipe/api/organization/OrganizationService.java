package dev.sentinelpipe.api.organization;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.ConstraintViolations;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.common.Timestamps;
import java.time.Clock;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OrganizationService {

	static final String SLUG_TAKEN = "organization-slug-taken";

	private final OrganizationRepository organizations;

	private final Clock clock;

	OrganizationService(OrganizationRepository organizations, Clock clock) {
		this.organizations = organizations;
		this.clock = clock;
	}

	/**
	 * Creates an organization. The pre-check gives a clear error for the common case; the
	 * unique constraint is the authoritative guard against concurrent duplicates.
	 */
	@Transactional
	public Organization create(String name, String slug) {
		Organization organization = Organization.create(name, slug, Timestamps.now(this.clock));
		if (this.organizations.existsBySlug(organization.getSlug())) {
			throw slugTaken();
		}
		try {
			return this.organizations.saveAndFlush(organization);
		}
		catch (DataIntegrityViolationException ex) {
			if (ConstraintViolations.isViolationOf(ex, "uq_organizations_slug")) {
				throw slugTaken();
			}
			throw ex;
		}
	}

	@Transactional(readOnly = true)
	public Organization get(UUID organizationId) {
		return this.organizations.findById(organizationId)
			.orElseThrow(() -> new ResourceNotFoundException("Organization", organizationId));
	}

	@Transactional(readOnly = true)
	public void requireExists(UUID organizationId) {
		if (!this.organizations.existsById(organizationId)) {
			throw new ResourceNotFoundException("Organization", organizationId);
		}
	}

	private static ConflictException slugTaken() {
		return new ConflictException(SLUG_TAKEN, "An organization with this slug already exists.");
	}

}

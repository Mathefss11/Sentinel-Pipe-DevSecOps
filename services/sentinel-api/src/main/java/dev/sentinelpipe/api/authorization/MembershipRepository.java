package dev.sentinelpipe.api.authorization;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

interface MembershipRepository extends JpaRepository<OrganizationMembership, UUID> {

	Optional<OrganizationMembership> findByOrganizationIdAndUserIdentityId(UUID organizationId, UUID userIdentityId);

	Optional<OrganizationMembership> findByIdAndOrganizationId(UUID id, UUID organizationId);

	List<OrganizationMembership> findByUserIdentityIdOrderByCreatedAtAsc(UUID userIdentityId);

	Page<OrganizationMembership> findByOrganizationId(UUID organizationId, Pageable pageable);

	long countByOrganizationIdAndRole(UUID organizationId, OrganizationRole role);

	/**
	 * Row-locks the organization. Every membership change takes this lock first, so
	 * concurrent changes in one organization are serialized (for example, two OWNERs
	 * demoting each other cannot leave the organization without an OWNER).
	 */
	@Query(value = "SELECT id FROM organizations WHERE id = :organizationId FOR UPDATE", nativeQuery = true)
	Optional<UUID> lockOrganization(UUID organizationId);

}

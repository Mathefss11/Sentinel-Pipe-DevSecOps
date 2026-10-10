package dev.sentinelpipe.api.organization;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

interface OrganizationRepository extends JpaRepository<Organization, UUID> {

	boolean existsBySlug(String slug);

}

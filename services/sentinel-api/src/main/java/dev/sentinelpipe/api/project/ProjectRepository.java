package dev.sentinelpipe.api.project;

import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

interface ProjectRepository extends JpaRepository<Project, UUID> {

	boolean existsByOrganizationIdAndRepositoryProviderAndRepositoryOwnerAndRepositoryName(UUID organizationId,
			RepositoryProvider provider, String repositoryOwner, String repositoryName);

	Page<Project> findByOrganizationId(UUID organizationId, Pageable pageable);

}

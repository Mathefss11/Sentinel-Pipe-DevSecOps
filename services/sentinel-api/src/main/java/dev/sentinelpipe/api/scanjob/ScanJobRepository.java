package dev.sentinelpipe.api.scanjob;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface ScanJobRepository extends JpaRepository<ScanJob, UUID> {

	/** Scalar lookup that does not load the job into the persistence context. */
	@Query("select j.scanId from ScanJob j where j.id = :id")
	Optional<UUID> findScanIdById(UUID id);

	List<ScanJob> findByScanIdOrderByScannerTypeAsc(UUID scanId);

	List<ScanJob> findByScanIdIn(Collection<UUID> scanIds);

}

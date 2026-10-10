package dev.sentinelpipe.api.scan;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

interface ScanRepository extends JpaRepository<Scan, UUID> {

	Optional<Scan> findByProjectIdAndIdempotencyKey(UUID projectId, String idempotencyKey);

	Page<Scan> findByProjectId(UUID projectId, Pageable pageable);

	/**
	 * Loads a scan with a row lock. Lifecycle operations on a scan and its jobs take this
	 * lock first, so they are serialized per scan across application instances.
	 */
	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select s from Scan s where s.id = :id")
	Optional<Scan> findByIdForUpdate(UUID id);

	/**
	 * Clears an expired idempotency key (and its fingerprint) from the scan holding it.
	 * The scan itself is kept. Returns the number of released keys (0 or 1).
	 */
	@Modifying(flushAutomatically = true)
	@Query(nativeQuery = true, value = """
			UPDATE scans SET idempotency_key = NULL, request_fingerprint = NULL
			WHERE project_id = :projectId AND idempotency_key = :idempotencyKey AND requested_at <= :cutoff
			""")
	int releaseExpiredIdempotencyKey(UUID projectId, String idempotencyKey, Instant cutoff);

}

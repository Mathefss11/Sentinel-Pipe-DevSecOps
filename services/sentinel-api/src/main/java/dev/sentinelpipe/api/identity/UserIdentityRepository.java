package dev.sentinelpipe.api.identity;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

interface UserIdentityRepository extends JpaRepository<UserIdentity, UUID> {

	Optional<UserIdentity> findByIssuerAndSubject(String issuer, String subject);

	/**
	 * Inserts the identity unless one with the same issuer and subject exists. Runs in the
	 * caller's transaction and connection; a concurrent insert of the same identity waits
	 * for the other transaction and then does nothing, so the caller's transaction is never
	 * aborted by a unique violation.
	 */
	@Modifying
	@Query(value = """
			INSERT INTO user_identities (id, issuer, subject, version, created_at, updated_at)
			VALUES (:id, :issuer, :subject, 0, :now, :now)
			ON CONFLICT ON CONSTRAINT uq_user_identities_issuer_subject DO NOTHING
			""", nativeQuery = true)
	int insertIfAbsent(UUID id, String issuer, String subject, Instant now);

}

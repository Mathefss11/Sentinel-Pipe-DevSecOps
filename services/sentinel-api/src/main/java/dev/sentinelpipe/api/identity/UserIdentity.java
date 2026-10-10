package dev.sentinelpipe.api.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * An external OIDC identity, keyed by token issuer and subject. SentinelPipe stores no
 * credentials and no profile data for users.
 */
@Entity
@Table(name = "user_identities")
public class UserIdentity {

	public static final int ISSUER_MAX_LENGTH = 512;

	public static final int SUBJECT_MAX_LENGTH = 255;

	@Id
	private UUID id;

	@Version
	private Long version;

	@Column(nullable = false, length = ISSUER_MAX_LENGTH, updatable = false)
	private String issuer;

	@Column(nullable = false, length = SUBJECT_MAX_LENGTH, updatable = false)
	private String subject;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	protected UserIdentity() {
		// for JPA
	}

	static UserIdentity create(String issuer, String subject, Instant now) {
		UserIdentity identity = new UserIdentity();
		identity.id = UUID.randomUUID();
		identity.issuer = IdentityClaims.requireIssuer(issuer);
		identity.subject = IdentityClaims.requireSubject(subject);
		identity.createdAt = Objects.requireNonNull(now, "now");
		identity.updatedAt = now;
		return identity;
	}

	public UUID getId() {
		return this.id;
	}

	public String getIssuer() {
		return this.issuer;
	}

	public String getSubject() {
		return this.subject;
	}

	public Instant getCreatedAt() {
		return this.createdAt;
	}

}

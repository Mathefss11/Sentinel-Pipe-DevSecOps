package dev.sentinelpipe.api.authorization;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A user's role in one organization. The server-side source of truth for authorization. */
@Entity
@Table(name = "organization_memberships")
public class OrganizationMembership {

	@Id
	private UUID id;

	@Version
	private Long version;

	@Column(name = "organization_id", nullable = false, updatable = false)
	private UUID organizationId;

	@Column(name = "user_identity_id", nullable = false, updatable = false)
	private UUID userIdentityId;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private OrganizationRole role;

	@Column(name = "granted_by", updatable = false)
	private UUID grantedBy;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	protected OrganizationMembership() {
		// for JPA
	}

	/**
	 * @param grantedBy identity of the granting member, or {@code null} for the bootstrap
	 * owner created together with the organization
	 */
	static OrganizationMembership grant(UUID organizationId, UUID userIdentityId, OrganizationRole role,
			UUID grantedBy, Instant now) {
		if (userIdentityId.equals(grantedBy)) {
			throw new IllegalArgumentException("A membership cannot be self-granted");
		}
		OrganizationMembership membership = new OrganizationMembership();
		membership.id = UUID.randomUUID();
		membership.organizationId = Objects.requireNonNull(organizationId, "organizationId");
		membership.userIdentityId = Objects.requireNonNull(userIdentityId, "userIdentityId");
		membership.role = Objects.requireNonNull(role, "role");
		membership.grantedBy = grantedBy;
		membership.createdAt = Objects.requireNonNull(now, "now");
		membership.updatedAt = now;
		return membership;
	}

	void changeRole(OrganizationRole newRole, Instant now) {
		this.role = Objects.requireNonNull(newRole, "newRole");
		this.updatedAt = now.isBefore(this.updatedAt) ? this.updatedAt : now;
	}

	public UUID getId() {
		return this.id;
	}

	public UUID getOrganizationId() {
		return this.organizationId;
	}

	public UUID getUserIdentityId() {
		return this.userIdentityId;
	}

	public OrganizationRole getRole() {
		return this.role;
	}

	public UUID getGrantedBy() {
		return this.grantedBy;
	}

	public Instant getCreatedAt() {
		return this.createdAt;
	}

	public Instant getUpdatedAt() {
		return this.updatedAt;
	}

}

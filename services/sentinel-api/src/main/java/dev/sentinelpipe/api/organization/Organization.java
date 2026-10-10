package dev.sentinelpipe.api.organization;

import dev.sentinelpipe.api.common.DisplayNames;
import dev.sentinelpipe.api.common.DomainValidationException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** A tenant that owns projects. */
@Entity
@Table(name = "organizations")
public class Organization {

	public static final int SLUG_MAX_LENGTH = 63;

	/** Lowercase alphanumeric words separated by single hyphens. */
	public static final String SLUG_REGEX = "^[a-z0-9]+(-[a-z0-9]+)*$";

	private static final Pattern SLUG = Pattern.compile(SLUG_REGEX);

	@Id
	private UUID id;

	@Version
	private Long version;

	@Column(nullable = false, length = 100)
	private String name;

	@Column(nullable = false, length = SLUG_MAX_LENGTH, updatable = false)
	private String slug;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	protected Organization() {
		// for JPA
	}

	private Organization(UUID id, String name, String slug, Instant now) {
		this.id = id;
		this.name = name;
		this.slug = slug;
		this.createdAt = now;
		this.updatedAt = now;
	}

	public static Organization create(String name, String slug, Instant now) {
		Objects.requireNonNull(now, "now");
		return new Organization(UUID.randomUUID(), DisplayNames.normalize("name", name), requireSlug(slug), now);
	}

	static String requireSlug(String slug) {
		if (slug == null || slug.length() > SLUG_MAX_LENGTH || !SLUG.matcher(slug).matches()) {
			throw new DomainValidationException("slug",
					"must be 1-63 lowercase letters, digits or single hyphens, starting and ending with a letter or digit");
		}
		return slug;
	}

	public UUID getId() {
		return this.id;
	}

	public String getName() {
		return this.name;
	}

	public String getSlug() {
		return this.slug;
	}

	public Instant getCreatedAt() {
		return this.createdAt;
	}

	public Instant getUpdatedAt() {
		return this.updatedAt;
	}

}

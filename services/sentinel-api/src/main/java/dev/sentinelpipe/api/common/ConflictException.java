package dev.sentinelpipe.api.common;

/**
 * The request conflicts with the current state of a resource, for example a uniqueness
 * rule. Mapped to HTTP 409. The message is a fixed, client-safe description.
 */
public class ConflictException extends RuntimeException {

	private final String code;

	public ConflictException(String code, String message) {
		super(message);
		this.code = code;
	}

	/** Stable, machine-readable conflict code, e.g. {@code organization-slug-taken}. */
	public String getCode() {
		return this.code;
	}

}

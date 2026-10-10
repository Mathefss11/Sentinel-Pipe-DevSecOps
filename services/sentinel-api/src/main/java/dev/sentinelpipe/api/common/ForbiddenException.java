package dev.sentinelpipe.api.common;

/**
 * The authenticated caller is a member of the organization but lacks the required
 * permission. Mapped to HTTP 403. Callers who are not members at all receive 404 instead
 * ({@link ResourceNotFoundException}), so resource existence is not disclosed.
 */
public class ForbiddenException extends RuntimeException {

	private final String code;

	public ForbiddenException(String code, String message) {
		super(message);
		this.code = code;
	}

	/** Stable, machine-readable reason, e.g. {@code insufficient-role}. */
	public String getCode() {
		return this.code;
	}

}

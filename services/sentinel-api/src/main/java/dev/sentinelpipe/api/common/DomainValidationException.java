package dev.sentinelpipe.api.common;

/**
 * A value violates a domain format rule. Domain types re-validate their inputs even when
 * the REST layer already did, so invariants hold for every caller. Mapped to HTTP 400.
 */
public class DomainValidationException extends RuntimeException {

	private final String field;

	public DomainValidationException(String field, String message) {
		super(message);
		this.field = field;
	}

	public String getField() {
		return this.field;
	}

}

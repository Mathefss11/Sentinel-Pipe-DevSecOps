package dev.sentinelpipe.api.common;

/**
 * An operation is not permitted in the current state of an aggregate, for example an
 * invalid lifecycle transition. Mapped to HTTP 409 if it ever reaches the API boundary.
 */
public class DomainRuleViolationException extends RuntimeException {

	public DomainRuleViolationException(String message) {
		super(message);
	}

}

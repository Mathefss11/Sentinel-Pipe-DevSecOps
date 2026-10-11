package dev.sentinelpipe.api.common;

import java.util.List;

/**
 * A submitted document (for example a policy definition) violates its schema. Each
 * violation names a location inside the document and carries a fixed message; rejected
 * values are never included. Mapped to HTTP 400 ({@code validation-error}).
 */
public class InvalidDocumentException extends RuntimeException {

	/** One violation: a location inside the document and a fixed message. */
	public record Violation(String field, String message) {
	}

	private final List<Violation> violations;

	public InvalidDocumentException(List<Violation> violations) {
		super("invalid document");
		this.violations = List.copyOf(violations);
	}

	public InvalidDocumentException(String field, String message) {
		this(List.of(new Violation(field, message)));
	}

	public List<Violation> getViolations() {
		return this.violations;
	}

}

package dev.sentinelpipe.api.common;

import java.net.URI;

/**
 * RFC 9457 problem type identifiers. They are URNs: stable identifiers that do not imply a
 * dereferenceable documentation URL. Documented in {@code packages/contracts}.
 */
public final class ProblemTypes {

	private static final String PREFIX = "urn:sentinelpipe:problem:";

	public static final URI VALIDATION_ERROR = URI.create(PREFIX + "validation-error");

	public static final URI MALFORMED_REQUEST = URI.create(PREFIX + "malformed-request");

	public static final URI NOT_FOUND = URI.create(PREFIX + "not-found");

	public static final URI CONFLICT = URI.create(PREFIX + "conflict");

	public static final URI IDEMPOTENCY_KEY_REUSED = URI.create(PREFIX + "idempotency-key-reused");

	public static final URI INTERNAL_ERROR = URI.create(PREFIX + "internal-error");

	private ProblemTypes() {
	}

}

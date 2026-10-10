package dev.sentinelpipe.api.common;

/**
 * An {@code Idempotency-Key} was reused with a different request payload. Mapped to HTTP
 * 422, following the IETF HTTPAPI Idempotency-Key header draft.
 */
public class IdempotencyKeyReuseException extends RuntimeException {

	public IdempotencyKeyReuseException() {
		super("The Idempotency-Key was already used for a different request");
	}

}

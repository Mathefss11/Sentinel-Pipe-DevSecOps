package dev.sentinelpipe.api.messaging;

/**
 * Sanitized publication failure categories, stored in {@code outbox_events.last_error}
 * and used as metric tags. Raw exception messages are only logged, never persisted.
 */
public enum PublicationFailure {

	/** No connection or channel to the broker. */
	BROKER_UNAVAILABLE,

	/** The broker negatively acknowledged the message (for example, queue full). */
	NACK,

	/** The broker returned the message because no queue was bound (mandatory flag). */
	UNROUTABLE,

	/** No confirm arrived within the configured timeout. */
	CONFIRM_TIMEOUT,

	/** No route is configured for the event type. */
	UNKNOWN_EVENT_TYPE,

	/** The publisher crashed or lost its lease after the final attempt. */
	LEASE_EXPIRED,

	/** Any other error. */
	UNEXPECTED

}

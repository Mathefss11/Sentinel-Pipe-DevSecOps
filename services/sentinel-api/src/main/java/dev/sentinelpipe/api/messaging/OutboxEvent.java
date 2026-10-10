package dev.sentinelpipe.api.messaging;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A domain event to be appended to the outbox in the caller's transaction.
 * @param payload JSON object; becomes the exact message body. Must not contain secrets.
 */
public record OutboxEvent(UUID eventId, String eventType, int schemaVersion, String aggregateType, UUID aggregateId,
		UUID organizationId, UUID correlationId, String payload, Instant createdAt) {

	public OutboxEvent {
		Objects.requireNonNull(eventId, "eventId");
		Objects.requireNonNull(eventType, "eventType");
		Objects.requireNonNull(aggregateType, "aggregateType");
		Objects.requireNonNull(aggregateId, "aggregateId");
		Objects.requireNonNull(organizationId, "organizationId");
		Objects.requireNonNull(correlationId, "correlationId");
		Objects.requireNonNull(payload, "payload");
		Objects.requireNonNull(createdAt, "createdAt");
	}

	/** An event claimed by a publisher; {@code attempts} includes the current attempt. */
	public record Claimed(UUID eventId, String eventType, int schemaVersion, UUID aggregateId, UUID organizationId,
			UUID correlationId, String payload, int attempts, Instant createdAt) {
	}

}

package dev.sentinelpipe.api.messaging;

import java.time.Duration;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/**
 * {@code outbox} health: DOWN when the oldest pending event is older than
 * {@code sentinel.messaging.outbox.max-pending-age}, i.e. publication is stalled (broker
 * unreachable, publisher disabled or failing). FAILED events do not change the status:
 * they are terminal and handled by alerting and the recovery runbook.
 *
 * <p>
 * This indicator is part of the aggregate {@code /actuator/health} status but not of the
 * liveness or readiness groups: a stalled outbox must not restart the API or stop it from
 * accepting scan requests, which the outbox buffers durably. Details are never exposed
 * over HTTP ({@code management.endpoint.health.show-details=never}).
 */
public class OutboxHealthIndicator implements HealthIndicator {

	private final OutboxStore store;

	private final Duration maxPendingAge;

	public OutboxHealthIndicator(OutboxStore store, Duration maxPendingAge) {
		this.store = store;
		this.maxPendingAge = maxPendingAge;
	}

	@Override
	public Health health() {
		double age = this.store.oldestPendingAgeSeconds();
		Health.Builder builder = (age > this.maxPendingAge.toSeconds()) ? Health.down() : Health.up();
		return builder.withDetail("oldestPendingAgeSeconds", (long) age)
			.withDetail("failedEvents", this.store.countByStatus("FAILED"))
			.build();
	}

}

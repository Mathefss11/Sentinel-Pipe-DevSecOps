package dev.sentinelpipe.api.messaging;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Outbox metrics. Tags carry only status and sanitized failure categories, never event
 * payloads or identifiers (unbounded cardinality and potential data exposure).
 *
 * <ul>
 * <li>{@code sentinel.outbox.events{status=pending|failed}}: gauge, current count;</li>
 * <li>{@code sentinel.outbox.publications{outcome=published}}: confirmed publications;</li>
 * <li>{@code sentinel.outbox.publications{outcome=retry_scheduled,reason}}: retries;</li>
 * <li>{@code sentinel.outbox.publications{outcome=failed,reason}}: terminal failures;</li>
 * <li>{@code sentinel.outbox.publications{outcome=lease_lost}}: possible duplicates;</li>
 * <li>{@code sentinel.outbox.oldest.pending.age}: gauge, seconds since the oldest pending
 * event was created (0 when none);</li>
 * <li>{@code sentinel.outbox.leases.expired}: gauge, pending events whose publisher claim
 * expired (crashed or stalled publisher; reclaimed automatically);</li>
 * <li>{@code sentinel.outbox.publish.failures{reason}}: every failed broker publication
 * attempt (RabbitMQ delivery failure), whether or not it is retried.</li>
 * </ul>
 * The gauges query PostgreSQL when read (partial indexes keep this cheap); while the
 * database is unavailable they report NaN.
 */
public class OutboxMetrics {

	static final String EVENTS = "sentinel.outbox.events";

	static final String PUBLICATIONS = "sentinel.outbox.publications";

	static final String OLDEST_PENDING_AGE = "sentinel.outbox.oldest.pending.age";

	static final String EXPIRED_LEASES = "sentinel.outbox.leases.expired";

	static final String PUBLISH_FAILURES = "sentinel.outbox.publish.failures";

	private final MeterRegistry registry;

	public OutboxMetrics(MeterRegistry registry, OutboxStore store) {
		this.registry = registry;
		Gauge.builder(EVENTS, store, (s) -> s.countByStatus("PENDING"))
			.tag("status", "pending")
			.description("Outbox events awaiting publication")
			.register(registry);
		Gauge.builder(EVENTS, store, (s) -> s.countByStatus("FAILED"))
			.tag("status", "failed")
			.description("Outbox events that exhausted their publication attempts")
			.register(registry);
		Gauge.builder(OLDEST_PENDING_AGE, store, OutboxStore::oldestPendingAgeSeconds)
			.baseUnit("seconds")
			.description("Age of the oldest outbox event awaiting publication")
			.register(registry);
		Gauge.builder(EXPIRED_LEASES, store, OutboxStore::countExpiredLeases)
			.description("Pending outbox events whose publisher claim has expired")
			.register(registry);
	}

	void publishFailed(PublicationFailure reason) {
		Counter.builder(PUBLISH_FAILURES)
			.tag("reason", reason.name())
			.description("Failed broker publication attempts")
			.register(this.registry)
			.increment();
	}

	void published() {
		counter("published", "none").increment();
	}

	void retryScheduled(PublicationFailure reason) {
		counter("retry_scheduled", reason.name()).increment();
	}

	void failed(PublicationFailure reason, int count) {
		counter("failed", reason.name()).increment(count);
	}

	void leaseLost() {
		counter("lease_lost", "none").increment();
	}

	private Counter counter(String outcome, String reason) {
		return Counter.builder(PUBLICATIONS)
			.tag("outcome", outcome)
			.tag("reason", reason)
			.description("Outbox publication outcomes")
			.register(this.registry);
	}

}

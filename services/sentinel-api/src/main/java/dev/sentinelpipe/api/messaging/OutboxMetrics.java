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
 * <li>{@code sentinel.outbox.publications{outcome=lease_lost}}: possible duplicates.</li>
 * </ul>
 */
public class OutboxMetrics {

	static final String EVENTS = "sentinel.outbox.events";

	static final String PUBLICATIONS = "sentinel.outbox.publications";

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

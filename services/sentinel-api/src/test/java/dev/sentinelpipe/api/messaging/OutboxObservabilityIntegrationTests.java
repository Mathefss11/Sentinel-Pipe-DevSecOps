package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Status;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Outbox metrics, health and label cardinality against real PostgreSQL and RabbitMQ. */
class OutboxObservabilityIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final Set<String> ALLOWED_TAG_KEYS = Set.of("status", "outcome", "reason");

	private static final Pattern LOW_CARDINALITY_VALUE = Pattern.compile("[a-z_]+|[A-Z_]+");

	@Autowired
	private OutboxStore store;

	@Autowired
	private MeterRegistry meterRegistry;

	@Autowired
	private RabbitTemplate rabbitTemplate;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	@AfterEach
	void emptyOutbox() {
		this.jdbcTemplate.update("DELETE FROM outbox_events");
	}

	private UUID appendEvent(String eventType, Duration age) {
		UUID eventId = UUID.randomUUID();
		new TransactionTemplate(this.transactionManager).executeWithoutResult((status) -> this.store
			.append(new OutboxEvent(eventId, eventType, 1, "scan", UUID.randomUUID(), UUID.randomUUID(),
					UUID.randomUUID(), "{\"event_id\": \"%s\"}".formatted(eventId), Instant.now().minus(age))));
		return eventId;
	}

	private double gauge(String name) {
		return this.meterRegistry.get(name).gauge().value();
	}

	private double counter(String name, String reason) {
		var counter = this.meterRegistry.find(name).tag("reason", reason).counter();
		return (counter != null) ? counter.count() : 0;
	}

	private OutboxPublisher publisher(OutboxRoutes routes) {
		MessagingProperties.Outbox settings = new MessagingProperties.Outbox();
		settings.setMaxAttempts(3);
		settings.setConfirmTimeout(Duration.ofSeconds(5));
		return new OutboxPublisher(this.store, this.rabbitTemplate, routes, settings,
				new OutboxMetrics(this.meterRegistry, this.store), "observability-" + UUID.randomUUID());
	}

	@Test
	void oldestPendingAgeReportsTheOldestUnpublishedEvent() {
		assertThat(gauge(OutboxMetrics.OLDEST_PENDING_AGE)).isZero();

		appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ofSeconds(30));
		appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ofMinutes(10));

		assertThat(gauge(OutboxMetrics.OLDEST_PENDING_AGE)).isBetween(599.0, 660.0);
		this.jdbcTemplate.update("UPDATE outbox_events SET status = 'PUBLISHED', published_at = now()");
		assertThat(gauge(OutboxMetrics.OLDEST_PENDING_AGE)).isZero();
	}

	@Test
	void expiredPublisherClaimsAreCounted() {
		UUID eventId = appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ZERO);
		assertThat(this.store.claim("crashed-publisher", 10, Duration.ofMinutes(5), 8)).hasSize(1);
		assertThat(gauge(OutboxMetrics.EXPIRED_LEASES)).isZero();

		this.jdbcTemplate.update("UPDATE outbox_events SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
				eventId);

		assertThat(gauge(OutboxMetrics.EXPIRED_LEASES)).isEqualTo(1);
	}

	@Test
	void everyFailedBrokerPublicationIsCountedByReason() {
		double unknownBefore = counter(OutboxMetrics.PUBLISH_FAILURES, "UNKNOWN_EVENT_TYPE");
		double unroutableBefore = counter(OutboxMetrics.PUBLISH_FAILURES, "UNROUTABLE");
		appendEvent("future.event", Duration.ZERO);
		appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ZERO);

		// No route for the unknown type; the scan event goes to a key nothing is bound to.
		publisher(new OutboxRoutes(Map.of(OutboxRoutes.SCAN_REQUESTED,
				new OutboxRoutes.Route(MessagingTopology.SCAN_REQUESTS_EXCHANGE, "unbound.routing.key"))))
			.publishBatch();

		assertThat(counter(OutboxMetrics.PUBLISH_FAILURES, "UNKNOWN_EVENT_TYPE")).isEqualTo(unknownBefore + 1);
		assertThat(counter(OutboxMetrics.PUBLISH_FAILURES, "UNROUTABLE")).isEqualTo(unroutableBefore + 1);
	}

	@Test
	void outboxHealthIsDownOnlyWhenPublicationStalls() {
		OutboxHealthIndicator indicator = new OutboxHealthIndicator(this.store, Duration.ofMinutes(15));
		assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);

		appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ofMinutes(5));
		assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);

		appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ofMinutes(20));
		assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
	}

	@Test
	void aStalledOutboxDoesNotFailReadinessOrLiveness() throws Exception {
		appendEvent(OutboxRoutes.SCAN_REQUESTED, Duration.ofMinutes(20));

		this.anonymousMvc.perform(get("/actuator/health"))
			.andExpect(jsonPath("$.status").value("DOWN"))
			.andExpect(jsonPath("$.components").doesNotExist());
		this.anonymousMvc.perform(get("/actuator/health/readiness")).andExpect(jsonPath("$.status").value("UP"));
		this.anonymousMvc.perform(get("/actuator/health/liveness")).andExpect(jsonPath("$.status").value("UP"));
	}

	@Test
	void sentinelMetricsUseOnlyLowCardinalityLabels() {
		appendEvent("future.event", Duration.ZERO);
		publisher(new OutboxRoutes(Map.of())).publishBatch();
		Pattern uuid = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-");

		assertThat(this.meterRegistry.getMeters()).filteredOn((meter) -> meter.getId().getName().startsWith("sentinel."))
			.isNotEmpty()
			.allSatisfy((Meter meter) -> meter.getId().getTags().forEach((tag) -> {
				assertThat(tag.getKey()).isIn(ALLOWED_TAG_KEYS);
				assertThat(tag.getValue()).matches(LOW_CARDINALITY_VALUE).doesNotContainPattern(uuid);
			}));
	}

}

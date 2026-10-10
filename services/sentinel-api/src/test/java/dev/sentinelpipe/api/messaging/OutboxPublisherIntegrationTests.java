package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;

/**
 * Publisher behaviour against real PostgreSQL and RabbitMQ. Each test starts with an empty
 * outbox and empty queues, and drives publication explicitly.
 */
@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
class OutboxPublisherIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private OutboxStore store;

	@Autowired
	private OutboxPublisher publisher;

	@Autowired
	private RabbitTemplate rabbitTemplate;

	@Autowired
	private ConnectionFactory connectionFactory;

	@Autowired
	private MessagingProperties properties;

	@Autowired
	private MeterRegistry meterRegistry;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@Autowired
	private org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate namedParameterJdbcTemplate;

	private RabbitAdmin admin;

	private final List<CachingConnectionFactory> extraConnectionFactories = new ArrayList<>();

	@BeforeEach
	void emptyOutboxAndQueues() {
		this.jdbcTemplate.update("DELETE FROM outbox_events");
		this.admin = new RabbitAdmin(this.connectionFactory);
		this.admin.purgeQueue(MessagingTopology.SCAN_REQUESTS_QUEUE, false);
		this.admin.purgeQueue(MessagingTopology.DEAD_LETTER_QUEUE, false);
	}

	@AfterEach
	void closeExtraConnections() {
		this.extraConnectionFactories.forEach(CachingConnectionFactory::destroy);
	}

	private UUID appendEvent() {
		return appendEvent(OutboxRoutes.SCAN_REQUESTED);
	}

	private UUID appendEvent(String eventType) {
		UUID eventId = UUID.randomUUID();
		String payload = "{\"event_id\": \"%s\", \"event_type\": \"%s\", \"schema_version\": 1}".formatted(eventId,
				eventType);
		new TransactionTemplate(this.transactionManager).executeWithoutResult((status) -> this.store
			.append(new OutboxEvent(eventId, eventType, 1, "scan", UUID.randomUUID(), UUID.randomUUID(),
					UUID.randomUUID(), payload, Instant.now())));
		return eventId;
	}

	private Map<String, Object> row(UUID eventId) {
		return this.jdbcTemplate.queryForMap("SELECT * FROM outbox_events WHERE id = ?", eventId);
	}

	private void makeDue(UUID eventId) {
		this.jdbcTemplate.update("UPDATE outbox_events SET next_attempt_at = now() WHERE id = ?", eventId);
	}

	private MessagingProperties.Outbox settings(int maxAttempts) {
		MessagingProperties.Outbox settings = new MessagingProperties.Outbox();
		settings.setMaxAttempts(maxAttempts);
		settings.setConfirmTimeout(Duration.ofSeconds(5));
		return settings;
	}

	private OutboxPublisher publisherWith(RabbitTemplate template, OutboxRoutes routes, int maxAttempts) {
		return new OutboxPublisher(this.store, template, routes, settings(maxAttempts),
				new OutboxMetrics(this.meterRegistry, this.store), "test-" + UUID.randomUUID());
	}

	/** A publisher whose broker connection always fails, as during broker downtime. */
	private OutboxPublisher unreachableBrokerPublisher(int maxAttempts) throws IOException {
		int closedPort;
		try (ServerSocket socket = new ServerSocket(0)) {
			closedPort = socket.getLocalPort();
		}
		CachingConnectionFactory factory = new CachingConnectionFactory("127.0.0.1", closedPort);
		factory.setConnectionTimeout(2000);
		factory.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
		factory.setPublisherReturns(true);
		this.extraConnectionFactories.add(factory);
		RabbitTemplate template = new RabbitTemplate(factory);
		template.setMandatory(true);
		return publisherWith(template, OutboxRoutes.standard(), maxAttempts);
	}

	private List<Message> drainWorkerQueue() {
		List<Message> messages = new ArrayList<>();
		Message message;
		while ((message = this.rabbitTemplate.receive(MessagingTopology.SCAN_REQUESTS_QUEUE, 500)) != null) {
			messages.add(message);
		}
		return messages;
	}

	private double counter(String outcome, String reason) {
		var counter = this.meterRegistry.find(OutboxMetrics.PUBLICATIONS)
			.tag("outcome", outcome)
			.tag("reason", reason)
			.counter();
		return (counter != null) ? counter.count() : 0;
	}

	@Test
	void publishesPersistentConfirmedMessagesAndMarksThemPublished() throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(createProject(), randomSha(), null)).get("id").asString());
		Map<String, Object> pending = this.jdbcTemplate
			.queryForMap("SELECT id, payload::text AS payload, correlation_id FROM outbox_events WHERE aggregate_id = ?",
					scanId);

		OutboxPublisher.BatchResult result = this.publisher.publishBatch();

		assertThat(result.claimed()).isEqualTo(1);
		assertThat(result.published()).isEqualTo(1);
		List<Message> messages = drainWorkerQueue();
		assertThat(messages).hasSize(1);
		Message message = messages.getFirst();
		assertThat(message.getMessageProperties().getMessageId()).isEqualTo(pending.get("id").toString());
		assertThat(message.getMessageProperties().getCorrelationId())
			.isEqualTo(pending.get("correlation_id").toString());
		assertThat(message.getMessageProperties().getReceivedDeliveryMode()).isEqualTo(MessageDeliveryMode.PERSISTENT);
		assertThat(message.getMessageProperties().getType()).isEqualTo("scan.requested.v1");
		assertThat(message.getMessageProperties().getContentType()).isEqualTo("application/json");
		JsonNode body = this.jsonMapper.readTree(new String(message.getBody(), StandardCharsets.UTF_8));
		assertThat(body).isEqualTo(this.jsonMapper.readTree((String) pending.get("payload")));
		dev.sentinelpipe.api.contract.ContractSchemas.assertValidMessage("scan-requested.v1.schema.json", body);

		Map<String, Object> published = row((UUID) pending.get("id"));
		assertThat(published).containsEntry("status", "PUBLISHED").containsEntry("attempts", 1);
		assertThat(published.get("published_at")).isNotNull();
		assertThat(published.get("lease_owner")).isNull();
		assertThat(this.publisher.publishBatch().claimed()).isZero();
	}

	@Test
	void concurrentPublishersPublishEveryEventExactlyOnce() throws Exception {
		Set<UUID> eventIds = new HashSet<>();
		for (int i = 0; i < 60; i++) {
			eventIds.add(appendEvent());
		}
		int publishers = 4;
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<Integer>> runs = new ArrayList<>();
		for (int i = 0; i < publishers; i++) {
			MessagingProperties.Outbox settings = settings(8);
			settings.setBatchSize(5);
			OutboxPublisher instance = new OutboxPublisher(this.store, this.rabbitTemplate, OutboxRoutes.standard(),
					settings, new OutboxMetrics(this.meterRegistry, this.store), "concurrent-" + i);
			runs.add(() -> {
				start.await();
				int published = 0;
				OutboxPublisher.BatchResult result;
				do {
					result = instance.publishBatch();
					published += result.published();
				}
				while (result.claimed() > 0);
				return published;
			});
		}
		int total = 0;
		try (ExecutorService executor = Executors.newFixedThreadPool(publishers)) {
			List<Future<Integer>> futures = runs.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<Integer> future : futures) {
				total += future.get();
			}
		}

		List<Message> messages = drainWorkerQueue();
		List<String> messageIds = messages.stream().map((m) -> m.getMessageProperties().getMessageId()).toList();
		assertThat(total).isEqualTo(60);
		assertThat(messageIds).hasSize(60).doesNotHaveDuplicates();
		assertThat(messageIds).containsExactlyInAnyOrderElementsOf(eventIds.stream().map(UUID::toString).toList());
		assertThat(this.store.countByStatus("PUBLISHED")).isEqualTo(60);
	}

	@Test
	void abandonedClaimsOfACrashedPublisherAreRecovered() {
		UUID eventId = appendEvent();
		// Publisher "crashed" claims the event and dies before publishing.
		assertThat(this.store.claim("crashed", 10, Duration.ofMinutes(5), 8)).hasSize(1);

		// While the lease is valid, nobody else may take the event.
		assertThat(this.publisher.publishBatch().claimed()).isZero();

		this.jdbcTemplate.update("UPDATE outbox_events SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
				eventId);
		OutboxPublisher.BatchResult result = this.publisher.publishBatch();

		assertThat(result.published()).isEqualTo(1);
		assertThat(row(eventId)).containsEntry("status", "PUBLISHED").containsEntry("attempts", 2);
		assertThat(drainWorkerQueue()).hasSize(1);
		// The crashed publisher's late outcome is fenced off.
		assertThat(this.store.markPublished(eventId, "crashed")).isFalse();
		assertThat(this.store.markAttemptFailed(eventId, "crashed", PublicationFailure.NACK, Duration.ZERO, 8))
			.isFalse();
		assertThat(row(eventId)).containsEntry("status", "PUBLISHED");
	}

	@Test
	void brokerDowntimeSchedulesARetryAndTheEventIsPublishedLater() throws Exception {
		UUID eventId = appendEvent();
		double retriesBefore = counter("retry_scheduled", "BROKER_UNAVAILABLE");

		OutboxPublisher.BatchResult result = unreachableBrokerPublisher(8).publishBatch();

		assertThat(result.retryScheduled()).isEqualTo(1);
		Map<String, Object> failed = row(eventId);
		assertThat(failed).containsEntry("status", "PENDING")
			.containsEntry("attempts", 1)
			.containsEntry("last_error", "BROKER_UNAVAILABLE");
		assertThat(failed.get("lease_owner")).isNull();
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT next_attempt_at > now() FROM outbox_events WHERE id = ?", Boolean.class, eventId))
			.isTrue();
		assertThat(counter("retry_scheduled", "BROKER_UNAVAILABLE")).isEqualTo(retriesBefore + 1);
		// Not due yet: the backoff is respected.
		assertThat(this.publisher.publishBatch().claimed()).isZero();

		makeDue(eventId);
		assertThat(this.publisher.publishBatch().published()).isEqualTo(1);
		assertThat(row(eventId)).containsEntry("status", "PUBLISHED");
		assertThat(row(eventId).get("last_error")).isNull();
		assertThat(drainWorkerQueue()).hasSize(1);
	}

	@Test
	void brokerNegativeAcknowledgementIsNotTreatedAsPublished() {
		String exchange = "test.nack." + UUID.randomUUID();
		String queue = "test.full." + UUID.randomUUID();
		this.admin.declareExchange(new org.springframework.amqp.core.DirectExchange(exchange, false, true));
		// A queue that is always full: the broker nacks every publication (reject-publish).
		this.admin.declareQueue(QueueBuilder.durable(queue)
			.withArgument("x-max-length", 0)
			.withArgument("x-overflow", "reject-publish")
			.build());
		this.admin.declareBinding(new org.springframework.amqp.core.Binding(queue,
				org.springframework.amqp.core.Binding.DestinationType.QUEUE, exchange, "rk", null));
		UUID eventId = appendEvent();

		OutboxPublisher.BatchResult result;
		try {
			result = publisherWith(this.rabbitTemplate,
					new OutboxRoutes(Map.of(OutboxRoutes.SCAN_REQUESTED, new OutboxRoutes.Route(exchange, "rk"))), 8)
				.publishBatch();
		}
		finally {
			this.admin.deleteQueue(queue);
		}

		assertThat(result.published()).isZero();
		assertThat(result.retryScheduled()).isEqualTo(1);
		assertThat(row(eventId)).containsEntry("status", "PENDING").containsEntry("last_error", "NACK");
	}

	@Test
	void unroutableMessagesAreNotTreatedAsPublished() {
		String exchange = "test.unbound." + UUID.randomUUID();
		this.admin.declareExchange(new org.springframework.amqp.core.DirectExchange(exchange, false, true));
		UUID eventId = appendEvent();

		OutboxPublisher.BatchResult result = publisherWith(this.rabbitTemplate,
				new OutboxRoutes(Map.of(OutboxRoutes.SCAN_REQUESTED, new OutboxRoutes.Route(exchange, "nowhere"))), 8)
			.publishBatch();

		assertThat(result.published()).isZero();
		assertThat(row(eventId)).containsEntry("status", "PENDING").containsEntry("last_error", "UNROUTABLE");
	}

	@Test
	void unknownEventTypesAreRetriedThenFailedNotDropped() {
		UUID eventId = appendEvent("future.event");

		OutboxPublisher.BatchResult result = publisherWith(this.rabbitTemplate, OutboxRoutes.standard(), 1)
			.publishBatch();

		assertThat(result.failed()).isEqualTo(1);
		assertThat(row(eventId)).containsEntry("status", "FAILED").containsEntry("last_error", "UNKNOWN_EVENT_TYPE");
	}

	@Test
	void retriesAreBoundedAndTerminalFailuresAreRecoverable() throws Exception {
		UUID eventId = appendEvent();
		OutboxPublisher failing = unreachableBrokerPublisher(3);
		double failedBefore = counter("failed", "BROKER_UNAVAILABLE");

		for (int attempt = 1; attempt <= 3; attempt++) {
			makeDue(eventId);
			failing.publishBatch();
		}

		assertThat(row(eventId)).containsEntry("status", "FAILED")
			.containsEntry("attempts", 3)
			.containsEntry("last_error", "BROKER_UNAVAILABLE");
		assertThat(counter("failed", "BROKER_UNAVAILABLE")).isEqualTo(failedBefore + 1);
		makeDue(eventId);
		assertThat(failing.publishBatch().claimed()).as("FAILED events are never claimed").isZero();
		assertThat(this.store.countByStatus("FAILED")).isEqualTo(1);

		// Operator recovery after the cause is fixed (docs/runbooks/messaging.md).
		assertThat(this.store.requeueFailed(eventId)).isTrue();
		assertThat(this.publisher.publishBatch().published()).isEqualTo(1);
		assertThat(row(eventId)).containsEntry("status", "PUBLISHED").containsEntry("attempts", 1);
		assertThat(drainWorkerQueue()).hasSize(1);
	}

	@Test
	void aCrashDuringTheFinalAttemptEndsInFailedInsteadOfUnboundedRetries() {
		UUID eventId = appendEvent();
		this.jdbcTemplate.update("UPDATE outbox_events SET attempts = 7 WHERE id = ?", eventId);
		assertThat(this.store.claim("crashed", 10, Duration.ofMinutes(5), 8)).hasSize(1);
		this.jdbcTemplate.update("UPDATE outbox_events SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
				eventId);

		OutboxPublisher.BatchResult result = this.publisher.publishBatch();

		assertThat(result.claimed()).isZero();
		assertThat(row(eventId)).containsEntry("status", "FAILED")
			.containsEntry("attempts", 8)
			.containsEntry("last_error", "LEASE_EXPIRED");
	}

	@Test
	void pendingAndFailedGaugesReflectTheOutbox() throws Exception {
		appendEvent();
		appendEvent();
		UUID failed = appendEvent("future.event");
		publisherWith(this.rabbitTemplate, new OutboxRoutes(Map.of()), 1).publishBatch();

		assertThat(row(failed)).containsEntry("status", "FAILED");
		assertThat(this.meterRegistry.get(OutboxMetrics.EVENTS).tag("status", "failed").gauge().value()).isEqualTo(3);
		this.store.requeueFailed(failed);
		assertThat(this.meterRegistry.get(OutboxMetrics.EVENTS).tag("status", "pending").gauge().value()).isEqualTo(1);
	}

	@Test
	void aPublisherCrashAfterTheBrokerConfirmIsRecoveredByRepublishingNotLost() {
		UUID eventId = appendEvent();
		// The broker confirms the publication, then the publisher dies before recording it.
		OutboxPublisher crashing = CrashingPublishers.crashAfterBrokerConfirm(this.namedParameterJdbcTemplate,
				this.rabbitTemplate, this.meterRegistry, this.store);

		assertThatThrownBy(crashing::publishBatch).isInstanceOf(CrashingPublishers.SimulatedCrash.class);

		// The event is still owed: PENDING and leased by the dead publisher. The message is in the queue.
		assertThat(row(eventId)).containsEntry("status", "PENDING").containsEntry("lease_owner", "crashed-publisher");
		assertThat(this.publisher.publishBatch().claimed()).as("lease still valid").isZero();

		this.jdbcTemplate.update("UPDATE outbox_events SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
				eventId);
		assertThat(this.publisher.publishBatch().published()).isEqualTo(1);

		// At-least-once: the event was delivered twice, never zero times.
		List<String> delivered = drainWorkerQueue().stream()
			.map((m) -> m.getMessageProperties().getMessageId())
			.toList();
		assertThat(delivered).containsExactly(eventId.toString(), eventId.toString());
		assertThat(row(eventId)).containsEntry("status", "PUBLISHED").containsEntry("attempts", 2);
	}

	@Test
	void eventsAreNotPublishedOnceTheLeaseCanNoLongerCoverTheConfirmWait() {
		UUID first = appendEvent();
		UUID second = appendEvent();
		UUID third = appendEvent();
		MessagingProperties.Outbox settings = settings(8);
		long budget = settings.getLeaseDuration().minus(settings.getConfirmTimeout()).toNanos();
		// Simulated monotonic clock: the first publication starts at once, then time jumps past the budget.
		java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
		OutboxPublisher slow = new OutboxPublisher(this.store, this.rabbitTemplate, OutboxRoutes.standard(), settings,
				new OutboxMetrics(this.meterRegistry, this.store), "slow",
				() -> (calls.getAndIncrement() < 2) ? 0L : budget + 1);

		OutboxPublisher.BatchResult result = slow.publishBatch();

		assertThat(result.claimed()).isEqualTo(3);
		assertThat(result.published()).isEqualTo(1);
		assertThat(result.released()).isEqualTo(2);
		List<Map<String, Object>> released = List.of(row(first), row(second), row(third))
			.stream()
			.filter((r) -> "PENDING".equals(r.get("status")))
			.toList();
		assertThat(released).hasSize(2).allSatisfy((r) -> {
			assertThat(r.get("lease_owner")).as("released immediately").isNull();
			assertThat(r).containsEntry("attempts", 0);
		});
		assertThat(this.publisher.publishBatch().published()).isEqualTo(2);
		assertThat(drainWorkerQueue()).hasSize(3);
	}

	@Test
	void logsAndMetricsCarryNoPayloadsOrCredentials(org.springframework.boot.test.system.CapturedOutput output)
			throws Exception {
		String marker = "payload-marker-" + UUID.randomUUID();
		UUID eventId = UUID.randomUUID();
		new TransactionTemplate(this.transactionManager).executeWithoutResult((status) -> this.store
			.append(new OutboxEvent(eventId, OutboxRoutes.SCAN_REQUESTED, 1, "scan", UUID.randomUUID(),
					UUID.randomUUID(), UUID.randomUUID(), "{\"secret\": \"%s\"}".formatted(marker), Instant.now())));
		unreachableBrokerPublisher(8).publishBatch();
		makeDue(eventId);
		this.publisher.publishBatch();

		assertThat(output.getAll()).contains(eventId.toString()).doesNotContain(marker);
		this.meterRegistry.getMeters()
			.stream()
			.filter((meter) -> meter.getId().getName().startsWith("sentinel.outbox"))
			.forEach((meter) -> meter.getId().getTags().forEach((tag) -> {
				assertThat(tag.getKey()).isIn("status", "outcome", "reason");
				assertThat(tag.getValue()).matches("[a-z_]+|[A-Z_]+");
			}));
		drainWorkerQueue();
	}

	@Test
	void defaultSettingsAreValid() {
		this.properties.getOutbox().validate();
		assertThat(this.publisher.instanceId()).startsWith("sentinel-api-");
	}

}

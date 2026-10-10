package dev.sentinelpipe.api.messaging;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.AmqpConnectException;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

/**
 * Publishes claimed outbox events to RabbitMQ.
 *
 * <p>
 * Guarantees:
 * <ul>
 * <li>never runs inside a business transaction; claiming, publishing and recording the
 * outcome are separate steps;</li>
 * <li>messages are persistent and published with the {@code mandatory} flag and
 * correlated publisher confirms;</li>
 * <li>an event is marked PUBLISHED only after a positive confirm for a message that was
 * not returned as unroutable;</li>
 * <li>an event is only published while its lease can still cover the full confirm wait;
 * claimed events beyond that budget are released untried, so a publisher never publishes
 * an event that another publisher may already have taken over;</li>
 * <li>failures are retried with exponential backoff up to {@code max-attempts}, then the
 * event becomes FAILED (terminal, recoverable by an operator).</li>
 * </ul>
 * Delivery is <b>at-least-once</b>: a crash between the broker confirm and the PUBLISHED
 * update re-publishes the event after the lease expires. Events are not ordered.
 */
public class OutboxPublisher {

	private static final Logger log = LoggerFactory.getLogger(OutboxPublisher.class);

	/** Result counts of one run. */
	public record BatchResult(int claimed, int published, int retryScheduled, int failed, int leaseLost,
			int released) {
	}

	/** Margin for clock and latency differences between this JVM and the database. */
	static final Duration LEASE_SAFETY_MARGIN = Duration.ofSeconds(1);

	private final OutboxStore store;

	private final RabbitTemplate rabbitTemplate;

	private final OutboxRoutes routes;

	private final MessagingProperties.Outbox settings;

	private final OutboxMetrics metrics;

	private final String instanceId;

	private final LongSupplier nanoClock;

	public OutboxPublisher(OutboxStore store, RabbitTemplate rabbitTemplate, OutboxRoutes routes,
			MessagingProperties.Outbox settings, OutboxMetrics metrics, String instanceId) {
		this(store, rabbitTemplate, routes, settings, metrics, instanceId, System::nanoTime);
	}

	OutboxPublisher(OutboxStore store, RabbitTemplate rabbitTemplate, OutboxRoutes routes,
			MessagingProperties.Outbox settings, OutboxMetrics metrics, String instanceId, LongSupplier nanoClock) {
		settings.validate();
		this.nanoClock = nanoClock;
		this.store = store;
		this.rabbitTemplate = rabbitTemplate;
		this.routes = routes;
		this.settings = settings;
		this.metrics = metrics;
		this.instanceId = instanceId;
	}

	public String instanceId() {
		return this.instanceId;
	}

	/** Claims and publishes one batch of due events. Safe to run on many instances. */
	public BatchResult publishBatch() {
		int abandoned = this.store.failAbandonedFinalAttempts(this.settings.getMaxAttempts());
		if (abandoned > 0) {
			log.warn("outbox.abandoned_final_attempts count={} status=FAILED", abandoned);
			this.metrics.failed(PublicationFailure.LEASE_EXPIRED, abandoned);
		}
		List<OutboxEvent.Claimed> claimed = this.store.claim(this.instanceId, this.settings.getBatchSize(),
				this.settings.getLeaseDuration(), this.settings.getMaxAttempts());
		long claimedAt = this.nanoClock.getAsLong();
		long budgetNanos = publishingBudget().toNanos();
		int published = 0;
		int retryScheduled = 0;
		int failed = 0;
		int leaseLost = 0;
		int released = 0;
		for (int index = 0; index < claimed.size(); index++) {
			OutboxEvent.Claimed event = claimed.get(index);
			if (this.nanoClock.getAsLong() - claimedAt > budgetNanos) {
				List<java.util.UUID> untried = claimed.subList(index, claimed.size())
					.stream()
					.map(OutboxEvent.Claimed::eventId)
					.toList();
				released = this.store.releaseUnattempted(untried, this.instanceId);
				log.warn("outbox.lease_budget_exhausted released={} note=publication slower than the lease allows",
						released);
				break;
			}
			Optional<PublicationFailure> failure = publish(event);
			if (failure.isEmpty()) {
				if (this.store.markPublished(event.eventId(), this.instanceId)) {
					published++;
					this.metrics.published();
					log.info("outbox.published event_id={} event_type={} attempt={} correlation_id={}",
							event.eventId(), event.eventType(), event.attempts(), event.correlationId());
				}
				else {
					leaseLost++;
					this.metrics.leaseLost();
					log.warn("outbox.lease_lost event_id={} attempt={} note=published_but_lease_expired; "
							+ "the event may be delivered more than once", event.eventId(), event.attempts());
				}
				continue;
			}
			boolean finalAttempt = event.attempts() >= this.settings.getMaxAttempts();
			Duration delay = retryDelay(event.attempts());
			if (!this.store.markAttemptFailed(event.eventId(), this.instanceId, failure.get(), delay,
					this.settings.getMaxAttempts())) {
				leaseLost++;
				this.metrics.leaseLost();
				log.warn("outbox.lease_lost event_id={} attempt={}", event.eventId(), event.attempts());
			}
			else if (finalAttempt) {
				failed++;
				this.metrics.failed(failure.get(), 1);
				log.error("outbox.failed event_id={} event_type={} attempts={} reason={} correlation_id={} "
						+ "action=see docs/runbooks/messaging.md", event.eventId(), event.eventType(),
						event.attempts(), failure.get(), event.correlationId());
			}
			else {
				retryScheduled++;
				this.metrics.retryScheduled(failure.get());
				log.warn("outbox.retry_scheduled event_id={} attempt={} reason={} retry_in_ms={}", event.eventId(),
						event.attempts(), failure.get(), delay.toMillis());
			}
		}
		return new BatchResult(claimed.size(), published, retryScheduled, failed, leaseLost, released);
	}

	/**
	 * Latest offset after claiming at which a publication may still start: the lease minus
	 * the longest confirm wait and a safety margin, so the outcome is recorded while the
	 * lease is still held.
	 */
	Duration publishingBudget() {
		return this.settings.getLeaseDuration().minus(this.settings.getConfirmTimeout()).minus(LEASE_SAFETY_MARGIN);
	}

	/** Exponential backoff: {@code initial * 2^(attempt-1)}, capped at {@code max}. */
	Duration retryDelay(int attempt) {
		Duration delay = this.settings.getBackoffInitial();
		for (int i = 1; i < attempt && delay.compareTo(this.settings.getBackoffMax()) < 0; i++) {
			delay = delay.multipliedBy(2);
		}
		return (delay.compareTo(this.settings.getBackoffMax()) > 0) ? this.settings.getBackoffMax() : delay;
	}

	private Optional<PublicationFailure> publish(OutboxEvent.Claimed event) {
		Optional<OutboxRoutes.Route> route = this.routes.routeFor(event.eventType());
		if (route.isEmpty()) {
			return Optional.of(PublicationFailure.UNKNOWN_EVENT_TYPE);
		}
		Message message = MessageBuilder.withBody(event.payload().getBytes(StandardCharsets.UTF_8))
			.setContentType("application/json")
			.setContentEncoding("utf-8")
			.setMessageId(event.eventId().toString())
			.setCorrelationId(event.correlationId().toString())
			.setType(event.eventType() + ".v" + event.schemaVersion())
			.setTimestamp(Date.from(event.createdAt()))
			.setAppId("sentinel-api")
			.setDeliveryMode(MessageDeliveryMode.PERSISTENT)
			.setHeader("schema_version", event.schemaVersion())
			.build();
		CorrelationData correlation = new CorrelationData(event.eventId().toString());
		try {
			this.rabbitTemplate.send(route.get().exchange(), route.get().routingKey(), message, correlation);
			CorrelationData.Confirm confirm = correlation.getFuture()
				.get(this.settings.getConfirmTimeout().toMillis(), TimeUnit.MILLISECONDS);
			if (correlation.getReturned() != null) {
				return Optional.of(PublicationFailure.UNROUTABLE);
			}
			if (!confirm.ack()) {
				log.debug("outbox.nack event_id={} reason={}", event.eventId(), confirm.reason());
				return Optional.of(PublicationFailure.NACK);
			}
			return Optional.empty();
		}
		catch (AmqpConnectException ex) {
			log.debug("outbox.broker_unavailable event_id={}", event.eventId(), ex);
			return Optional.of(PublicationFailure.BROKER_UNAVAILABLE);
		}
		catch (AmqpException ex) {
			log.debug("outbox.broker_error event_id={}", event.eventId(), ex);
			return Optional.of(PublicationFailure.BROKER_UNAVAILABLE);
		}
		catch (TimeoutException ex) {
			return Optional.of(PublicationFailure.CONFIRM_TIMEOUT);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			return Optional.of(PublicationFailure.UNEXPECTED);
		}
		catch (ExecutionException | RuntimeException ex) {
			log.warn("outbox.unexpected_error event_id={} error_type={}", event.eventId(),
					ex.getClass().getSimpleName());
			return Optional.of(PublicationFailure.UNEXPECTED);
		}
	}

}

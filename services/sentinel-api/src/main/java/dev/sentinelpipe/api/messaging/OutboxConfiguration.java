package dev.sentinelpipe.api.messaging;

import io.micrometer.core.instrument.MeterRegistry;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration(proxyBeanMethods = false)
class OutboxConfiguration {

	@Bean
	OutboxMetrics outboxMetrics(MeterRegistry registry, OutboxStore store) {
		return new OutboxMetrics(registry, store);
	}

	/** Contributes {@code outbox} to the aggregate health status (not to readiness). */
	@Bean
	OutboxHealthIndicator outboxHealthIndicator(OutboxStore store, MessagingProperties properties) {
		return new OutboxHealthIndicator(store, properties.getOutbox().getMaxPendingAge());
	}

	@Bean
	OutboxPublisher outboxPublisher(OutboxStore store, RabbitTemplate rabbitTemplate, MessagingProperties properties,
			OutboxMetrics metrics) {
		return new OutboxPublisher(store, rabbitTemplate, OutboxRoutes.standard(), properties.getOutbox(), metrics,
				"sentinel-api-" + UUID.randomUUID());
	}

	/** Runs the publisher periodically; disable to run publication elsewhere (or in tests). */
	@Configuration(proxyBeanMethods = false)
	@EnableScheduling
	@ConditionalOnBooleanProperty(name = "sentinel.messaging.outbox.publisher-enabled", matchIfMissing = true)
	static class OutboxPublisherScheduler {

		private static final Logger log = LoggerFactory.getLogger(OutboxPublisherScheduler.class);

		private final OutboxPublisher publisher;

		OutboxPublisherScheduler(OutboxPublisher publisher) {
			this.publisher = publisher;
		}

		@Scheduled(fixedDelayString = "${sentinel.messaging.outbox.poll-interval-ms:1000}",
				initialDelayString = "${sentinel.messaging.outbox.poll-interval-ms:1000}")
		void publishDueEvents() {
			try {
				this.publisher.publishBatch();
			}
			catch (RuntimeException ex) {
				// Typically the database is unavailable; the next run retries.
				log.warn("outbox.run_failed error_type={}", ex.getClass().getSimpleName());
			}
		}

	}

}

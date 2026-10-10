package dev.sentinelpipe.api.messaging;

import io.micrometer.core.instrument.MeterRegistry;
import java.util.UUID;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** Test support: publishers that crash at precise points of the publication protocol. */
public final class CrashingPublishers {

	/** Thrown where a real publisher process would have died. */
	public static final class SimulatedCrash extends RuntimeException {

		SimulatedCrash(String message) {
			super(message);
		}

	}

	private CrashingPublishers() {
	}

	/**
	 * A publisher that dies after the broker confirmed a publication but before the outbox
	 * row is marked PUBLISHED. The event stays PENDING and leased by this publisher.
	 */
	public static OutboxPublisher crashAfterBrokerConfirm(NamedParameterJdbcTemplate jdbc, RabbitTemplate rabbitTemplate,
			MeterRegistry registry, OutboxStore store) {
		OutboxStore crashingStore = new OutboxStore(jdbc) {
			@Override
			public boolean markPublished(UUID eventId, String owner) {
				throw new SimulatedCrash("simulated crash after broker confirm");
			}
		};
		MessagingProperties.Outbox settings = new MessagingProperties.Outbox();
		return new OutboxPublisher(crashingStore, rabbitTemplate, OutboxRoutes.standard(), settings,
				new OutboxMetrics(registry, store), "crashed-publisher");
	}

}

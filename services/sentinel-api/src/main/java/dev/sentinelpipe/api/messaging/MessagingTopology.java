package dev.sentinelpipe.api.messaging;

import java.util.Map;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Declarables;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.FanoutExchange;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * RabbitMQ topology, mirroring {@code packages/contracts/messaging/topology.v1.json}
 * (verified by tests).
 *
 * <pre>
 * sentinel.scan-requests (direct) --scan.requested.v1--> sentinel.scan-requests.worker (quorum)
 *   worker: permanent failure / delivery limit --> sentinel.scan-requests.dlx (fanout)
 *                                                  --> sentinel.scan-requests.dead-letter (quorum)
 *   worker: transient failure --> sentinel.scan-requests.retry (fanout)
 *        --> sentinel.scan-requests.retry (quorum, TTL) --expired--> sentinel.scan-requests
 * </pre>
 *
 * RabbitMQ 4 does not count explicit requeues towards a quorum queue's delivery limit,
 * so transient retries go through the delayed retry queue and are counted by the worker
 * in a header; the delivery limit remains the backstop for consumer crash loops.
 *
 * Quorum queues are replicated and durable, and their delivery limit turns an endless
 * redelivery loop of a poison message into dead-lettering. {@code reject-publish}
 * overflow makes a full queue nack new publications, so the outbox retries later
 * instead of losing events, and enables at-least-once dead-lettering.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(MessagingProperties.class)
public class MessagingTopology {

	public static final String SCAN_REQUESTS_EXCHANGE = "sentinel.scan-requests";

	public static final String SCAN_REQUESTS_QUEUE = "sentinel.scan-requests.worker";

	public static final String DEAD_LETTER_EXCHANGE = "sentinel.scan-requests.dlx";

	public static final String DEAD_LETTER_QUEUE = "sentinel.scan-requests.dead-letter";

	public static final String RETRY_EXCHANGE = "sentinel.scan-requests.retry";

	public static final String RETRY_QUEUE = "sentinel.scan-requests.retry";

	static final int RETRY_DELAY_MS = 15_000;

	public static final String SCAN_REQUESTED_ROUTING_KEY = "scan.requested.v1";

	static final int DELIVERY_LIMIT = 5;

	static final int MAX_QUEUE_LENGTH = 100_000;

	@Bean
	@ConditionalOnBooleanProperty(name = "sentinel.messaging.declare-topology", matchIfMissing = true)
	Declarables sentinelMessagingTopology() {
		DirectExchange scanRequests = new DirectExchange(SCAN_REQUESTS_EXCHANGE, true, false);
		FanoutExchange deadLetters = new FanoutExchange(DEAD_LETTER_EXCHANGE, true, false);
		FanoutExchange retries = new FanoutExchange(RETRY_EXCHANGE, true, false);
		Queue workerQueue = QueueBuilder.durable(SCAN_REQUESTS_QUEUE)
			.withArguments(Map.of("x-queue-type", "quorum", "x-delivery-limit", DELIVERY_LIMIT,
					"x-dead-letter-exchange", DEAD_LETTER_EXCHANGE, "x-dead-letter-strategy", "at-least-once",
					"x-overflow", "reject-publish", "x-max-length", MAX_QUEUE_LENGTH))
			.build();
		Queue deadLetterQueue = QueueBuilder.durable(DEAD_LETTER_QUEUE)
			.withArguments(Map.of("x-queue-type", "quorum"))
			.build();
		Queue retryQueue = QueueBuilder.durable(RETRY_QUEUE)
			.withArguments(Map.of("x-queue-type", "quorum", "x-message-ttl", RETRY_DELAY_MS, "x-dead-letter-exchange",
					SCAN_REQUESTS_EXCHANGE, "x-dead-letter-routing-key", SCAN_REQUESTED_ROUTING_KEY,
					"x-dead-letter-strategy", "at-least-once", "x-overflow", "reject-publish", "x-max-length",
					MAX_QUEUE_LENGTH))
			.build();
		Binding scanRequested = BindingBuilder.bind(workerQueue).to(scanRequests).with(SCAN_REQUESTED_ROUTING_KEY);
		Binding deadLettered = BindingBuilder.bind(deadLetterQueue).to(deadLetters);
		Binding retried = BindingBuilder.bind(retryQueue).to(retries);
		return new Declarables(scanRequests, deadLetters, retries, workerQueue, deadLetterQueue, retryQueue,
				scanRequested, deadLettered, retried);
	}

}

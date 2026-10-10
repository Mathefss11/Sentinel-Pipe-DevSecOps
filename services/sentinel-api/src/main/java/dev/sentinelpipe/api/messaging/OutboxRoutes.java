package dev.sentinelpipe.api.messaging;

import java.util.Map;
import java.util.Optional;

/** Maps outbox event types to their exchange and routing key. */
public final class OutboxRoutes {

	public static final String SCAN_REQUESTED = "scan.requested";

	/** Destination of one event type. */
	public record Route(String exchange, String routingKey) {
	}

	private final Map<String, Route> routes;

	public OutboxRoutes(Map<String, Route> routes) {
		this.routes = Map.copyOf(routes);
	}

	/** The production routing table (see packages/contracts/messaging/topology.v1.json). */
	public static OutboxRoutes standard() {
		return new OutboxRoutes(Map.of(SCAN_REQUESTED, new Route(MessagingTopology.SCAN_REQUESTS_EXCHANGE,
				MessagingTopology.SCAN_REQUESTED_ROUTING_KEY)));
	}

	public Optional<Route> routeFor(String eventType) {
		return Optional.ofNullable(this.routes.get(eventType));
	}

}

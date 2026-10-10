package dev.sentinelpipe.api.messaging;

import java.sql.Timestamp;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persistence of outbox events.
 *
 * <p>
 * All lease and retry times use the database clock ({@code now()}), so publishers on
 * hosts with skewed clocks agree on lease expiry. Every state change after a claim is
 * fenced by {@code lease_owner}: a publisher that lost its lease cannot overwrite the
 * outcome recorded by the publisher that took over.
 */
@Repository
public class OutboxStore {

	private final NamedParameterJdbcTemplate jdbc;

	OutboxStore(NamedParameterJdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	/**
	 * Appends an event. Must run inside the transaction that performs the corresponding
	 * state change, so both commit or roll back together.
	 */
	@Transactional(propagation = Propagation.MANDATORY)
	public void append(OutboxEvent event) {
		this.jdbc.update("""
				INSERT INTO outbox_events (id, event_type, schema_version, aggregate_type, aggregate_id,
				    organization_id, correlation_id, payload, status, attempts, next_attempt_at,
				    created_at, updated_at)
				VALUES (:id, :eventType, :schemaVersion, :aggregateType, :aggregateId, :organizationId,
				    :correlationId, CAST(:payload AS jsonb), 'PENDING', 0, :createdAt, :createdAt, :createdAt)
				""",
				new MapSqlParameterSource().addValue("id", event.eventId())
					.addValue("eventType", event.eventType())
					.addValue("schemaVersion", event.schemaVersion())
					.addValue("aggregateType", event.aggregateType())
					.addValue("aggregateId", event.aggregateId())
					.addValue("organizationId", event.organizationId())
					.addValue("correlationId", event.correlationId())
					.addValue("payload", event.payload())
					.addValue("createdAt", Timestamp.from(event.createdAt())));
	}

	/**
	 * Atomically claims up to {@code batchSize} due events for {@code owner}.
	 * {@code FOR UPDATE SKIP LOCKED} lets concurrent publishers claim disjoint sets
	 * without blocking each other; an expired lease (crashed publisher) is claimable
	 * again. The attempt counter is incremented at claim time, so an event that crashes
	 * its publisher repeatedly still exhausts its attempts.
	 */
	@Transactional
	public List<OutboxEvent.Claimed> claim(String owner, int batchSize, Duration lease, int maxAttempts) {
		return this.jdbc.query("""
				WITH candidates AS (
				    SELECT id FROM outbox_events
				    WHERE status = 'PENDING'
				      AND attempts < :maxAttempts
				      AND next_attempt_at <= now()
				      AND (lease_expires_at IS NULL OR lease_expires_at <= now())
				    ORDER BY next_attempt_at, created_at
				    LIMIT :batchSize
				    FOR UPDATE SKIP LOCKED
				)
				UPDATE outbox_events o
				SET lease_owner = :owner,
				    lease_expires_at = now() + make_interval(secs => :leaseSeconds),
				    attempts = o.attempts + 1,
				    updated_at = now()
				FROM candidates c
				WHERE o.id = c.id
				RETURNING o.id, o.event_type, o.schema_version, o.aggregate_id, o.organization_id,
				    o.correlation_id, o.payload::text AS payload, o.attempts, o.created_at
				""",
				new MapSqlParameterSource().addValue("owner", owner)
					.addValue("batchSize", batchSize)
					.addValue("maxAttempts", maxAttempts)
					.addValue("leaseSeconds", (double) lease.toMillis() / 1000),
				(rs, row) -> new OutboxEvent.Claimed(rs.getObject("id", UUID.class), rs.getString("event_type"),
						rs.getInt("schema_version"), rs.getObject("aggregate_id", UUID.class),
						rs.getObject("organization_id", UUID.class), rs.getObject("correlation_id", UUID.class),
						rs.getString("payload"), rs.getInt("attempts"), rs.getTimestamp("created_at").toInstant()));
	}

	/** Records a confirmed publication. Returns false if the lease was lost meanwhile. */
	@Transactional
	public boolean markPublished(UUID eventId, String owner) {
		return this.jdbc.update("""
				UPDATE outbox_events
				SET status = 'PUBLISHED', published_at = now(), updated_at = now(),
				    lease_owner = NULL, lease_expires_at = NULL, last_error = NULL
				WHERE id = :id AND lease_owner = :owner AND status = 'PENDING'
				""", Map.of("id", eventId, "owner", owner)) == 1;
	}

	/**
	 * Records a failed attempt: schedules a retry after {@code retryDelay}, or marks the
	 * event FAILED once {@code maxAttempts} is reached. Returns false if the lease was
	 * lost meanwhile.
	 */
	@Transactional
	public boolean markAttemptFailed(UUID eventId, String owner, PublicationFailure failure, Duration retryDelay,
			int maxAttempts) {
		return this.jdbc.update("""
				UPDATE outbox_events
				SET status = CASE WHEN attempts >= :maxAttempts THEN 'FAILED' ELSE 'PENDING' END,
				    next_attempt_at = now() + make_interval(secs => :delaySeconds),
				    last_error = :failure, updated_at = now(),
				    lease_owner = NULL, lease_expires_at = NULL
				WHERE id = :id AND lease_owner = :owner AND status = 'PENDING'
				""",
				new MapSqlParameterSource().addValue("id", eventId)
					.addValue("owner", owner)
					.addValue("failure", failure.name())
					.addValue("delaySeconds", (double) retryDelay.toMillis() / 1000)
					.addValue("maxAttempts", maxAttempts)) == 1;
	}

	/**
	 * Releases claimed events that this publisher did not attempt (its lease budget ran
	 * out), restoring their attempt counter so they are claimable again immediately.
	 */
	@Transactional
	public int releaseUnattempted(java.util.Collection<UUID> eventIds, String owner) {
		if (eventIds.isEmpty()) {
			return 0;
		}
		return this.jdbc.update("""
				UPDATE outbox_events
				SET attempts = attempts - 1, lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
				WHERE id IN (:ids) AND lease_owner = :owner AND status = 'PENDING' AND attempts > 0
				""", new MapSqlParameterSource().addValue("ids", eventIds).addValue("owner", owner));
	}

	/**
	 * Marks PENDING events FAILED that have no attempts left and are not being published:
	 * their publisher crashed during the final attempt (lease expired), or the attempt
	 * limit was lowered by configuration.
	 */
	@Transactional
	public int failAbandonedFinalAttempts(int maxAttempts) {
		return this.jdbc.update("""
				UPDATE outbox_events
				SET status = 'FAILED', last_error = 'LEASE_EXPIRED', updated_at = now(),
				    lease_owner = NULL, lease_expires_at = NULL
				WHERE status = 'PENDING' AND attempts >= :maxAttempts
				  AND (lease_expires_at IS NULL OR lease_expires_at <= now())
				""", Map.of("maxAttempts", maxAttempts));
	}

	/**
	 * Returns a FAILED event to PENDING for immediate publication, resetting its attempts.
	 * Operator recovery action (see docs/runbooks/messaging.md).
	 */
	@Transactional
	public boolean requeueFailed(UUID eventId) {
		return this.jdbc.update("""
				UPDATE outbox_events
				SET status = 'PENDING', attempts = 0, next_attempt_at = now(), last_error = NULL,
				    updated_at = now()
				WHERE id = :id AND status = 'FAILED'
				""", Map.of("id", eventId)) == 1;
	}

	@Transactional(readOnly = true)
	public long countByStatus(String status) {
		Long count = this.jdbc.queryForObject("SELECT count(*) FROM outbox_events WHERE status = :status",
				Map.of("status", status), Long.class);
		return (count != null) ? count : 0;
	}

	/** Seconds since the oldest PENDING event was created; 0 when there is none. */
	@Transactional(readOnly = true)
	public double oldestPendingAgeSeconds() {
		Double age = this.jdbc.getJdbcTemplate().queryForObject("""
				SELECT coalesce(extract(epoch FROM now() - min(created_at)), 0)::double precision
				FROM outbox_events WHERE status = 'PENDING'
				""", Double.class);
		return (age != null) ? Math.max(age, 0) : 0;
	}

	/** PENDING events claimed by a publisher whose lease has expired. */
	@Transactional(readOnly = true)
	public long countExpiredLeases() {
		Long count = this.jdbc.getJdbcTemplate().queryForObject("""
				SELECT count(*) FROM outbox_events
				WHERE status = 'PENDING' AND lease_expires_at IS NOT NULL AND lease_expires_at <= now()
				""", Long.class);
		return (count != null) ? count : 0;
	}

}

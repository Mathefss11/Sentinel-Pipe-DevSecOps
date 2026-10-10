package dev.sentinelpipe.api.scan;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Releases expired idempotency keys in bounded batches (see {@link IdempotencyProperties}).
 *
 * <p>
 * Each batch is one short transaction that locks at most {@code cleanup-batch-size} rows
 * with {@code FOR UPDATE SKIP LOCKED}, so concurrent cleanups on several instances take
 * disjoint rows and never block scan creation or lifecycle updates for long. Only the two
 * key columns are cleared; no row is deleted. A request racing with the cleanup is
 * resolved by the same expiry rule either way (see {@code ScanService#requestScan}).
 */
public class IdempotencyKeyCleanup {

	static final String RELEASED_KEYS = "sentinel.idempotency.keys.released";

	private static final Logger log = LoggerFactory.getLogger(IdempotencyKeyCleanup.class);

	private final NamedParameterJdbcTemplate jdbc;

	private final TransactionTemplate transaction;

	private final IdempotencyProperties properties;

	private final Clock clock;

	private final Counter released;

	public IdempotencyKeyCleanup(NamedParameterJdbcTemplate jdbc, PlatformTransactionManager transactionManager,
			IdempotencyProperties properties, Clock clock, MeterRegistry registry) {
		properties.validate();
		this.jdbc = jdbc;
		this.transaction = new TransactionTemplate(transactionManager);
		this.properties = properties;
		this.clock = clock;
		this.released = Counter.builder(RELEASED_KEYS)
			.description("Expired scan idempotency keys released by the cleanup")
			.register(registry);
	}

	/** Runs up to {@code cleanup-max-batches} batches. Returns the number of released keys. */
	public int run() {
		Instant cutoff = this.properties.cutoff(this.clock.instant());
		int total = 0;
		for (int batch = 0; batch < this.properties.getCleanupMaxBatches(); batch++) {
			int count = releaseBatch(cutoff);
			total += count;
			if (count < this.properties.getCleanupBatchSize()) {
				break;
			}
		}
		if (total > 0) {
			this.released.increment(total);
			log.info("idempotency.keys_released count={} retention={}", total, this.properties.getRetention());
		}
		return total;
	}

	int releaseBatch(Instant cutoff) {
		Integer count = this.transaction.execute((status) -> this.jdbc.update("""
				WITH expired AS (
				    SELECT id FROM scans
				    WHERE idempotency_key IS NOT NULL AND requested_at <= :cutoff
				    ORDER BY requested_at, id
				    LIMIT :batchSize
				    FOR UPDATE SKIP LOCKED
				)
				UPDATE scans s
				SET idempotency_key = NULL, request_fingerprint = NULL
				FROM expired e
				WHERE s.id = e.id
				""", new MapSqlParameterSource().addValue("cutoff", Timestamp.from(cutoff))
			.addValue("batchSize", this.properties.getCleanupBatchSize())));
		return (count != null) ? count : 0;
	}

}

package dev.sentinelpipe.api.scan;

import java.time.Duration;
import java.time.Instant;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Lifecycle of scan {@code Idempotency-Key}s ({@code sentinel.idempotency.*}).
 *
 * <p>
 * A key is honored for {@link #getRetention() retention} after the scan it created was
 * requested. A key whose scan was requested at or before {@code now - retention} is
 * <b>expired</b>: it is never replayed, and a request reusing it creates a new scan.
 * Expired keys are released from their scans lazily (when reused) and by a bounded
 * periodic cleanup. Releasing a key only clears {@code scans.idempotency_key} and
 * {@code scans.request_fingerprint}; scans, outbox events and audit evidence are never
 * deleted.
 */
@ConfigurationProperties("sentinel.idempotency")
public class IdempotencyProperties {

	static final Duration MIN_RETENTION = Duration.ofHours(1);

	static final Duration MAX_RETENTION = Duration.ofDays(30);

	/** How long a key replays its scan. */
	private Duration retention = Duration.ofHours(24);

	/** Run the periodic cleanup in this instance (safe on many instances). */
	private boolean cleanupEnabled = true;

	/** Delay between cleanup runs. */
	private Duration cleanupInterval = Duration.ofMinutes(10);

	/** Keys released per transaction. */
	private int cleanupBatchSize = 500;

	/** Upper bound of batches per run, so one run never holds the scheduler for long. */
	private int cleanupMaxBatches = 20;

	public Duration getRetention() {
		return this.retention;
	}

	public void setRetention(Duration retention) {
		this.retention = retention;
	}

	public boolean isCleanupEnabled() {
		return this.cleanupEnabled;
	}

	public void setCleanupEnabled(boolean cleanupEnabled) {
		this.cleanupEnabled = cleanupEnabled;
	}

	public Duration getCleanupInterval() {
		return this.cleanupInterval;
	}

	public void setCleanupInterval(Duration cleanupInterval) {
		this.cleanupInterval = cleanupInterval;
	}

	public int getCleanupBatchSize() {
		return this.cleanupBatchSize;
	}

	public void setCleanupBatchSize(int cleanupBatchSize) {
		this.cleanupBatchSize = cleanupBatchSize;
	}

	public int getCleanupMaxBatches() {
		return this.cleanupMaxBatches;
	}

	public void setCleanupMaxBatches(int cleanupMaxBatches) {
		this.cleanupMaxBatches = cleanupMaxBatches;
	}

	/** Scans requested at or before this instant hold expired keys. */
	Instant cutoff(Instant now) {
		return now.minus(this.retention);
	}

	boolean isExpired(Instant requestedAt, Instant now) {
		return !requestedAt.isAfter(cutoff(now));
	}

	/** Fails startup on unsafe values. */
	void validate() {
		if (this.retention == null || this.retention.compareTo(MIN_RETENTION) < 0
				|| this.retention.compareTo(MAX_RETENTION) > 0) {
			throw new IllegalStateException("sentinel.idempotency.retention must be between 1h and 30d");
		}
		if (this.cleanupInterval == null || this.cleanupInterval.compareTo(Duration.ofSeconds(10)) < 0) {
			throw new IllegalStateException("sentinel.idempotency.cleanup-interval must be at least 10s");
		}
		if (this.cleanupBatchSize < 1 || this.cleanupBatchSize > 5000) {
			throw new IllegalStateException("sentinel.idempotency.cleanup-batch-size must be between 1 and 5000");
		}
		if (this.cleanupMaxBatches < 1 || this.cleanupMaxBatches > 1000) {
			throw new IllegalStateException("sentinel.idempotency.cleanup-max-batches must be between 1 and 1000");
		}
	}

}

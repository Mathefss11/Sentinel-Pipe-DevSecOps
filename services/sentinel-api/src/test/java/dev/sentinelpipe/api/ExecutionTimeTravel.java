package dev.sentinelpipe.api;

import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Superuser fixtures that move execution timestamps into the past, so lease expiry,
 * retry backoff and hard deadlines are tested deterministically instead of by sleeping.
 * Only timestamps are changed; states are always produced by the real lifecycle functions.
 */
public final class ExecutionTimeTravel {

	private final JdbcTemplate admin;

	public ExecutionTimeTravel(TestDatabaseAdmin admin) {
		this.admin = admin.jdbc();
	}

	/** The job's current lease expired a second ago (worker crashed or stopped renewing). */
	public void expireLease(UUID jobId) {
		this.admin.update("UPDATE scan_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = ?", jobId);
	}

	/** The job's retry backoff has elapsed. */
	public void makeRetryDue(UUID jobId) {
		this.admin.update("UPDATE scan_jobs SET next_attempt_at = now() - interval '1 second' WHERE id = ?", jobId);
	}

	/** The scan was requested and started two hours ago and its deadline passed a second ago. */
	public void passDeadline(UUID scanId) {
		this.admin.update("""
				UPDATE scans SET requested_at = requested_at - interval '2 hours',
				                 started_at = started_at - interval '2 hours',
				                 deadline_at = now() - interval '1 second'
				WHERE id = ?""", scanId);
	}

}

package dev.sentinelpipe.api.scanjob;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One scanner execution within a scan.
 *
 * <p>
 * The API only <b>plans</b> jobs ({@link #plan}). Every later transition (claim, lease
 * renewal, completion, retry, failure, cancellation) is performed by the database
 * execution protocol (Flyway V007, ADR-0007), which authenticates the worker, fences stale
 * leases and enforces {@link #MAX_ATTEMPTS}. The API's database role has no UPDATE
 * privilege on this table, so the lifecycle columns are mapped read-only.
 */
@Entity
@Table(name = "scan_jobs")
public class ScanJob {

	/** Upper bound on execution attempts, including the first one (also enforced in V007). */
	public static final int MAX_ATTEMPTS = 3;

	@Id
	private UUID id;

	@Version
	private Long version;

	@Column(name = "scan_id", nullable = false, updatable = false)
	private UUID scanId;

	@Enumerated(EnumType.STRING)
	@Column(name = "scanner_type", nullable = false, length = 20, updatable = false)
	private ScannerType scannerType;

	@Enumerated(EnumType.STRING)
	@Column(name = "execution_status", nullable = false, length = 20, updatable = false)
	private ScanJobStatus executionStatus;

	@Column(name = "attempt_count", nullable = false, updatable = false)
	private int attemptCount;

	@Enumerated(EnumType.STRING)
	@Column(name = "failure_reason", length = 40, insertable = false, updatable = false)
	private JobFailureReason failureReason;

	@Column(name = "next_attempt_at", insertable = false, updatable = false)
	private Instant nextAttemptAt;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "started_at", updatable = false)
	private Instant startedAt;

	@Column(name = "completed_at", updatable = false)
	private Instant completedAt;

	@Column(name = "updated_at", nullable = false, updatable = false)
	private Instant updatedAt;

	protected ScanJob() {
		// for JPA
	}

	public static ScanJob plan(UUID scanId, ScannerType scannerType, Instant now) {
		ScanJob job = new ScanJob();
		job.id = UUID.randomUUID();
		job.scanId = Objects.requireNonNull(scanId, "scanId");
		job.scannerType = Objects.requireNonNull(scannerType, "scannerType");
		job.executionStatus = ScanJobStatus.QUEUED;
		job.attemptCount = 0;
		job.createdAt = Objects.requireNonNull(now, "now");
		job.updatedAt = now;
		return job;
	}

	public UUID getId() {
		return this.id;
	}

	public UUID getScanId() {
		return this.scanId;
	}

	public ScannerType getScannerType() {
		return this.scannerType;
	}

	public ScanJobStatus getExecutionStatus() {
		return this.executionStatus;
	}

	public int getAttemptCount() {
		return this.attemptCount;
	}

	public JobFailureReason getFailureReason() {
		return this.failureReason;
	}

	public Instant getNextAttemptAt() {
		return this.nextAttemptAt;
	}

	public Instant getCreatedAt() {
		return this.createdAt;
	}

	public Instant getStartedAt() {
		return this.startedAt;
	}

	public Instant getCompletedAt() {
		return this.completedAt;
	}

	public Instant getUpdatedAt() {
		return this.updatedAt;
	}

}

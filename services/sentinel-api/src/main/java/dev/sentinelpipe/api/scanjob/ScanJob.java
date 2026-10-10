package dev.sentinelpipe.api.scanjob;

import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.InvalidStateTransitionException;
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
 * One scanner execution within a scan. Execution is not implemented in this phase; the
 * entity models and enforces the lifecycle that trusted internal components will drive.
 */
@Entity
@Table(name = "scan_jobs")
public class ScanJob {

	/** Upper bound on execution attempts, including the first one. */
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
	@Column(name = "execution_status", nullable = false, length = 20)
	private ScanJobStatus executionStatus;

	@Column(name = "attempt_count", nullable = false)
	private int attemptCount;

	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@Column(name = "started_at")
	private Instant startedAt;

	@Column(name = "completed_at")
	private Instant completedAt;

	@Column(name = "updated_at", nullable = false)
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

	/** Starts a new attempt. */
	public void start(Instant now) {
		if (this.executionStatus == ScanJobStatus.QUEUED && this.attemptCount >= MAX_ATTEMPTS) {
			throw new DomainRuleViolationException("Scan job has exhausted its " + MAX_ATTEMPTS + " attempts");
		}
		transitionTo(ScanJobStatus.RUNNING, now);
		this.attemptCount++;
		this.startedAt = now;
	}

	/** The scanner finished and produced its output. Says nothing about findings. */
	public void complete(Instant now) {
		transitionTo(ScanJobStatus.COMPLETED, now);
		this.completedAt = now;
	}

	/** Returns a running job to the queue after a transient failure, if attempts remain. */
	public void requeueForRetry(Instant now) {
		if (this.executionStatus == ScanJobStatus.RUNNING && this.attemptCount >= MAX_ATTEMPTS) {
			throw new DomainRuleViolationException("Scan job has exhausted its " + MAX_ATTEMPTS + " attempts");
		}
		transitionTo(ScanJobStatus.QUEUED, now);
		this.startedAt = null;
	}

	public void fail(Instant now) {
		transitionTo(ScanJobStatus.FAILED, now);
		this.completedAt = now;
	}

	public void cancel(Instant now) {
		transitionTo(ScanJobStatus.CANCELLED, now);
		this.completedAt = now;
	}

	private void transitionTo(ScanJobStatus target, Instant now) {
		Objects.requireNonNull(now, "now");
		if (!this.executionStatus.canTransitionTo(target)) {
			throw new InvalidStateTransitionException("ScanJob", this.executionStatus, target);
		}
		if (now.isBefore(this.updatedAt)) {
			throw new DomainRuleViolationException("Scan job timestamps must not move backwards");
		}
		this.executionStatus = target;
		this.updatedAt = now;
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

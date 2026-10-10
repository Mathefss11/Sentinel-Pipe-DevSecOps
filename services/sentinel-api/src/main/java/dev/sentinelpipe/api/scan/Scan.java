package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.GitBranchNames;
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
 * One security analysis request for a specific commit of a project.
 *
 * <p>
 * Invariants (enforced by database CHECK constraints and the V007 lifecycle functions):
 * <ul>
 * <li>the security decision is {@code PENDING} exactly while execution is non-terminal;</li>
 * <li>{@code FAILED} and {@code CANCELLED} scans are always {@code INCOMPLETE} (fail
 * closed); {@code PASS} requires every job to have completed and a policy evaluation;</li>
 * <li>terminal scans are immutable;</li>
 * <li>identifiers and timestamps are generated server-side.</li>
 * </ul>
 * The API creates scans ({@link #request}). Execution state changes only through the
 * database lifecycle functions (ADR-0007): the API's database role has no UPDATE privilege
 * on the lifecycle columns, which are therefore mapped read-only.
 */
@Entity
@Table(name = "scans")
public class Scan {

	/** Bounds mirrored by the {@code ck_scans_lease_duration} constraint. */
	static final int MIN_LEASE_SECONDS = 15;

	static final int MAX_LEASE_SECONDS = 600;

	/** Bounds mirrored by the {@code ck_scans_execution_timeout} constraint. */
	static final int MIN_TIMEOUT_SECONDS = 60;

	static final int MAX_TIMEOUT_SECONDS = 86_400;

	/** Bounds mirrored by the {@code ck_scans_evidence_retention} constraint. */
	static final int MIN_RETENTION_DAYS = 1;

	static final int MAX_RETENTION_DAYS = 3650;

	@Id
	private UUID id;

	@Version
	private Long version;

	@Column(name = "project_id", nullable = false, updatable = false)
	private UUID projectId;

	@Column(name = "commit_sha", nullable = false, length = 64, updatable = false)
	private String commitSha;

	@Column(nullable = false, length = 255, updatable = false)
	private String branch;

	@Enumerated(EnumType.STRING)
	@Column(name = "trigger_type", nullable = false, length = 20, updatable = false)
	private TriggerType triggerType;

	@Enumerated(EnumType.STRING)
	@Column(name = "execution_status", nullable = false, length = 20, updatable = false)
	private ScanExecutionStatus executionStatus;

	@Enumerated(EnumType.STRING)
	@Column(name = "security_decision", nullable = false, length = 20, updatable = false)
	private SecurityDecision securityDecision;

	@Enumerated(EnumType.STRING)
	@Column(name = "decision_reason", length = 40, insertable = false, updatable = false)
	private DecisionReason decisionReason;

	@Column(name = "idempotency_key", length = 128, updatable = false)
	private String idempotencyKey;

	@Column(name = "request_fingerprint", length = 64, updatable = false)
	private String requestFingerprint;

	@Column(name = "lease_duration_seconds", nullable = false, updatable = false)
	private int leaseDurationSeconds;

	@Column(name = "execution_timeout_seconds", nullable = false, updatable = false)
	private int executionTimeoutSeconds;

	@Column(name = "evidence_retention_days", nullable = false, updatable = false)
	private int evidenceRetentionDays;

	@Column(name = "requested_at", nullable = false, updatable = false)
	private Instant requestedAt;

	@Column(name = "started_at", updatable = false)
	private Instant startedAt;

	@Column(name = "deadline_at", insertable = false, updatable = false)
	private Instant deadlineAt;

	@Column(name = "completed_at", updatable = false)
	private Instant completedAt;

	@Column(name = "updated_at", nullable = false, updatable = false)
	private Instant updatedAt;

	protected Scan() {
		// for JPA
	}

	/**
	 * Creates a queued scan. {@code idempotencyKey} and {@code requestFingerprint} are
	 * either both present or both absent. Every job lease of the scan lasts
	 * {@code leaseDurationSeconds} (renewed by heartbeats); execution must end within
	 * {@code executionTimeoutSeconds} of the first claim. Evidence content is retained for
	 * {@code evidenceRetentionDays} after upload.
	 */
	static Scan request(UUID projectId, String commitSha, String branch, TriggerType triggerType,
			String idempotencyKey, String requestFingerprint, int leaseDurationSeconds, int executionTimeoutSeconds,
			int evidenceRetentionDays, Instant now) {
		if ((idempotencyKey == null) != (requestFingerprint == null)) {
			throw new IllegalArgumentException("idempotencyKey and requestFingerprint must be set together");
		}
		if (leaseDurationSeconds < MIN_LEASE_SECONDS || leaseDurationSeconds > MAX_LEASE_SECONDS) {
			throw new IllegalArgumentException("leaseDurationSeconds out of range");
		}
		if (executionTimeoutSeconds < MIN_TIMEOUT_SECONDS || executionTimeoutSeconds > MAX_TIMEOUT_SECONDS
				|| executionTimeoutSeconds <= leaseDurationSeconds) {
			throw new IllegalArgumentException("executionTimeoutSeconds out of range");
		}
		if (evidenceRetentionDays < MIN_RETENTION_DAYS || evidenceRetentionDays > MAX_RETENTION_DAYS) {
			throw new IllegalArgumentException("evidenceRetentionDays out of range");
		}
		Scan scan = new Scan();
		scan.id = UUID.randomUUID();
		scan.projectId = Objects.requireNonNull(projectId, "projectId");
		scan.commitSha = CommitShas.normalize(commitSha);
		scan.branch = GitBranchNames.require("branch", branch);
		scan.triggerType = Objects.requireNonNull(triggerType, "triggerType");
		scan.executionStatus = ScanExecutionStatus.QUEUED;
		scan.securityDecision = SecurityDecision.PENDING;
		scan.idempotencyKey = idempotencyKey;
		scan.requestFingerprint = requestFingerprint;
		scan.leaseDurationSeconds = leaseDurationSeconds;
		scan.executionTimeoutSeconds = executionTimeoutSeconds;
		scan.evidenceRetentionDays = evidenceRetentionDays;
		scan.requestedAt = Objects.requireNonNull(now, "now");
		scan.updatedAt = now;
		return scan;
	}

	boolean matchesFingerprint(String fingerprint) {
		return this.requestFingerprint != null && this.requestFingerprint.equals(fingerprint);
	}

	public UUID getId() {
		return this.id;
	}

	public UUID getProjectId() {
		return this.projectId;
	}

	public String getCommitSha() {
		return this.commitSha;
	}

	public String getBranch() {
		return this.branch;
	}

	public TriggerType getTriggerType() {
		return this.triggerType;
	}

	public ScanExecutionStatus getExecutionStatus() {
		return this.executionStatus;
	}

	public SecurityDecision getSecurityDecision() {
		return this.securityDecision;
	}

	public DecisionReason getDecisionReason() {
		return this.decisionReason;
	}

	public int getLeaseDurationSeconds() {
		return this.leaseDurationSeconds;
	}

	public int getExecutionTimeoutSeconds() {
		return this.executionTimeoutSeconds;
	}

	public int getEvidenceRetentionDays() {
		return this.evidenceRetentionDays;
	}

	public Instant getRequestedAt() {
		return this.requestedAt;
	}

	public Instant getStartedAt() {
		return this.startedAt;
	}

	public Instant getDeadlineAt() {
		return this.deadlineAt;
	}

	public Instant getCompletedAt() {
		return this.completedAt;
	}

	public Instant getUpdatedAt() {
		return this.updatedAt;
	}

}

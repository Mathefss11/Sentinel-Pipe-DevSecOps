package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.GitBranchNames;
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
 * One security analysis request for a specific commit of a project.
 *
 * <p>
 * Invariants (also enforced by database CHECK constraints):
 * <ul>
 * <li>the security decision is {@code PENDING} exactly while execution is non-terminal;</li>
 * <li>{@code FAILED} and {@code CANCELLED} scans are always {@code INCOMPLETE} (fail
 * closed);</li>
 * <li>terminal scans are immutable;</li>
 * <li>identifiers and timestamps are generated server-side.</li>
 * </ul>
 * Whether {@code PASS} is justified by the scan's jobs is checked by
 * {@link ScanLifecycleService}, which has access to them.
 */
@Entity
@Table(name = "scans")
public class Scan {

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
	@Column(name = "execution_status", nullable = false, length = 20)
	private ScanExecutionStatus executionStatus;

	@Enumerated(EnumType.STRING)
	@Column(name = "security_decision", nullable = false, length = 20)
	private SecurityDecision securityDecision;

	@Column(name = "idempotency_key", length = 128, updatable = false)
	private String idempotencyKey;

	@Column(name = "request_fingerprint", length = 64, updatable = false)
	private String requestFingerprint;

	@Column(name = "requested_at", nullable = false, updatable = false)
	private Instant requestedAt;

	@Column(name = "started_at")
	private Instant startedAt;

	@Column(name = "completed_at")
	private Instant completedAt;

	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

	protected Scan() {
		// for JPA
	}

	/**
	 * Creates a queued scan. {@code idempotencyKey} and {@code requestFingerprint} are
	 * either both present or both absent.
	 */
	static Scan request(UUID projectId, String commitSha, String branch, TriggerType triggerType,
			String idempotencyKey, String requestFingerprint, Instant now) {
		if ((idempotencyKey == null) != (requestFingerprint == null)) {
			throw new IllegalArgumentException("idempotencyKey and requestFingerprint must be set together");
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
		scan.requestedAt = Objects.requireNonNull(now, "now");
		scan.updatedAt = now;
		return scan;
	}

	void start(Instant now) {
		transitionTo(ScanExecutionStatus.RUNNING, now);
		this.startedAt = now;
	}

	/**
	 * Marks execution as completed with a final security decision. Completing execution
	 * never implies {@code PASS}; the caller must supply the evaluated decision.
	 */
	void complete(SecurityDecision decision, Instant now) {
		Objects.requireNonNull(decision, "decision");
		if (!decision.isFinal()) {
			throw new DomainRuleViolationException("A completed scan requires a final security decision");
		}
		transitionTo(ScanExecutionStatus.COMPLETED, now);
		this.securityDecision = decision;
		this.completedAt = now;
	}

	/** Execution failed. The security decision becomes {@code INCOMPLETE} (fail closed). */
	void fail(Instant now) {
		transitionTo(ScanExecutionStatus.FAILED, now);
		this.securityDecision = SecurityDecision.INCOMPLETE;
		this.completedAt = now;
	}

	/** Execution was cancelled. The security decision becomes {@code INCOMPLETE}. */
	void cancel(Instant now) {
		transitionTo(ScanExecutionStatus.CANCELLED, now);
		this.securityDecision = SecurityDecision.INCOMPLETE;
		this.completedAt = now;
	}

	private void transitionTo(ScanExecutionStatus target, Instant now) {
		Objects.requireNonNull(now, "now");
		if (!this.executionStatus.canTransitionTo(target)) {
			throw new InvalidStateTransitionException("Scan", this.executionStatus, target);
		}
		if (now.isBefore(this.updatedAt)) {
			throw new DomainRuleViolationException("Scan timestamps must not move backwards");
		}
		this.executionStatus = target;
		this.updatedAt = now;
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

	public Instant getRequestedAt() {
		return this.requestedAt;
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

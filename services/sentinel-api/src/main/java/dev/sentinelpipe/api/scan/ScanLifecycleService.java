package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.ConstraintViolations;
import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.common.Timestamps;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScanJobRepository;
import dev.sentinelpipe.api.scanjob.ScanJobStatus;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Control-plane lifecycle operations on scans and their jobs.
 *
 * <p>
 * Execution state is owned by the database (Flyway V007, ADR-0007). This service only
 * plans jobs (INSERT) and calls the lifecycle functions granted to the API's database
 * role; it cannot write lifecycle columns directly. Worker-side transitions (claim,
 * heartbeat, report) are not reachable from the API at all.
 *
 * <p>
 * Every function locks the scan row before its jobs, so operations on one scan are
 * serialized across application instances and workers.
 */
@Service
public class ScanLifecycleService {

	static final String SCANNER_ALREADY_PLANNED = "scanner-already-planned";

	static final String SCAN_NOT_CANCELLABLE = "scan-not-cancellable";

	private static final Logger log = LoggerFactory.getLogger(ScanLifecycleService.class);

	/** Result of a cancellation request; both outcomes leave the scan CANCELLED. */
	public enum Cancellation {

		CANCELLED, ALREADY_CANCELLED

	}

	private final ScanRepository scans;

	private final ScanJobRepository scanJobs;

	private final JdbcTemplate jdbc;

	private final ExecutionProperties execution;

	private final Clock clock;

	ScanLifecycleService(ScanRepository scans, ScanJobRepository scanJobs, JdbcTemplate jdbc,
			ExecutionProperties execution, Clock clock) {
		this.scans = scans;
		this.scanJobs = scanJobs;
		this.jdbc = jdbc;
		this.execution = execution;
		this.clock = clock;
	}

	/**
	 * Adds a scanner job to a scan that has not started yet. The scan row lock serializes
	 * planning with worker claims.
	 */
	@Transactional
	public ScanJob planJob(UUID scanId, ScannerType scannerType) {
		Objects.requireNonNull(scannerType, "scannerType");
		if (!this.execution.isPlannable(scannerType)) {
			throw new DomainRuleViolationException(
					"The FIXTURE scanner requires sentinel.execution.fixture-enabled=true");
		}
		Scan scan = this.scans.findByIdForUpdate(scanId)
			.orElseThrow(() -> new ResourceNotFoundException("Scan", scanId));
		if (scan.getExecutionStatus() != ScanExecutionStatus.QUEUED) {
			throw new DomainRuleViolationException("Scanner jobs can only be planned while the scan is QUEUED");
		}
		ScanJob job = ScanJob.plan(scanId, scannerType, Timestamps.now(this.clock));
		try {
			return this.scanJobs.saveAndFlush(job);
		}
		catch (DataIntegrityViolationException ex) {
			if (ConstraintViolations.isViolationOf(ex, "uq_scan_jobs_scan_scanner")) {
				throw new ConflictException(SCANNER_ALREADY_PLANNED, "This scanner is already planned for the scan.");
			}
			throw ex;
		}
	}

	/**
	 * Cancels a scan that has not reached a terminal state: the scan becomes CANCELLED with
	 * decision INCOMPLETE and its unfinished jobs are cancelled. A worker executing one of
	 * them is told on its next heartbeat and its report is rejected. Idempotent.
	 * @param actor audited identity of the requester (never a client-supplied value)
	 * @throws ConflictException if the scan already COMPLETED or FAILED
	 */
	@Transactional
	public Cancellation cancelScan(UUID scanId, String actor) {
		String outcome = call("SELECT lifecycle.cancel_scan(?, ?)", scanId, actor);
		return switch (outcome) {
			case "CANCELLED" -> {
				log.info("scan.cancelled scan_id={}", scanId);
				yield Cancellation.CANCELLED;
			}
			case "ALREADY_CANCELLED" -> Cancellation.ALREADY_CANCELLED;
			case "NOT_CANCELLABLE" -> throw new ConflictException(SCAN_NOT_CANCELLABLE,
					"The scan has already finished and cannot be cancelled.");
			case "NOT_FOUND" -> throw new ResourceNotFoundException("Scan", scanId);
			default -> throw unexpected(outcome);
		};
	}

	/** Marks a non-terminal scan FAILED (decision INCOMPLETE) and cancels its unfinished jobs. */
	@Transactional
	public void failScan(UUID scanId) {
		String outcome = call("SELECT lifecycle.fail_scan(?)", scanId);
		switch (outcome) {
			case "FAILED" -> log.info("scan.failed scan_id={}", scanId);
			case "TERMINAL" -> throw new DomainRuleViolationException("A terminal scan cannot be failed");
			case "NOT_FOUND" -> throw new ResourceNotFoundException("Scan", scanId);
			default -> throw unexpected(outcome);
		}
	}

	/**
	 * Records the security decision of an EVALUATING scan. Fail closed: PASS requires every
	 * job to have COMPLETED, and PASS or FAIL require reason {@code POLICY_EVALUATED}.
	 * @throws DomainRuleViolationException if the scan is not EVALUATING or the decision is
	 * not justified
	 */
	@Transactional
	public void completeEvaluation(UUID scanId, SecurityDecision decision, DecisionReason reason) {
		Objects.requireNonNull(decision, "decision");
		Objects.requireNonNull(reason, "reason");
		if (!decision.isFinal()) {
			throw new DomainRuleViolationException("A completed scan requires a final security decision");
		}
		if ((decision != SecurityDecision.INCOMPLETE) != (reason == DecisionReason.POLICY_EVALUATED)) {
			throw new DomainRuleViolationException("PASS and FAIL require a policy evaluation");
		}
		String outcome = call("SELECT lifecycle.complete_evaluation(?, ?, ?)", scanId, decision.name(),
				reason.name());
		switch (outcome) {
			case "COMPLETED" -> log.info("scan.completed scan_id={} decision={} reason={}", scanId, decision, reason);
			case "NOT_EVALUATING" -> throw new DomainRuleViolationException("The scan is not EVALUATING");
			case "REJECTED_PASS_NOT_JUSTIFIED" -> throw new DomainRuleViolationException(
					"PASS requires at least one scan job and every scan job to have COMPLETED");
			case "NOT_FOUND" -> throw new ResourceNotFoundException("Scan", scanId);
			default -> throw unexpected(outcome);
		}
	}

	/**
	 * Evaluates an EVALUATING scan with the evaluation available in this version: no policy
	 * engine exists yet (M4), so the decision is always INCOMPLETE, never PASS. Returns
	 * {@code false} if the scan is no longer EVALUATING (evaluated concurrently).
	 */
	@Transactional
	public boolean evaluate(UUID scanId) {
		List<ScanJobStatus> statuses = this.scanJobs.findByScanIdOrderByScannerTypeAsc(scanId)
			.stream()
			.map(ScanJob::getExecutionStatus)
			.toList();
		String outcome = call("SELECT lifecycle.complete_evaluation(?, ?, ?)", scanId,
				SecurityDecision.INCOMPLETE.name(), reasonWithoutPolicyEngine(statuses).name());
		if (outcome.equals("COMPLETED")) {
			log.info("scan.evaluated scan_id={} decision=INCOMPLETE reason={}", scanId,
					reasonWithoutPolicyEngine(statuses));
			return true;
		}
		if (outcome.equals("NOT_EVALUATING") || outcome.equals("NOT_FOUND")) {
			return false;
		}
		throw unexpected(outcome);
	}

	/**
	 * Explains the INCOMPLETE decision of a scan evaluated without a policy engine. A scan
	 * whose jobs all completed still lacks a policy evaluation; one with a failed or
	 * cancelled job also lacks evidence.
	 */
	static DecisionReason reasonWithoutPolicyEngine(List<ScanJobStatus> jobStatuses) {
		boolean allCompleted = !jobStatuses.isEmpty()
				&& jobStatuses.stream().allMatch((status) -> status == ScanJobStatus.COMPLETED);
		return allCompleted ? DecisionReason.POLICY_EVALUATION_UNAVAILABLE
				: DecisionReason.SCANNER_EXECUTION_INCOMPLETE;
	}

	private String call(String sql, Object... arguments) {
		String outcome = this.jdbc.queryForObject(sql, String.class, arguments);
		if (outcome == null) {
			throw unexpected("null");
		}
		return outcome;
	}

	private static IllegalStateException unexpected(String outcome) {
		return new IllegalStateException("Unexpected lifecycle function outcome: " + outcome);
	}

}

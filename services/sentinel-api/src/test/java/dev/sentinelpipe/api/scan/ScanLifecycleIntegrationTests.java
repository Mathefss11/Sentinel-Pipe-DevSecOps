package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.ExecutionTimeTravel;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScanJobStatus;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Scan lifecycle rules against real PostgreSQL: the API's lifecycle service (planning,
 * cancellation, evaluation) together with the worker protocol, so the database functions,
 * the CHECK constraints and the API's restricted privileges are all in play.
 */
class ScanLifecycleIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	private UUID scanId;

	@BeforeEach
	void queueScan() throws Exception {
		this.worker = WorkerProtocol.asWorker(this.admin);
		this.scanId = this.scanService.requestScan(createProject(), randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
	}

	private Map<String, Object> scanRow() {
		return this.jdbcTemplate.queryForMap("""
				SELECT execution_status, security_decision, decision_reason, started_at, deadline_at, completed_at
				FROM scans WHERE id = ?""", this.scanId);
	}

	private String jobStatus(UUID jobId) {
		return this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?", String.class,
				jobId);
	}

	/** Plans a FIXTURE job, claims it and reports COMPLETED: the scan becomes EVALUATING. */
	private Lease runFixtureToCompletion() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);
		Lease lease = this.worker.claimFixtureOrFail(this.scanId);
		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");
		return lease;
	}

	@Test
	void firstClaimStartsTheScanWithAHardDeadline() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);

		Lease lease = this.worker.claimFixtureOrFail(this.scanId);

		Map<String, Object> scan = scanRow();
		assertThat(scan).containsEntry("execution_status", "RUNNING").containsEntry("security_decision", "PENDING");
		assertThat(scan.get("started_at")).isNotNull();
		java.sql.Timestamp started = (java.sql.Timestamp) scan.get("started_at");
		java.sql.Timestamp deadline = (java.sql.Timestamp) scan.get("deadline_at");
		assertThat(deadline.toInstant()).isEqualTo(started.toInstant().plusSeconds(15 * 60));
		assertThat(lease.deadlineAt()).isEqualTo(deadline.toInstant());
		assertThat(lease.leaseDurationSeconds()).isEqualTo(60);
		assertThat(jobStatus(lease.jobId())).isEqualTo("RUNNING");
	}

	@Test
	void completedExecutionWaitsForEvaluationAndIsNeverPassWithoutAPolicyEngine() {
		runFixtureToCompletion();
		assertThat(scanRow()).containsEntry("execution_status", "EVALUATING")
			.containsEntry("security_decision", "PENDING");

		assertThat(this.lifecycle.evaluate(this.scanId)).isTrue();

		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "POLICY_EVALUATION_UNAVAILABLE");
		assertThat(scanRow().get("completed_at")).isNotNull();
		// Evaluating twice is a no-op.
		assertThat(this.lifecycle.evaluate(this.scanId)).isFalse();
	}

	@Test
	void completesWithPassOnlyWhenEveryJobCompletedAndAPolicyWasEvaluated() {
		runFixtureToCompletion();

		assertThatThrownBy(() -> this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.PASS,
				DecisionReason.POLICY_EVALUATION_UNAVAILABLE))
			.isInstanceOf(DomainRuleViolationException.class);
		this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.PASS, DecisionReason.POLICY_EVALUATED);

		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "PASS")
			.containsEntry("decision_reason", "POLICY_EVALUATED");
		assertThat(this.scanService.get(this.scanId).jobs()).extracting(ScanJob::getExecutionStatus)
			.containsOnly(ScanJobStatus.COMPLETED);
	}

	@Test
	void passIsRejectedWhenAJobFailedButFailAndIncompleteAreAllowed() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);
		Lease lease = this.worker.claimFixtureOrFail(this.scanId);
		assertThat(this.worker.fail(lease, "UNSUPPORTED_SCANNER")).isEqualTo("ACCEPTED");
		assertThat(jobStatus(lease.jobId())).isEqualTo("FAILED");
		assertThat(scanRow()).containsEntry("execution_status", "EVALUATING");

		assertThatThrownBy(() -> this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.PASS,
				DecisionReason.POLICY_EVALUATED))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThat(scanRow()).containsEntry("execution_status", "EVALUATING")
			.containsEntry("security_decision", "PENDING");

		this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.FAIL, DecisionReason.POLICY_EVALUATED);
		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "FAIL");
	}

	@Test
	void evaluationWithAFailedJobIsIncompleteForMissingEvidence() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);
		this.worker.fail(this.worker.claimFixtureOrFail(this.scanId), "RESOURCE_LIMIT_EXCEEDED");

		assertThat(this.lifecycle.evaluate(this.scanId)).isTrue();

		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "SCANNER_EXECUTION_INCOMPLETE");
	}

	@Test
	void decisionsRequireAnEvaluatingScan() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);

		assertThatThrownBy(() -> this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.INCOMPLETE,
				DecisionReason.POLICY_EVALUATION_UNAVAILABLE))
			.isInstanceOf(DomainRuleViolationException.class);
		this.worker.claimFixtureOrFail(this.scanId);
		assertThatThrownBy(() -> this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.FAIL,
				DecisionReason.POLICY_EVALUATED))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThat(scanRow()).containsEntry("execution_status", "RUNNING");
		assertThatThrownBy(() -> this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.PENDING,
				DecisionReason.POLICY_EVALUATED))
			.isInstanceOf(DomainRuleViolationException.class);
	}

	@Test
	void aScanWithoutJobsIsNeverStartedOrEvaluated() {
		assertThat(this.worker.claimFixture(this.scanId)).isEmpty();
		assertThat(this.lifecycle.evaluate(this.scanId)).isFalse();

		assertThat(scanRow()).containsEntry("execution_status", "QUEUED")
			.containsEntry("security_decision", "PENDING");
	}

	@Test
	void cancellationCancelsUnfinishedJobsAndIsIncomplete() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);
		Lease running = this.worker.claimFixtureOrFail(this.scanId);

		assertThat(this.lifecycle.cancelScan(this.scanId, "user:test"))
			.isEqualTo(ScanLifecycleService.Cancellation.CANCELLED);

		assertThat(scanRow()).containsEntry("execution_status", "CANCELLED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "CANCELLED_BY_USER");
		assertThat(jobStatus(running.jobId())).isEqualTo("CANCELLED");
		// The running worker learns about it on its next heartbeat and cannot report.
		assertThat(this.worker.heartbeat(running).status()).isEqualTo("CANCELLED");
		assertThat(this.worker.complete(running)).isEqualTo("REJECTED_JOB_NOT_RUNNING");
		// Idempotent.
		assertThat(this.lifecycle.cancelScan(this.scanId, "user:test"))
			.isEqualTo(ScanLifecycleService.Cancellation.ALREADY_CANCELLED);
	}

	@Test
	void queuedScansCanBeCancelledAndNothingIsClaimedAfterwards() {
		ScanJob job = this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);

		this.lifecycle.cancelScan(this.scanId, "user:test");

		assertThat(jobStatus(job.getId())).isEqualTo("CANCELLED");
		assertThat(this.worker.claimFixture(this.scanId)).isEmpty();
		assertThat(scanRow().get("started_at")).isNull();
	}

	@Test
	void failedScanIsIncomplete() {
		this.lifecycle.failScan(this.scanId);

		assertThat(scanRow()).containsEntry("execution_status", "FAILED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "EXECUTION_FAILED");
	}

	@Test
	void terminalScansCannotBeModified() {
		Lease lease = runFixtureToCompletion();
		this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.FAIL, DecisionReason.POLICY_EVALUATED);

		assertThatThrownBy(() -> this.lifecycle.completeEvaluation(this.scanId, SecurityDecision.PASS,
				DecisionReason.POLICY_EVALUATED))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThatThrownBy(() -> this.lifecycle.cancelScan(this.scanId, "user:test"))
			.isInstanceOf(ConflictException.class);
		assertThatThrownBy(() -> this.lifecycle.failScan(this.scanId)).isInstanceOf(DomainRuleViolationException.class);
		assertThatThrownBy(() -> this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThat(this.worker.complete(lease)).isEqualTo("DUPLICATE");
		assertThat(this.worker.fail(lease, "SCANNER_ERROR")).isEqualTo("CONFLICT");
		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "FAIL");
	}

	@Test
	void jobsCanOnlyBePlannedOncePerScannerAndBeforeTheScanStarts() {
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);

		assertThatThrownBy(() -> this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE))
			.isInstanceOf(ConflictException.class);

		this.worker.claimFixtureOrFail(this.scanId);
		assertThatThrownBy(() -> this.lifecycle.planJob(this.scanId, ScannerType.TRIVY))
			.isInstanceOf(DomainRuleViolationException.class);
	}

	@Test
	void unknownScansAreReportedAsNotFound() {
		UUID unknown = UUID.randomUUID();

		assertThatThrownBy(() -> this.lifecycle.cancelScan(unknown, "user:test"))
			.isInstanceOf(ResourceNotFoundException.class);
		assertThatThrownBy(() -> this.lifecycle.failScan(unknown)).isInstanceOf(ResourceNotFoundException.class);
		assertThatThrownBy(() -> this.lifecycle.planJob(unknown, ScannerType.FIXTURE))
			.isInstanceOf(ResourceNotFoundException.class);
	}

	@Test
	void retriedJobsPersistTheirAttemptCount() {
		ScanJob job = this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);
		Lease first = this.worker.claimFixtureOrFail(this.scanId);
		assertThat(this.worker.fail(first, "SANDBOX_ERROR")).isEqualTo("ACCEPTED");
		assertThat(this.jdbcTemplate.queryForMap(
				"SELECT execution_status, failure_reason, next_attempt_at > now() AS backoff FROM scan_jobs WHERE id = ?",
				job.getId()))
			.containsEntry("execution_status", "QUEUED")
			.containsEntry("failure_reason", "SANDBOX_ERROR")
			.containsEntry("backoff", true);
		// Not claimable until the backoff has elapsed.
		assertThat(this.worker.claimFixture(this.scanId)).isEmpty();
		new ExecutionTimeTravel(this.admin).makeRetryDue(job.getId());

		Lease second = this.worker.claimFixtureOrFail(this.scanId);

		assertThat(second.attempt()).isEqualTo(2);
		assertThat(second.epoch()).isEqualTo(first.epoch() + 1);
		assertThat(this.jdbcTemplate.queryForObject("SELECT attempt_count FROM scan_jobs WHERE id = ?", Integer.class,
				job.getId()))
			.isEqualTo(2);
		assertThat(jobStatus(job.getId())).isEqualTo("RUNNING");
	}

	@Test
	void theApiCannotPlanTheFixtureUnlessEnabled() {
		ExecutionProperties disabled = new ExecutionProperties();

		assertThat(disabled.isPlannable(ScannerType.FIXTURE)).isFalse();
		assertThat(disabled.isPlannable(ScannerType.SEMGREP)).isTrue();
	}

	@Test
	void everyTransitionIsAudited() {
		Lease lease = runFixtureToCompletion();
		this.lifecycle.evaluate(this.scanId);

		List<Map<String, Object>> events = this.jdbcTemplate.queryForList("""
				SELECT event_type, actor_type, actor, lease_epoch, detail FROM lifecycle.execution_events
				WHERE scan_id = ? ORDER BY id""", this.scanId);

		assertThat(events).extracting((event) -> event.get("event_type"))
			.containsExactly("SCAN_STARTED", "JOB_CLAIMED", "JOB_COMPLETED", "SCAN_EVALUATING", "SCAN_COMPLETED");
		assertThat(events.get(1)).containsEntry("actor_type", "WORKER")
			.containsEntry("actor", dev.sentinelpipe.api.DatabaseRoles.WORKER_USER)
			.containsEntry("lease_epoch", lease.epoch())
			.containsEntry("detail", "ATTEMPT_1");
		assertThat(events.get(4)).containsEntry("actor_type", "SUPERVISOR").containsEntry("detail", "INCOMPLETE");
	}

}

package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.InvalidStateTransitionException;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScanJobStatus;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Lifecycle rules exercised through the internal service against real PostgreSQL, so both
 * the domain checks and the database CHECK constraints are in play.
 */
class ScanLifecycleIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	private UUID scanId;

	@BeforeEach
	void queueScan() throws Exception {
		this.scanId = this.scanService.requestScan(createProject(), randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
	}

	private Map<String, Object> scanRow() {
		return this.jdbcTemplate.queryForMap(
				"SELECT execution_status, security_decision, started_at, completed_at FROM scans WHERE id = ?",
				this.scanId);
	}

	private String jobStatus(UUID jobId) {
		return this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?", String.class,
				jobId);
	}

	@Test
	void completesWithPassOnlyWhenEveryJobCompleted() {
		ScanJob semgrep = this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);
		ScanJob gitleaks = this.lifecycle.planJob(this.scanId, ScannerType.GITLEAKS);
		this.lifecycle.startScan(this.scanId);
		for (ScanJob job : new ScanJob[] { semgrep, gitleaks }) {
			this.lifecycle.startJob(job.getId());
			this.lifecycle.completeJob(job.getId());
		}

		this.lifecycle.completeScan(this.scanId, SecurityDecision.PASS);

		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "PASS");
		assertThat(scanRow().get("started_at")).isNotNull();
		assertThat(scanRow().get("completed_at")).isNotNull();
		assertThat(this.scanService.get(this.scanId).jobs()).extracting(ScanJob::getExecutionStatus)
			.containsOnly(ScanJobStatus.COMPLETED);
	}

	@Test
	void passIsRejectedWhenAJobFailedButFailAndIncompleteAreAllowed() {
		ScanJob job = this.lifecycle.planJob(this.scanId, ScannerType.TRIVY);
		this.lifecycle.startScan(this.scanId);
		this.lifecycle.startJob(job.getId());
		this.lifecycle.failJob(job.getId());

		assertThatThrownBy(() -> this.lifecycle.completeScan(this.scanId, SecurityDecision.PASS))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThat(scanRow()).containsEntry("execution_status", "RUNNING")
			.containsEntry("security_decision", "PENDING");

		this.lifecycle.completeScan(this.scanId, SecurityDecision.INCOMPLETE);
		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE");
	}

	@Test
	void passIsRejectedWithoutAnyJob() {
		this.lifecycle.startScan(this.scanId);

		assertThatThrownBy(() -> this.lifecycle.completeScan(this.scanId, SecurityDecision.PASS))
			.isInstanceOf(DomainRuleViolationException.class);
	}

	@Test
	void completionRequiresEveryJobToBeTerminal() {
		this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);
		this.lifecycle.startScan(this.scanId);

		assertThatThrownBy(() -> this.lifecycle.completeScan(this.scanId, SecurityDecision.FAIL))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThat(scanRow()).containsEntry("execution_status", "RUNNING");
	}

	@Test
	void cancellationCancelsUnfinishedJobsAndIsIncomplete() {
		ScanJob running = this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);
		ScanJob queued = this.lifecycle.planJob(this.scanId, ScannerType.GITLEAKS);
		this.lifecycle.startScan(this.scanId);
		this.lifecycle.startJob(running.getId());

		this.lifecycle.cancelScan(this.scanId);

		assertThat(scanRow()).containsEntry("execution_status", "CANCELLED")
			.containsEntry("security_decision", "INCOMPLETE");
		assertThat(jobStatus(running.getId())).isEqualTo("CANCELLED");
		assertThat(jobStatus(queued.getId())).isEqualTo("CANCELLED");
	}

	@Test
	void failedScanIsIncomplete() {
		this.lifecycle.failScan(this.scanId);

		assertThat(scanRow()).containsEntry("execution_status", "FAILED")
			.containsEntry("security_decision", "INCOMPLETE");
	}

	@Test
	void terminalScansCannotBeModified() {
		ScanJob job = this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);
		this.lifecycle.startScan(this.scanId);
		this.lifecycle.startJob(job.getId());
		this.lifecycle.completeJob(job.getId());
		this.lifecycle.completeScan(this.scanId, SecurityDecision.FAIL);

		assertThatThrownBy(() -> this.lifecycle.startScan(this.scanId))
			.isInstanceOf(InvalidStateTransitionException.class);
		assertThatThrownBy(() -> this.lifecycle.completeScan(this.scanId, SecurityDecision.PASS))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThatThrownBy(() -> this.lifecycle.cancelScan(this.scanId))
			.isInstanceOf(InvalidStateTransitionException.class);
		assertThatThrownBy(() -> this.lifecycle.failJob(job.getId())).isInstanceOf(DomainRuleViolationException.class);
		assertThat(scanRow()).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "FAIL");
	}

	@Test
	void jobsCanOnlyBePlannedOncePerScannerAndBeforeTheScanStarts() {
		this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);

		assertThatThrownBy(() -> this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP))
			.isInstanceOf(ConflictException.class);

		this.lifecycle.startScan(this.scanId);
		assertThatThrownBy(() -> this.lifecycle.planJob(this.scanId, ScannerType.TRIVY))
			.isInstanceOf(DomainRuleViolationException.class);
	}

	@Test
	void jobsCannotStartBeforeTheScanRuns() {
		ScanJob job = this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);

		assertThatThrownBy(() -> this.lifecycle.startJob(job.getId())).isInstanceOf(DomainRuleViolationException.class);
		assertThat(jobStatus(job.getId())).isEqualTo("QUEUED");
	}

	@Test
	void retriedJobsPersistTheirAttemptCount() {
		ScanJob job = this.lifecycle.planJob(this.scanId, ScannerType.SEMGREP);
		this.lifecycle.startScan(this.scanId);
		this.lifecycle.startJob(job.getId());
		this.lifecycle.retryJob(job.getId());
		this.lifecycle.startJob(job.getId());

		assertThat(this.jdbcTemplate.queryForObject("SELECT attempt_count FROM scan_jobs WHERE id = ?", Integer.class,
				job.getId()))
			.isEqualTo(2);
		assertThat(jobStatus(job.getId())).isEqualTo("RUNNING");
	}

}

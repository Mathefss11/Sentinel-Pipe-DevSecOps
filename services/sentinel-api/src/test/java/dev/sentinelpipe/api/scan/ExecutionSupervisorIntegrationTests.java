package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.ExecutionTimeTravel;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScannerType;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Supervisor-driven recovery (crashed and hung workers, attempt exhaustion, hard
 * deadlines) and evaluation, against real PostgreSQL. The periodic scheduler is disabled
 * in tests; passes are driven explicitly.
 */
class ExecutionSupervisorIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private ExecutionSupervisor supervisor;

	@Autowired
	private TestDatabaseAdmin admin;

	@Autowired
	private MeterRegistry meterRegistry;

	private WorkerProtocol worker;

	private ExecutionTimeTravel time;

	@BeforeEach
	void setUp() {
		this.worker = WorkerProtocol.asWorker(this.admin);
		this.time = new ExecutionTimeTravel(this.admin);
	}

	private UUID fixtureScan() throws Exception {
		UUID scanId = this.scanService.requestScan(createProject(), randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
		this.lifecycle.planJob(scanId, ScannerType.FIXTURE);
		return scanId;
	}

	private Map<String, Object> scan(UUID scanId) {
		return this.jdbcTemplate.queryForMap(
				"SELECT execution_status, security_decision, decision_reason FROM scans WHERE id = ?", scanId);
	}

	private Map<String, Object> job(UUID jobId) {
		return this.jdbcTemplate.queryForMap(
				"SELECT execution_status, attempt_count, failure_reason, next_attempt_at FROM scan_jobs WHERE id = ?",
				jobId);
	}

	private int events(UUID scanId, String type) {
		return this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = ?", Integer.class,
				scanId, type);
	}

	@Test
	void aCrashedWorkersJobIsReclaimedAndRetriedWithBackoff() throws Exception {
		UUID scanId = fixtureScan();
		Lease crashed = this.worker.claimFixtureOrFail(scanId);
		this.time.expireLease(crashed.jobId());

		ExecutionSupervisor.Pass pass = this.supervisor.runOnce();

		assertThat(pass.leasesExpired()).isPositive();
		assertThat(job(crashed.jobId())).containsEntry("execution_status", "QUEUED")
			.containsEntry("attempt_count", 1)
			.containsEntry("failure_reason", "LEASE_EXPIRED");
		assertThat(job(crashed.jobId()).get("next_attempt_at")).isNotNull();
		assertThat(scan(scanId)).containsEntry("execution_status", "RUNNING");
		this.time.makeRetryDue(crashed.jobId());
		Lease retry = this.worker.claimFixtureOrFail(scanId);
		assertThat(retry.attempt()).isEqualTo(2);
		assertThat(this.worker.complete(crashed)).isEqualTo("REJECTED_STALE_EPOCH");
		assertThat(this.worker.complete(retry)).isEqualTo("ACCEPTED");
	}

	@Test
	void aJobWhoseEveryAttemptCrashedFailsAndTheScanIsIncomplete() throws Exception {
		UUID scanId = fixtureScan();
		UUID jobId = null;
		for (int attempt = 1; attempt <= ScanJob.MAX_ATTEMPTS; attempt++) {
			Lease lease = this.worker.claimFixtureOrFail(scanId);
			jobId = lease.jobId();
			this.time.expireLease(jobId);
			this.supervisor.runOnce();
			if (attempt < ScanJob.MAX_ATTEMPTS) {
				this.time.makeRetryDue(jobId);
			}
		}

		assertThat(job(jobId)).containsEntry("execution_status", "FAILED")
			.containsEntry("attempt_count", 3)
			.containsEntry("failure_reason", "LEASE_EXPIRED");
		// The same pass moved the scan to EVALUATING and evaluated it: never PASS.
		assertThat(scan(scanId)).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "SCANNER_EXECUTION_INCOMPLETE");
		assertThat(events(scanId, "JOB_LEASE_EXPIRED")).isEqualTo(3);
	}

	@Test
	void theHardDeadlineFailsTheScanAndEveryUnfinishedJob() throws Exception {
		UUID scanId = fixtureScan();
		ScanJob queued = this.lifecycle.planJob(scanId, ScannerType.SEMGREP);
		Lease running = this.worker.claimFixtureOrFail(scanId);
		this.time.passDeadline(scanId);

		assertThat(this.supervisor.runOnce().deadlinesExceeded()).isPositive();

		assertThat(scan(scanId)).containsEntry("execution_status", "FAILED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "EXECUTION_DEADLINE_EXCEEDED");
		assertThat(job(running.jobId())).containsEntry("execution_status", "FAILED")
			.containsEntry("failure_reason", "EXECUTION_DEADLINE_EXCEEDED");
		assertThat(job(queued.getId())).containsEntry("execution_status", "FAILED")
			.containsEntry("failure_reason", "EXECUTION_DEADLINE_EXCEEDED");
		assertThat(this.worker.heartbeat(running).status()).isEqualTo("LEASE_LOST");
		assertThat(this.worker.complete(running)).isEqualTo("REJECTED_JOB_NOT_RUNNING");
	}

	@Test
	void completedExecutionIsEvaluatedAsIncompleteNeverPass() throws Exception {
		UUID scanId = fixtureScan();
		this.worker.complete(this.worker.claimFixtureOrFail(scanId));
		assertThat(scan(scanId)).containsEntry("execution_status", "EVALUATING");

		assertThat(this.supervisor.runOnce().scansEvaluated()).isPositive();

		assertThat(scan(scanId)).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "POLICY_EVALUATION_UNAVAILABLE");
		assertThat(this.meterRegistry.get(ExecutionSupervisor.SCANS_EVALUATED).counter().count()).isPositive();
	}

	@Test
	void repeatedPassesChangeNothingFurther() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		this.time.expireLease(lease.jobId());
		this.supervisor.runOnce();
		long version = this.jdbcTemplate.queryForObject("SELECT version FROM scan_jobs WHERE id = ?", Long.class,
				lease.jobId());

		this.supervisor.runOnce();
		this.supervisor.runOnce();

		assertThat(this.jdbcTemplate.queryForObject("SELECT version FROM scan_jobs WHERE id = ?", Long.class,
				lease.jobId()))
			.isEqualTo(version);
		assertThat(events(scanId, "JOB_LEASE_EXPIRED")).isEqualTo(1);
	}

	@Test
	void liveLeasesAreNeverReclaimed() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		this.supervisor.runOnce();

		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(this.worker.heartbeat(lease).status()).isEqualTo("RENEWED");
	}

	@Test
	void concurrentSupervisorsReclaimEachExpiredLeaseExactlyOnce() throws Exception {
		List<UUID> scans = new ArrayList<>();
		for (int i = 0; i < 6; i++) {
			UUID scanId = fixtureScan();
			this.time.expireLease(this.worker.claimFixtureOrFail(scanId).jobId());
			scans.add(scanId);
		}
		// Each "instance" calls the database function with its own API connection.
		List<Callable<Object>> passes = new ArrayList<>();
		for (int i = 0; i < 4; i++) {
			passes.add(() -> this.supervisor.runOnce());
		}
		ExecutorService pool = Executors.newFixedThreadPool(passes.size());
		try {
			for (Future<Object> pass : pool.invokeAll(passes)) {
				pass.get();
			}
		}
		finally {
			pool.shutdownNow();
		}
		// Rows skipped because another pass held them are picked up by the next pass.
		this.supervisor.runOnce();

		for (UUID scanId : scans) {
			assertThat(events(scanId, "JOB_LEASE_EXPIRED")).as("lease of scan %s", scanId).isEqualTo(1);
			assertThat(events(scanId, "JOB_RETRY_SCHEDULED")).isEqualTo(1);
		}
	}

}

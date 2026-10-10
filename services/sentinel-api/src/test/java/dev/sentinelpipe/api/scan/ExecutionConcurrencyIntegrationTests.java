package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;

/**
 * Concurrent workers, duplicate deliveries and races between workers, users and the
 * supervisor. Every worker uses its own database connections, as separate processes do.
 */
class ExecutionConcurrencyIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final int THREADS = 8;

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	@BeforeEach
	void setUp() {
		this.worker = WorkerProtocol.asWorker(this.admin);
	}

	private UUID fixtureScan() throws Exception {
		UUID scanId = this.scanService.requestScan(createProject(), randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
		this.lifecycle.planJob(scanId, ScannerType.FIXTURE);
		return scanId;
	}

	/** Runs every task at the same moment (after a shared start signal). */
	private static <T> List<T> race(Collection<Callable<T>> tasks) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
		CountDownLatch start = new CountDownLatch(1);
		try {
			List<Future<T>> futures = new ArrayList<>();
			for (Callable<T> task : tasks) {
				futures.add(pool.submit(() -> {
					start.await();
					return task.call();
				}));
			}
			start.countDown();
			List<T> results = new ArrayList<>();
			for (Future<T> future : futures) {
				results.add(future.get(60, TimeUnit.SECONDS));
			}
			return results;
		}
		finally {
			pool.shutdownNow();
		}
	}

	private static <T> List<Callable<T>> times(int count, Callable<T> task) {
		List<Callable<T>> tasks = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			tasks.add(task);
		}
		return tasks;
	}

	@Test
	void concurrentWorkersClaimAJobExactlyOnce() throws Exception {
		for (int round = 0; round < 5; round++) {
			UUID scanId = fixtureScan();

			List<Optional<Lease>> claims = race(times(THREADS, () -> this.worker.claimFixture(scanId)));

			assertThat(claims.stream().filter(Optional::isPresent).count()).as("round %d", round).isEqualTo(1);
			assertThat(this.jdbcTemplate.queryForObject(
					"SELECT count(*) FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = 'JOB_CLAIMED'",
					Integer.class, scanId))
				.isEqualTo(1);
		}
	}

	@Test
	void workersPollingForAnyJobNeverShareOne() throws Exception {
		Set<UUID> mine = new HashSet<>();
		for (int i = 0; i < 6; i++) {
			UUID scanId = fixtureScan();
			mine.add(this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class, scanId));
		}

		// Each worker keeps claiming until nothing is left (other tests' queued jobs included).
		List<List<UUID>> claimed = race(times(THREADS, () -> {
			List<UUID> jobs = new ArrayList<>();
			for (int empty = 0; empty < 3;) {
				Optional<Lease> lease = this.worker.claim(null, "FIXTURE");
				if (lease.isPresent()) {
					jobs.add(lease.get().jobId());
				}
				else {
					empty++;
				}
			}
			return jobs;
		}));

		List<UUID> all = claimed.stream().flatMap(List::stream).toList();
		assertThat(all).doesNotHaveDuplicates();
		assertThat(all).containsAll(mine);
	}

	@Test
	void concurrentDuplicateReportsApplyExactlyOnce() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		List<String> outcomes = race(times(THREADS, () -> this.worker.complete(lease)));

		assertThat(outcomes).filteredOn("ACCEPTED"::equals).hasSize(1);
		assertThat(outcomes).filteredOn("DUPLICATE"::equals).hasSize(THREADS - 1);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'JOB_COMPLETED'",
				Integer.class, lease.jobId()))
			.isEqualTo(1);
	}

	@Test
	void contradictoryConcurrentReportsLeaveExactlyOneOutcome() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		List<Callable<String>> reports = new ArrayList<>();
		reports.addAll(times(THREADS / 2, () -> this.worker.complete(lease)));
		reports.addAll(times(THREADS / 2, () -> this.worker.fail(lease, "UNSUPPORTED_SCANNER")));

		List<String> outcomes = race(reports);

		assertThat(outcomes).filteredOn("ACCEPTED"::equals).hasSize(1);
		assertThat(outcomes).allMatch((outcome) -> List.of("ACCEPTED", "DUPLICATE", "CONFLICT").contains(outcome));
		String status = this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?",
				String.class, lease.jobId());
		assertThat(status).isIn("COMPLETED", "FAILED");
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM lifecycle.job_reports WHERE job_id = ?",
				Integer.class, lease.jobId()))
			.isEqualTo(1);
	}

	@RepeatedTest(5)
	void cancellationRacingACompletionReportIsConsistent() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		List<Callable<String>> tasks = List.of(() -> this.worker.complete(lease),
				() -> this.lifecycle.cancelScan(scanId, "user:race").name());

		List<String> outcomes = race(tasks);

		Map<String, Object> scan = this.jdbcTemplate
			.queryForMap("SELECT execution_status, security_decision FROM scans WHERE id = ?", scanId);
		String job = this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?",
				String.class, lease.jobId());
		// The cancellation always wins at the scan level; the job either completed first or
		// was cancelled first, and the worker's report says which.
		assertThat(scan).containsEntry("execution_status", "CANCELLED").containsEntry("security_decision", "INCOMPLETE");
		assertThat(outcomes.get(1)).isEqualTo("CANCELLED");
		if (outcomes.get(0).equals("ACCEPTED")) {
			assertThat(job).isEqualTo("COMPLETED");
		}
		else {
			assertThat(outcomes.get(0)).isEqualTo("REJECTED_JOB_NOT_RUNNING");
			assertThat(job).isEqualTo("CANCELLED");
		}
	}

	@Test
	void heartbeatsRacingTheSupervisorNeverReviveAnExpiredLease() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		this.jdbcTemplate.update("UPDATE scan_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
				lease.jobId());
		List<Callable<String>> tasks = new ArrayList<>(times(THREADS - 1, () -> this.worker.heartbeat(lease).status()));
		tasks.add(() -> this.jdbcTemplate.queryForMap("SELECT * FROM lifecycle.supervise(100)").toString());

		List<String> outcomes = race(tasks);

		assertThat(outcomes.subList(0, THREADS - 1)).containsOnly("LEASE_LOST");
		assertThat(this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?",
				String.class, lease.jobId()))
			.isEqualTo("QUEUED");
	}

	@Test
	void aBrokenWorkerConnectionChangesNothing() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		WorkerProtocol wrongPassword = new WorkerProtocol(
				this.admin.connectAs(dev.sentinelpipe.api.DatabaseRoles.WORKER_USER, "wrong-password"));

		org.assertj.core.api.Assertions.assertThatThrownBy(() -> wrongPassword.complete(lease))
			.isInstanceOf(DataAccessException.class);

		assertThat(this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?",
				String.class, lease.jobId()))
			.isEqualTo("RUNNING");
		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");
	}

}

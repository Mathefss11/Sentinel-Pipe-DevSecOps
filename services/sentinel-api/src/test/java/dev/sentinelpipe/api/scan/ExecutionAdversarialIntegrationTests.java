package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.DatabaseRoles;
import dev.sentinelpipe.api.ExecutionTimeTravel;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Artifact;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.WorkerProtocol.Upload;
import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Adversarial tests of the execution state machine (M3 Phase 1 security review): crashes
 * inside transactions, out-of-order events, deadline races, retry exhaustion, forged
 * contexts and a randomized concurrent workload. Every test asserts the protocol's
 * answer and the resulting rows. {@link #crossTableInvariantsHoldForEveryScanTouched}
 * then checks the invariants that no single CHECK constraint expresses, for every scan
 * this class touched: no failure path may produce a false completion or a false PASS.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ExecutionAdversarialIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final byte[] EVIDENCE = "{\"fixture\":\"harmless\"}".getBytes(StandardCharsets.UTF_8);

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private ExecutionSupervisor supervisor;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	private ExecutionTimeTravel time;

	private final Set<UUID> touchedScans = ConcurrentHashMap.newKeySet();

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
		this.touchedScans.add(scanId);
		return scanId;
	}

	private Map<String, Object> job(UUID jobId) {
		return this.jdbcTemplate.queryForMap("""
				SELECT execution_status, attempt_count, lease_epoch, failure_reason FROM scan_jobs WHERE id = ?""",
				jobId);
	}

	private Map<String, Object> scan(UUID scanId) {
		return this.jdbcTemplate.queryForMap(
				"SELECT execution_status, security_decision, decision_reason FROM scans WHERE id = ?", scanId);
	}

	private int count(String sql, Object... arguments) {
		return this.jdbcTemplate.queryForObject(sql, Integer.class, arguments);
	}

	// ---------------------------------------------------------------------------------
	// Worker crashes inside the protocol's transactions
	// ---------------------------------------------------------------------------------

	@Test
	void aWorkerCrashingInsideTheSubmissionTransactionLeavesNoTrace() throws Exception {
		Lease lease = this.worker.claimFixtureOrFail(fixtureScan());
		Upload upload = this.worker.putEvidence(lease, "fixture-result.json", "application/json", EVIDENCE);
		String document = WorkerProtocol.canonical(WorkerProtocol.resultDocument(lease, "COMPLETED", null,
				List.of(Artifact.of(upload, "fixture-result.json", "application/json"))));

		try (Connection connection = this.admin.openConnection(DatabaseRoles.WORKER_USER,
				DatabaseRoles.WORKER_PASSWORD)) {
			connection.setAutoCommit(false);
			try (PreparedStatement submit = connection.prepareStatement("SELECT worker.submit_result(?, ?)")) {
				submit.setString(1, lease.token());
				submit.setString(2, document);
				try (ResultSet answer = submit.executeQuery()) {
					answer.next();
					assertThat(answer.getString(1)).isEqualTo("ACCEPTED");
				}
			}
			// The worker dies before COMMIT: the transaction is rolled back.
			connection.rollback();
		}

		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(count("SELECT count(*) FROM lifecycle.job_reports WHERE job_id = ?", lease.jobId())).isZero();
		assertThat(count("SELECT count(*) FROM evidence.result_artifacts WHERE job_id = ?", lease.jobId())).isZero();
		assertThat(count("SELECT count(*) FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'JOB_COMPLETED'",
				lease.jobId()))
			.isZero();
		// The retry after the crash is accepted exactly once.
		assertThat(this.worker.submitRaw(lease.token(), document)).isEqualTo("ACCEPTED");
		assertThat(this.worker.submitRaw(lease.token(), document)).isEqualTo("DUPLICATE");
		assertThat(job(lease.jobId())).containsEntry("execution_status", "COMPLETED");
	}

	@Test
	void aWorkerCrashingInsideAnUploadLeavesNoEvidence() throws Exception {
		Lease lease = this.worker.claimFixtureOrFail(fixtureScan());

		try (Connection connection = this.admin.openConnection(DatabaseRoles.WORKER_USER,
				DatabaseRoles.WORKER_PASSWORD)) {
			connection.setAutoCommit(false);
			try (PreparedStatement upload = connection
				.prepareStatement("SELECT status FROM worker.put_evidence(?, ?, ?, ?, ?, ?)")) {
				upload.setObject(1, lease.jobId());
				upload.setLong(2, lease.epoch());
				upload.setString(3, lease.token());
				upload.setString(4, "fixture-result.json");
				upload.setString(5, "application/json");
				upload.setBytes(6, EVIDENCE);
				try (ResultSet answer = upload.executeQuery()) {
					answer.next();
					assertThat(answer.getString(1)).isEqualTo("STORED");
				}
			}
			connection.rollback();
		}

		assertThat(count("SELECT count(*) FROM evidence.job_artifacts WHERE job_id = ?", lease.jobId())).isZero();
		assertThat(this.worker.submit(lease, "COMPLETED", null, List.of(new Artifact("fixture-result.json",
				"application/json", dev.sentinelpipe.api.evidence.EvidenceVerifier.sha256(EVIDENCE), EVIDENCE.length))))
			.isEqualTo("REJECTED_MISSING_ARTIFACT");
		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
	}

	// ---------------------------------------------------------------------------------
	// Out-of-order events
	// ---------------------------------------------------------------------------------

	@Test
	void eventsArrivingOutOfOrderChangeNothing() throws Exception {
		UUID scanId = fixtureScan();
		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);

		// A result for a job nobody has claimed yet (epoch 0): a forged lease.
		assertThat(this.worker.report(jobId, scanId, 1, "a".repeat(64), "COMPLETED", null))
			.isEqualTo("REJECTED_UNKNOWN_EPOCH");
		// An evaluation before execution started.
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT lifecycle.complete_evaluation(?, 'INCOMPLETE', 'POLICY_EVALUATION_UNAVAILABLE')", String.class,
				scanId))
			.isEqualTo("NOT_EVALUATING");
		assertThat(job(jobId)).containsEntry("execution_status", "QUEUED").containsEntry("lease_epoch", 0L);
		assertThat(scan(scanId)).containsEntry("execution_status", "QUEUED");

		Lease lease = this.worker.claimFixtureOrFail(scanId);
		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");
		// Heartbeats, uploads and other outcomes after the result was accepted.
		assertThat(this.worker.heartbeat(lease).status()).isEqualTo("LEASE_LOST");
		assertThat(this.worker.putEvidence(lease, "late.json", "application/json", EVIDENCE).status())
			.isEqualTo("REJECTED_JOB_NOT_RUNNING");
		assertThat(this.worker.fail(lease, "SCANNER_ERROR")).isEqualTo("CONFLICT");
		// A supervisor pass and a second evaluation after the decision.
		this.supervisor.runOnce();
		assertThat(this.lifecycle.evaluate(scanId)).isFalse();
		assertThat(this.worker.claimFixture(scanId)).isEmpty();

		assertThat(job(jobId)).containsEntry("execution_status", "COMPLETED");
		assertThat(scan(scanId)).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "POLICY_EVALUATION_UNAVAILABLE");
		assertThat(count("SELECT count(*) FROM lifecycle.job_reports WHERE job_id = ?", jobId)).isEqualTo(1);
	}

	@Test
	void theDeadlinePassingBetweenUploadAndSubmissionFailsTheScanWithoutAResult() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		Upload upload = this.worker.putEvidence(lease, "fixture-result.json", "application/json", EVIDENCE);
		this.time.passDeadline(scanId);

		assertThat(this.worker.submit(lease, "COMPLETED", null,
				List.of(Artifact.of(upload, "fixture-result.json", "application/json"))))
			.isEqualTo("REJECTED_DEADLINE_EXCEEDED");
		this.supervisor.runOnce();

		assertThat(job(lease.jobId())).containsEntry("execution_status", "FAILED")
			.containsEntry("failure_reason", "EXECUTION_DEADLINE_EXCEEDED");
		assertThat(scan(scanId)).containsEntry("execution_status", "FAILED")
			.containsEntry("security_decision", "INCOMPLETE");
		assertThat(count("SELECT count(*) FROM lifecycle.job_reports WHERE job_id = ?", lease.jobId())).isZero();
		assertThat(count("SELECT count(*) FROM evidence.result_artifacts WHERE job_id = ?", lease.jobId())).isZero();
	}

	@Test
	void retryExhaustionThroughMixedFailuresNeverYieldsPass() throws Exception {
		UUID scanId = fixtureScan();
		Lease first = this.worker.claimFixtureOrFail(scanId);
		this.worker.fail(first, "SANDBOX_ERROR");
		this.time.makeRetryDue(first.jobId());
		Lease second = this.worker.claimFixtureOrFail(scanId);
		this.time.expireLease(second.jobId());
		this.supervisor.runOnce();
		this.time.makeRetryDue(first.jobId());
		Lease third = this.worker.claimFixtureOrFail(scanId);
		assertThat(this.worker.fail(third, "EVIDENCE_UNAVAILABLE")).isEqualTo("ACCEPTED");

		assertThat(job(first.jobId())).containsEntry("execution_status", "FAILED")
			.containsEntry("attempt_count", 3)
			.containsEntry("failure_reason", "EVIDENCE_UNAVAILABLE");
		assertThat(this.worker.claimFixture(scanId)).isEmpty();
		org.assertj.core.api.Assertions
			.assertThatThrownBy(() -> this.lifecycle.completeEvaluation(scanId, SecurityDecision.PASS,
					DecisionReason.POLICY_EVALUATED))
			.isInstanceOf(DomainRuleViolationException.class);
		this.supervisor.runOnce();
		assertThat(scan(scanId)).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "SCANNER_EXECUTION_INCOMPLETE");
	}

	@Test
	void aForgedExecutionContextForAnotherTenantIsRejectedAndChangesNothing() throws Exception {
		Lease victim = this.worker.claimFixtureOrFail(fixtureScan());
		Lease attacker = this.worker.claimFixtureOrFail(fixtureScan());
		Map<String, Object> forged = WorkerProtocol.resultDocument(attacker, "COMPLETED", null, List.of());
		forged.put("organization_id", victim.organizationId().toString());
		forged.put("project_id", victim.projectId().toString());
		forged.put("commit_sha", victim.commitSha());

		assertThat(this.worker.submit(attacker.token(), forged)).isEqualTo("REJECTED_CONTEXT_MISMATCH");
		// The victim's identifiers with the attacker's lease.
		Map<String, Object> hijack = WorkerProtocol.resultDocument(victim, "COMPLETED", null, List.of());
		assertThat(this.worker.submit(attacker.token(), hijack)).isEqualTo("REJECTED_TOKEN_MISMATCH");

		assertThat(job(victim.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(job(attacker.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(count("SELECT count(*) FROM lifecycle.job_reports WHERE job_id IN (?, ?)", victim.jobId(),
				attacker.jobId()))
			.isZero();
	}

	// ---------------------------------------------------------------------------------
	// Randomized concurrent workload and cross-table invariants
	// ---------------------------------------------------------------------------------

	@Test
	void aRandomizedConcurrentWorkloadNeverProducesAFalseCompletion() throws Exception {
		Random random = new Random(20261010L);
		List<UUID> scans = new ArrayList<>();
		for (int i = 0; i < 12; i++) {
			scans.add(fixtureScan());
		}
		List<Callable<Object>> actions = new ArrayList<>();
		for (UUID scanId : scans) {
			int scenario = random.nextInt(5);
			actions.add(() -> {
				var lease = this.worker.claimFixture(scanId);
				if (lease.isEmpty()) {
					return null;
				}
				List<Callable<Object>> racing = new ArrayList<>(List.of(() -> this.worker.complete(lease.get()),
						() -> this.worker.fail(lease.get(), "SCANNER_ERROR")));
				if (scenario == 0) {
					racing.add(() -> this.lifecycle.cancelScan(scanId, "user:race"));
				}
				if (scenario == 1) {
					racing.add(() -> {
						this.time.expireLease(lease.get().jobId());
						return this.supervisor.runOnce();
					});
				}
				if (scenario == 2) {
					racing.add(() -> this.worker.complete(lease.get().withToken("f".repeat(64))));
				}
				if (scenario == 3) {
					racing.add(() -> this.worker.complete(lease.get().withEpoch(lease.get().epoch() + 1)));
				}
				Collections.shuffle(racing, random);
				race(racing);
				return null;
			});
		}

		race(actions);
		this.supervisor.runOnce();

		for (UUID scanId : scans) {
			Map<String, Object> state = scan(scanId);
			assertThat(state.get("security_decision")).as("scan %s", scanId).isIn("PENDING", "INCOMPLETE");
		}
	}

	private static void race(List<Callable<Object>> tasks) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
		try {
			for (Future<Object> future : pool.invokeAll(tasks)) {
				try {
					future.get();
				}
				catch (java.util.concurrent.ExecutionException ex) {
					// Lifecycle refusals (e.g. cancelling a finished scan) are legitimate outcomes.
					if (!(ex.getCause() instanceof RuntimeException)) {
						throw ex;
					}
				}
			}
		}
		finally {
			pool.shutdownNow();
		}
	}

	/**
	 * Invariants across scans, jobs, reports and evidence that no CHECK constraint can
	 * express, for every scan touched by this class.
	 */
	@AfterAll
	void crossTableInvariantsHoldForEveryScanTouched() {
		assertThat(this.touchedScans).isNotEmpty();
		UUID[] scans = this.touchedScans.toArray(UUID[]::new);
		Map<String, String> invariants = Map.of(
				// A COMPLETED job always has an accepted COMPLETED report for its current lease,
				// submitted by the lease owner.
				"completed job without its accepted report", """
						SELECT j.id FROM scan_jobs j
						WHERE j.scan_id = ANY (?) AND j.execution_status = 'COMPLETED'
						  AND NOT EXISTS (SELECT 1 FROM lifecycle.job_reports r
						                  WHERE r.job_id = j.id AND r.lease_epoch = j.lease_epoch
						                    AND r.outcome = 'COMPLETED' AND r.lease_owner = j.lease_owner)""",
				// No report from a future lease.
				"report newer than the job's lease", """
						SELECT r.job_id FROM lifecycle.job_reports r JOIN scan_jobs j ON j.id = r.job_id
						WHERE j.scan_id = ANY (?) AND r.lease_epoch > j.lease_epoch""",
				// PASS and FAIL only with a policy evaluation; PASS only with every job completed.
				"unjustified PASS or FAIL", """
						SELECT s.id FROM scans s
						WHERE s.id = ANY (?) AND (
						    (s.security_decision IN ('PASS', 'FAIL') AND s.decision_reason <> 'POLICY_EVALUATED')
						    OR (s.security_decision = 'PASS' AND EXISTS (SELECT 1 FROM scan_jobs j
						        WHERE j.scan_id = s.id AND j.execution_status <> 'COMPLETED')))""",
				// Finished or evaluating scans have no unfinished jobs; running jobs belong to running scans.
				"unfinished job of a finished scan", """
						SELECT j.id FROM scan_jobs j JOIN scans s ON s.id = j.scan_id
						WHERE s.id = ANY (?) AND (
						    (s.execution_status IN ('EVALUATING', 'COMPLETED', 'FAILED', 'CANCELLED')
						     AND j.execution_status IN ('QUEUED', 'RUNNING'))
						    OR (j.execution_status = 'RUNNING' AND s.execution_status <> 'RUNNING'))""",
				// Evidence of record always belongs to the job's own tenant and lease.
				"evidence of record outside its job's tenant", """
						SELECT r.job_id FROM evidence.result_artifacts r
						JOIN evidence.job_artifacts u USING (job_id, lease_epoch, name)
						JOIN scan_jobs j ON j.id = r.job_id JOIN scans s ON s.id = j.scan_id
						JOIN projects p ON p.id = s.project_id
						WHERE s.id = ANY (?) AND u.organization_id <> p.organization_id""",
				// Every evaluated scan has a recorded reason.
				"final decision without a reason", """
						SELECT s.id FROM scans s
						WHERE s.id = ANY (?) AND s.security_decision <> 'PENDING' AND s.decision_reason IS NULL""");
		for (Map.Entry<String, String> invariant : invariants.entrySet()) {
			assertThat(this.jdbcTemplate.queryForList(invariant.getValue(), Object.class, (Object) scans))
				.as(invariant.getKey())
				.isEmpty();
		}
	}

}

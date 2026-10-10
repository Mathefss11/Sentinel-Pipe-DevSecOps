package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.DatabaseRoles;
import dev.sentinelpipe.api.ExecutionTimeTravel;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;

/**
 * Security properties of the worker execution protocol (Flyway V007): workers are
 * authenticated by their database login, a lease token and a fencing epoch; stale,
 * forged, stolen, cross-scan and malformed operations change nothing and are audited;
 * duplicates are idempotent.
 */
class ExecutionProtocolIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final String OTHER_WORKER = "sentinel_worker_other";

	private static final String OTHER_WORKER_PASSWORD = "p" + UUID.randomUUID().toString().replace("-", "");

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	private ExecutionTimeTravel time;

	@BeforeEach
	void setUp() {
		this.worker = WorkerProtocol.asWorker(this.admin);
		this.time = new ExecutionTimeTravel(this.admin);
	}

	@AfterEach
	void dropOtherWorker() {
		this.jdbcTemplate.execute("""
				DO $drop$
				BEGIN
				    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%1$s') THEN
				        EXECUTE format('REVOKE CONNECT ON DATABASE %%I FROM %1$s', current_database());
				        DROP ROLE %1$s;
				    END IF;
				END
				$drop$""".formatted(OTHER_WORKER));
	}

	/** A second, independently authenticated worker login (member of sentinel_worker). */
	private WorkerProtocol otherWorker() {
		this.jdbcTemplate.execute("CREATE ROLE " + OTHER_WORKER + " LOGIN PASSWORD '" + OTHER_WORKER_PASSWORD + "'");
		this.jdbcTemplate.execute("GRANT CONNECT ON DATABASE " + this.jdbcTemplate.queryForObject(
				"SELECT current_database()", String.class) + " TO " + OTHER_WORKER);
		this.jdbcTemplate.execute("GRANT sentinel_worker TO " + OTHER_WORKER);
		return new WorkerProtocol(this.admin.connectAs(OTHER_WORKER, OTHER_WORKER_PASSWORD));
	}

	private UUID fixtureScan() throws Exception {
		return fixtureScan(createProject());
	}

	private UUID fixtureScan(UUID projectId) {
		UUID scanId = this.scanService.requestScan(projectId, randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
		this.lifecycle.planJob(scanId, ScannerType.FIXTURE);
		return scanId;
	}

	private Map<String, Object> job(UUID jobId) {
		return this.jdbcTemplate.queryForMap("""
				SELECT execution_status, attempt_count, lease_epoch, lease_owner, lease_token_sha256, failure_reason
				FROM scan_jobs WHERE id = ?""", jobId);
	}

	private List<String> rejections(UUID jobId) {
		return this.jdbcTemplate.queryForList(
				"SELECT detail FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'REPORT_REJECTED' ORDER BY id",
				String.class, jobId);
	}

	private static String sqlState(Throwable ex) {
		return ((SQLException) ((DataAccessException) ex).getMostSpecificCause()).getSQLState();
	}

	@Test
	void claimReturnsTheAuthoritativeContextAndNeverStoresTheToken() throws Exception {
		UUID projectId = createProject();
		UUID scanId = fixtureScan(projectId);
		Map<String, Object> expected = this.jdbcTemplate.queryForMap("""
				SELECT s.commit_sha, p.organization_id, p.repository_owner, p.repository_name
				FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = ?""", scanId);

		Lease lease = this.worker.claimFixtureOrFail(scanId);

		assertThat(lease.scanId()).isEqualTo(scanId);
		assertThat(lease.projectId()).isEqualTo(projectId);
		assertThat(lease.organizationId()).isEqualTo(expected.get("organization_id"));
		assertThat(lease.commitSha()).isEqualTo(expected.get("commit_sha"));
		assertThat(lease.repositoryName()).isEqualTo(expected.get("repository_name"));
		assertThat(lease.scannerType()).isEqualTo("FIXTURE");
		assertThat(lease.attempt()).isEqualTo(1);
		assertThat(lease.maxAttempts()).isEqualTo(3);
		assertThat(lease.epoch()).isEqualTo(1);
		assertThat(lease.token()).matches("[0-9a-f]{64}");
		Map<String, Object> job = job(lease.jobId());
		assertThat(job).containsEntry("lease_owner", DatabaseRoles.WORKER_USER);
		assertThat((String) job.get("lease_token_sha256")).matches("[0-9a-f]{64}").isNotEqualTo(lease.token());
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE detail = ? OR actor = ?", Integer.class,
				lease.token(), lease.token()))
			.isZero();
	}

	@Test
	void eachClaimIssuesAFreshTokenAndAHigherEpoch() throws Exception {
		UUID scanId = fixtureScan();
		Lease first = this.worker.claimFixtureOrFail(scanId);
		this.worker.fail(first, "SCANNER_ERROR");
		this.time.makeRetryDue(first.jobId());

		Lease second = this.worker.claimFixtureOrFail(scanId);

		assertThat(second.jobId()).isEqualTo(first.jobId());
		assertThat(second.epoch()).isEqualTo(first.epoch() + 1);
		assertThat(second.token()).isNotEqualTo(first.token());
	}

	@Test
	void onlyRequestedScannerTypesAreClaimed() throws Exception {
		UUID scanId = fixtureScan();

		assertThat(this.worker.claim(scanId, "SEMGREP", "TRIVY")).isEmpty();
		assertThat(this.worker.claim(scanId, "SEMGREP", "FIXTURE")).isPresent();
	}

	@Test
	void heartbeatsRenewOnlyTheCurrentHoldersLease() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		WorkerProtocol.Heartbeat renewed = this.worker.heartbeat(lease);

		assertThat(renewed.status()).isEqualTo("RENEWED");
		assertThat(renewed.leaseExpiresAt()).isAfterOrEqualTo(lease.expiresAt());
		assertThat(this.worker.heartbeat(lease.withToken("0".repeat(64))).status()).isEqualTo("LEASE_LOST");
		assertThat(this.worker.heartbeat(lease.withEpoch(lease.epoch() + 1)).status()).isEqualTo("LEASE_LOST");
		assertThat(otherWorker().heartbeat(lease).status()).isEqualTo("LEASE_LOST");
	}

	@Test
	void anExpiredLeaseIsNeverRevivedEvenBeforeTheSupervisorRuns() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		this.time.expireLease(lease.jobId());

		assertThat(this.worker.heartbeat(lease).status()).isEqualTo("LEASE_LOST");
		assertThat(this.worker.complete(lease)).isEqualTo("REJECTED_LEASE_EXPIRED");
		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(rejections(lease.jobId())).containsExactly("LEASE_EXPIRED");
	}

	@Test
	void aStaleWorkerCannotOverwriteTheResultOfANewerLease() throws Exception {
		UUID scanId = fixtureScan();
		Lease stale = this.worker.claimFixtureOrFail(scanId);
		// The worker hangs; its lease expires and the job is reclaimed by another worker.
		this.time.expireLease(stale.jobId());
		this.jdbcTemplate.queryForMap("SELECT * FROM lifecycle.supervise(100)");
		this.time.makeRetryDue(stale.jobId());
		WorkerProtocol other = otherWorker();
		Lease current = other.claimFixtureOrFail(scanId);
		assertThat(other.fail(current, "UNSUPPORTED_SCANNER")).isEqualTo("ACCEPTED");

		// The stale worker wakes up and reports success: rejected, the FAILED result stands.
		assertThat(this.worker.complete(stale)).isEqualTo("REJECTED_STALE_EPOCH");
		assertThat(this.worker.heartbeat(stale).status()).isEqualTo("LEASE_LOST");
		assertThat(job(stale.jobId())).containsEntry("execution_status", "FAILED")
			.containsEntry("failure_reason", "UNSUPPORTED_SCANNER")
			.containsEntry("lease_epoch", current.epoch())
			.containsEntry("lease_owner", OTHER_WORKER);
		assertThat(rejections(stale.jobId())).containsExactly("STALE_EPOCH");
	}

	@Test
	void aStolenTokenIsUselessToAnotherWorkerLogin() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		assertThat(otherWorker().complete(lease)).isEqualTo("REJECTED_NOT_LEASE_OWNER");

		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");
	}

	@Test
	void forgedTokensAndEpochsAreRejectedAndAudited() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		assertThat(this.worker.complete(lease.withToken("a".repeat(64)))).isEqualTo("REJECTED_TOKEN_MISMATCH");
		assertThat(this.worker.complete(lease.withEpoch(lease.epoch() + 5))).isEqualTo("REJECTED_UNKNOWN_EPOCH");
		assertThat(this.worker.report(UUID.randomUUID(), scanId, 1, lease.token(), "COMPLETED", null))
			.isEqualTo("REJECTED_UNKNOWN_JOB");

		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(rejections(lease.jobId())).containsExactly("TOKEN_MISMATCH", "UNKNOWN_EPOCH");
	}

	@Test
	void aLeaseCannotBeUsedForAnotherTenantsScan() throws Exception {
		UUID scanA = fixtureScan();
		UUID scanB = fixtureScan();
		Lease leaseA = this.worker.claimFixtureOrFail(scanA);
		Lease leaseB = this.worker.claimFixtureOrFail(scanB);

		// Job of tenant A reported as if it belonged to tenant B's scan.
		assertThat(this.worker.report(leaseA.jobId(), scanB, leaseA.epoch(), leaseA.token(), "COMPLETED", null))
			.isEqualTo("REJECTED_SCAN_MISMATCH");
		// Tenant B's job reported with tenant A's lease.
		assertThat(this.worker.report(leaseB.jobId(), scanB, leaseB.epoch(), leaseA.token(), "COMPLETED", null))
			.isEqualTo("REJECTED_TOKEN_MISMATCH");

		assertThat(job(leaseA.jobId())).containsEntry("execution_status", "RUNNING");
		assertThat(job(leaseB.jobId())).containsEntry("execution_status", "RUNNING");
	}

	@Test
	void duplicateReportsAreIdempotentAndContradictionsAreRefused() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");
		assertThat(this.worker.complete(lease)).isEqualTo("DUPLICATE");
		assertThat(this.worker.fail(lease, "SCANNER_ERROR")).isEqualTo("CONFLICT");

		assertThat(job(lease.jobId())).containsEntry("execution_status", "COMPLETED");
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'JOB_COMPLETED'",
				Integer.class, lease.jobId()))
			.isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForList(
				"SELECT event_type FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'REPORT_CONFLICT'",
				String.class, lease.jobId()))
			.hasSize(1);
	}

	@Test
	void aDuplicateOfARetryReportStaysIdempotentAfterTheJobWasReclaimed() throws Exception {
		UUID scanId = fixtureScan();
		Lease first = this.worker.claimFixtureOrFail(scanId);
		assertThat(this.worker.fail(first, "SANDBOX_ERROR")).isEqualTo("ACCEPTED");
		this.time.makeRetryDue(first.jobId());
		Lease second = this.worker.claimFixtureOrFail(scanId);

		// Redelivery of the first attempt's report (e.g. after an ambiguous commit).
		assertThat(this.worker.fail(first, "SANDBOX_ERROR")).isEqualTo("DUPLICATE");

		assertThat(job(second.jobId())).containsEntry("execution_status", "RUNNING")
			.containsEntry("lease_epoch", second.epoch());
	}

	@Test
	void retryDecisionsBelongToTheControlPlaneAndAttemptsAreBounded() throws Exception {
		UUID scanId = fixtureScan();
		UUID jobId = null;
		for (int attempt = 1; attempt <= 3; attempt++) {
			Lease lease = this.worker.claimFixtureOrFail(scanId);
			jobId = lease.jobId();
			assertThat(lease.attempt()).isEqualTo(attempt);
			assertThat(this.worker.fail(lease, "SCANNER_ERROR")).isEqualTo("ACCEPTED");
			if (attempt < 3) {
				this.time.makeRetryDue(jobId);
			}
		}

		assertThat(job(jobId)).containsEntry("execution_status", "FAILED")
			.containsEntry("attempt_count", 3)
			.containsEntry("failure_reason", "SCANNER_ERROR");
		assertThat(this.worker.claimFixture(scanId)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "EXECUTION_TIMEOUT", "RESOURCE_LIMIT_EXCEEDED", "UNSUPPORTED_SCANNER" })
	void deterministicFailuresAreNotRetried(String reason) throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);

		assertThat(this.worker.fail(lease, reason)).isEqualTo("ACCEPTED");

		assertThat(job(lease.jobId())).containsEntry("execution_status", "FAILED")
			.containsEntry("attempt_count", 1)
			.containsEntry("failure_reason", reason);
	}

	@Test
	void malformedCallsAreRejectedBeforeTouchingAnyRow() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		List<Runnable> malformed = List.of(
				() -> this.worker.report(lease, "PASSED", null),
				() -> this.worker.report(lease, "COMPLETED", "SCANNER_ERROR"),
				() -> this.worker.report(lease, "FAILED", null),
				() -> this.worker.report(lease, "FAILED", "LEASE_EXPIRED"),
				() -> this.worker.report(lease, "FAILED", "EXECUTION_DEADLINE_EXCEEDED"),
				() -> this.worker.report(lease.jobId(), lease.scanId(), 0, lease.token(), "COMPLETED", null),
				() -> this.worker.report(lease.jobId(), lease.scanId(), lease.epoch(), "short", "COMPLETED", null),
				() -> this.worker.report(lease.jobId(), lease.scanId(), lease.epoch(), lease.token().toUpperCase(),
						"COMPLETED", null),
				() -> this.worker.report(lease.jobId(), null, lease.epoch(), lease.token(), "COMPLETED", null),
				() -> this.worker.heartbeat(lease.withToken("x'; DROP TABLE scans; --")),
				() -> this.worker.claim(null, "NOT_A_SCANNER"),
				() -> this.worker.claim(null, "FIXTURE", ""));

		for (Runnable call : malformed) {
			assertThatThrownBy(call::run).isInstanceOf(DataAccessException.class)
				.satisfies((ex) -> assertThat(sqlState(ex)).isEqualTo("22023"));
		}
		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING")
			.containsEntry("lease_epoch", lease.epoch());
		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");
	}

	@Test
	void reportsAfterTheHardDeadlineAreRejected() throws Exception {
		UUID scanId = fixtureScan();
		Lease lease = this.worker.claimFixtureOrFail(scanId);
		this.time.passDeadline(scanId);

		assertThat(this.worker.heartbeat(lease).status()).isEqualTo("DEADLINE_EXCEEDED");
		assertThat(this.worker.complete(lease)).isEqualTo("REJECTED_DEADLINE_EXCEEDED");
		assertThat(job(lease.jobId())).containsEntry("execution_status", "RUNNING");
	}

}

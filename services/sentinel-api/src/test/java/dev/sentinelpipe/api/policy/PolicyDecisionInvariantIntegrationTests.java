package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.DatabaseRoles;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.policy.PolicyFixtures.Findings;
import dev.sentinelpipe.api.policy.PolicyFixtures.JobContext;
import dev.sentinelpipe.api.scan.ScanLifecycleService;
import dev.sentinelpipe.api.scan.ScanService;
import dev.sentinelpipe.api.scan.TriggerType;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * M4 Phase 1 final review: a security decision can only come from the lifecycle and policy
 * functions with a matching evaluation record, never from rows a runtime role writes
 * directly (defect M4-5); every scan is pinned to exactly one immutable policy version even
 * while activations race with scan creation.
 */
class PolicyDecisionInvariantIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private TestDatabaseAdmin admin;

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private PolicyService policies;

	private JdbcTemplate api;

	private UUID organizationId;

	private UUID projectId;

	@BeforeEach
	void setUp() throws Exception {
		this.api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "invariants");
	}

	/** Runs SQL as the schema owner, the identity SECURITY DEFINER functions run as. */
	private void asOwner(String sql) {
		this.admin.connectAs(DatabaseRoles.MIGRATOR_USER, DatabaseRoles.MIGRATOR_PASSWORD)
			.execute("SET ROLE sentinel_owner; " + sql);
	}

	private UUID requestScan() {
		return this.scanService.requestScan(this.projectId, randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
	}

	@Test
	void theApiRoleCannotInsertAScanThatIsBornWithADecisionOrAlreadyRunning() {
		for (String[] state : List.of(new String[] { "COMPLETED", "PASS", "POLICY_EVALUATED" },
				new String[] { "COMPLETED", "FAIL", "POLICY_EVALUATED" },
				new String[] { "COMPLETED", "INCOMPLETE", "POLICY_EVALUATION_UNAVAILABLE" })) {
			UUID scanId = UUID.randomUUID();
			assertThatThrownBy(() -> this.api.update("""
					INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type, execution_status,
					    security_decision, decision_reason, version, requested_at, started_at, completed_at,
					    deadline_at, updated_at)
					VALUES (?, ?, repeat('a', 40), 'main', 'PUSH', ?, ?, ?, 0, now(), now(), now(),
					    now() + interval '1 hour', now())""", scanId, this.projectId, state[0], state[1], state[2]))
				.as(String.join("/", state))
				.hasMessageContaining("new scans must be QUEUED without a decision");
			assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans WHERE id = ?", Integer.class,
					scanId))
				.isZero();
		}
		assertThatThrownBy(() -> this.api.update("""
				INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type, execution_status,
				    security_decision, version, requested_at, started_at, deadline_at, updated_at)
				VALUES (gen_random_uuid(), ?, repeat('a', 40), 'main', 'PUSH', 'EVALUATING', 'PENDING', 0, now(),
				    now(), now() + interval '1 hour', now())""", this.projectId))
			.hasMessageContaining("new scans must be QUEUED without a decision");
	}

	@Test
	void theApiRoleCannotInsertAJobThatIsBornCompletedOrLeased() {
		UUID scanId = requestScan();

		assertThatThrownBy(() -> this.api.update("""
				INSERT INTO scan_jobs (id, scan_id, scanner_type, execution_status, attempt_count, version, created_at,
				    started_at, completed_at, updated_at)
				VALUES (gen_random_uuid(), ?, 'GITLEAKS', 'COMPLETED', 1, 0, now(), now(), now(), now())""", scanId))
			.hasMessageContaining("new scan jobs must be QUEUED and unleased");
		assertThatThrownBy(() -> this.api.update("""
				INSERT INTO scan_jobs (id, scan_id, scanner_type, execution_status, attempt_count, version, created_at,
				    updated_at, lease_owner, lease_token_sha256)
				VALUES (gen_random_uuid(), ?, 'GITLEAKS', 'QUEUED', 0, 0, now(), now(), 'sentinel_worker_app',
				    repeat('a', 64))""", scanId))
			.hasMessageContaining("new scan jobs must be QUEUED and unleased");
		// Ordinary planning still works.
		this.lifecycle.planJob(scanId, ScannerType.GITLEAKS);
	}

	@Test
	void evenTheOwnerContextCannotSetAPolicyDecisionWithoutAMatchingEvaluation() throws Exception {
		UUID versionId = this.policies.createVersion(this.organizationId, PolicyFixtures.gitleaksOnly("secrets"),
				"user:test").id();
		this.policies.activate(this.projectId, versionId, "user:test");
		UUID scanId = requestScan();
		this.lifecycle.planJob(scanId, ScannerType.GITLEAKS);
		WorkerProtocol worker = WorkerProtocol.asWorker(this.admin);
		Lease lease = worker.claim(scanId, "GITLEAKS").orElseThrow();
		worker.completeWithEvidence(lease, "findings.json", new Findings(PolicyScanner.GITLEAKS,
				new JobContext(lease.organizationId(), lease.projectId(), lease.scanId(), lease.jobId(),
						lease.commitSha()))
			.finding("x")
			.bytes());

		// SECURITY DEFINER functions run as the owner: a future function that set a decision
		// without an evaluation would be refused, whatever the decision or reason.
		for (String set : List.of("security_decision = 'PASS', decision_reason = 'POLICY_EVALUATED'",
				"security_decision = 'INCOMPLETE', decision_reason = 'POLICY_EVALUATION_UNAVAILABLE'")) {
			assertThatThrownBy(() -> asOwner("UPDATE scans SET execution_status = 'COMPLETED', " + set
					+ ", completed_at = now() WHERE id = '" + scanId + "'"))
				.as(set)
				.hasMessageContaining("a policy decision requires a matching evaluation record");
		}

		assertThat(this.lifecycle.evaluate(scanId)).isTrue();
		// The record is FAIL: the scan cannot be turned into PASS afterwards either.
		assertThat(this.jdbcTemplate.queryForObject("SELECT security_decision FROM scans WHERE id = ?",
				String.class, scanId))
			.isEqualTo("FAIL");
		assertThatThrownBy(() -> asOwner("UPDATE scans SET security_decision = 'PASS' WHERE id = '" + scanId + "'"))
			.hasMessageContaining("a policy decision requires a matching evaluation record");
	}

	@Test
	void everyScanIsPinnedToExactlyOneVersionWhileActivationsRaceWithScanCreation() throws Exception {
		List<UUID> versions = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			versions.add(this.policies
				.createVersion(this.organizationId,
						PolicyFixtures.gitleaksOnly("raced").replace("\"max_blocking_findings\": 0",
								"\"max_blocking_findings\": " + i),
						"user:test")
				.id());
		}
		this.policies.activate(this.projectId, versions.get(0), "user:test");
		int scans = 24;
		int activations = 12;
		ExecutorService pool = Executors.newFixedThreadPool(8);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<UUID>> created = new ArrayList<>();
		List<Future<?>> activated = new ArrayList<>();
		try {
			for (int i = 0; i < scans; i++) {
				created.add(pool.submit((Callable<UUID>) () -> {
					start.await();
					return requestScan();
				}));
			}
			for (int i = 0; i < activations; i++) {
				UUID version = versions.get(i % versions.size());
				activated.add(pool.submit(() -> {
					start.await();
					return this.policies.activate(this.projectId, version, "user:test");
				}));
			}
			start.countDown();
			for (Future<?> activation : activated) {
				activation.get();
			}
			List<UUID> scanIds = new ArrayList<>();
			for (Future<UUID> scan : created) {
				scanIds.add(scan.get());
			}

			for (UUID scanId : scanIds) {
				List<Map<String, Object>> pins = this.jdbcTemplate.queryForList("""
						SELECT sp.policy_version_id, a.policy_version_id AS assigned_version, a.project_id
						FROM policy.scan_policies sp JOIN policy.project_assignments a ON a.id = sp.assignment_id
						WHERE sp.scan_id = ?""", scanId);
				assertThat(pins).as("scan %s", scanId).hasSize(1);
				assertThat(pins.get(0).get("policy_version_id")).isIn(versions.toArray())
					.isEqualTo(pins.get(0).get("assigned_version"));
				assertThat(pins.get(0).get("project_id")).isEqualTo(this.projectId);
			}
			// A pin can be written once only, and is immutable.
			assertThatThrownBy(() -> this.api.queryForObject("SELECT policy.pin_scan_policy(?)", UUID.class,
					scanIds.get(0)))
				.hasMessageContaining("scan cannot be pinned");
			assertThatThrownBy(() -> this.jdbcTemplate.update(
					"UPDATE policy.scan_policies SET policy_version_id = ? WHERE scan_id = ?", versions.get(2),
					scanIds.get(0)))
				.hasMessageContaining("policy records are immutable");
		}
		finally {
			pool.shutdownNow();
		}
	}

	@Test
	void aPinOrEvaluationCanNeverReferenceAnotherTenantsPolicy() throws Exception {
		UUID otherOrganization = createOrganization();
		UUID foreignVersion = this.policies
			.createVersion(otherOrganization, PolicyFixtures.gitleaksOnly("foreign"), "user:test")
			.id();
		UUID ownVersion = this.policies
			.createVersion(this.organizationId, PolicyFixtures.gitleaksOnly("own"), "user:test")
			.id();
		this.policies.activate(this.projectId, ownVersion, "user:test");
		UUID scanId = requestScan();
		Long assignment = this.jdbcTemplate.queryForObject(
				"SELECT assignment_id FROM policy.scan_policies WHERE scan_id = ?", Long.class, scanId);

		// Even a superuser cannot pin across tenants: the composite keys refuse every mix.
		UUID unpinned = UUID.randomUUID();
		this.jdbcTemplate.update("""
				INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type, execution_status,
				    security_decision, version, requested_at, updated_at)
				VALUES (?, ?, repeat('b', 40), 'main', 'PUSH', 'QUEUED', 'PENDING', 0, now(), now())""", unpinned,
				this.projectId);
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.scan_policies (scan_id, project_id, organization_id, policy_version_id, assignment_id)
				VALUES (?, ?, ?, ?, ?)""", unpinned, this.projectId, this.organizationId, foreignVersion, assignment))
			.hasMessageContaining("fk_scan_policies_version");
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.scan_policies (scan_id, project_id, organization_id, policy_version_id, assignment_id)
				VALUES (?, ?, ?, ?, ?)""", unpinned, this.projectId, otherOrganization, foreignVersion, assignment))
			.hasMessageContaining("fk_scan_policies_project");
	}

}

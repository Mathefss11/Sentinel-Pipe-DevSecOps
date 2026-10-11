package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.DatabaseRoles;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.TestJwts;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.policy.PolicyFixtures.Findings;
import dev.sentinelpipe.api.policy.PolicyFixtures.JobContext;
import dev.sentinelpipe.api.scan.ExecutionSupervisor;
import dev.sentinelpipe.api.scan.ScanLifecycleService;
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
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;

/**
 * The policy engine end to end inside the control plane (ADR-0013): policies activated
 * through the API, scans pinned at request time, evidence uploaded and results submitted
 * through the real worker protocol with the worker's own database login, evaluation by the
 * lifecycle service, and records checked by {@code policy.record_evaluation}. The evidence
 * documents are synthetic; real scanner runs are covered by the end-to-end tests.
 */
class PolicyEvaluationIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private ExecutionSupervisor supervisor;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	private UUID organizationId;

	private UUID projectId;

	@BeforeEach
	void setUp() throws Exception {
		this.worker = WorkerProtocol.asWorker(this.admin);
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "evaluated");
	}

	// --- Helpers ------------------------------------------------------------------------

	private UUID createPolicy(UUID organizationId, String definition) throws Exception {
		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations/{id}/policies", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content(definition))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
		return UUID.fromString(json(result).get("id").asString());
	}

	private void activate(UUID projectId, UUID versionId) throws Exception {
		MvcResult result = this.mockMvc
			.perform(put("/api/v1/projects/{id}/policy", projectId).contentType(MediaType.APPLICATION_JSON)
				.content("{\"policyVersionId\": \"%s\"}".formatted(versionId)))
			.andReturn();
		assertThat(result.getResponse().getStatus()).isEqualTo(200);
	}

	private UUID activePolicy(String definition) throws Exception {
		UUID versionId = createPolicy(this.organizationId, definition);
		activate(this.projectId, versionId);
		return versionId;
	}

	private UUID scan(ScannerType... scanners) throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(this.projectId, randomSha(), null)).get("id").asString());
		for (ScannerType scanner : scanners) {
			this.lifecycle.planJob(scanId, scanner);
		}
		return scanId;
	}

	private Lease claim(UUID scanId, ScannerType scanner) {
		return this.worker.claim(scanId, scanner.name())
			.orElseThrow(() -> new AssertionError("no claimable " + scanner + " job"));
	}

	private static JobContext context(Lease lease) {
		return new JobContext(lease.organizationId(), lease.projectId(), lease.scanId(), lease.jobId(),
				lease.commitSha());
	}

	/** Claims the scanner's job and completes it with the evidence the function builds. */
	private Lease complete(UUID scanId, ScannerType scanner, Function<JobContext, byte[]> evidence) {
		Lease lease = claim(scanId, scanner);
		assertThat(this.worker.completeWithEvidence(lease, "findings.json", evidence.apply(context(lease))))
			.isEqualTo("ACCEPTED");
		return lease;
	}

	private static Function<JobContext, byte[]> clean(PolicyScanner scanner) {
		return (context) -> new Findings(scanner, context).bytes();
	}

	private Map<String, Object> scanRow(UUID scanId) {
		return this.jdbcTemplate.queryForMap(
				"SELECT execution_status, security_decision, decision_reason FROM scans WHERE id = ?", scanId);
	}

	private JsonNode evaluation(UUID scanId) throws Exception {
		MvcResult result = this.mockMvc.perform(get("/api/v1/scans/{id}/evaluation", scanId)).andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		JsonNode body = json(result);
		ContractSchemas.assertValid("policy-evaluation.schema.json", body);
		return body;
	}

	private static List<String> reasons(JsonNode evaluation) {
		List<String> codes = new ArrayList<>();
		evaluation.get("reasons")
			.forEach((reason) -> codes.add(reason.get("code").asString() + ":" + reason.get("scanner").asString("")
					+ ":" + reason.get("subject").asString("")));
		return codes;
	}

	private void assertCompleted(UUID scanId, String decision) {
		assertThat(scanRow(scanId)).containsEntry("execution_status", "COMPLETED")
			.containsEntry("security_decision", decision)
			.containsEntry("decision_reason", "POLICY_EVALUATED");
	}

	// --- Decisions ----------------------------------------------------------------------

	@Test
	void cleanCompleteEvidenceFromEveryMandatoryScannerIsPassWithAnAuditableRecord() throws Exception {
		UUID versionId = activePolicy(PolicyFixtures.allScanners("baseline"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		for (PolicyScanner scanner : PolicyScanner.values()) {
			complete(scanId, scanner.scannerType(), clean(scanner));
		}
		assertThat(scanRow(scanId)).containsEntry("execution_status", "EVALUATING");

		assertThat(this.supervisor.runOnce().scansEvaluated()).isGreaterThanOrEqualTo(1);

		assertCompleted(scanId, "PASS");
		JsonNode record = evaluation(scanId);
		assertThat(record.get("decision").asString()).isEqualTo("PASS");
		assertThat(record.get("reasons")).isEmpty();
		assertThat(record.get("policyVersionId").asString()).isEqualTo(versionId.toString());
		assertThat(record.get("engineVersion").asString()).isEqualTo(PolicyEvaluator.ENGINE_VERSION);
		assertThat(record.get("evidence")).hasSize(3);
		// The record references exactly the evidence of record, by the digests PostgreSQL computed.
		for (JsonNode evidence : record.get("evidence")) {
			assertThat(this.jdbcTemplate.queryForObject("""
					SELECT u.sha256 FROM evidence.job_artifacts u
					WHERE u.job_id = ? AND u.lease_epoch = ? AND u.name = 'findings.json'""", String.class,
					UUID.fromString(evidence.get("jobId").asString()), evidence.get("leaseEpoch").asLong()))
				.isEqualTo(evidence.get("sha256").asString());
		}
		assertThat(this.jdbcTemplate.queryForList(
				"SELECT detail FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = 'SCAN_COMPLETED'",
				String.class, scanId))
			.containsExactly("PASS");
	}

	@Test
	void aDetectedSecretIsFail() throws Exception {
		activePolicy(PolicyFixtures.gitleaksOnly("secrets"));
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, (context) -> new Findings(PolicyScanner.GITLEAKS, context).finding("x")
			.finding("x")
			.bytes());

		assertThat(this.lifecycle.evaluate(scanId)).isTrue();

		assertCompleted(scanId, "FAIL");
		JsonNode record = evaluation(scanId);
		assertThat(reasons(record)).containsExactly("BLOCKING_FINDINGS_EXCEEDED:GITLEAKS:");
		assertThat(record.at("/reasons/0/observed").asInt()).isEqualTo(2);
		assertThat(record.at("/reasons/0/limit").asInt()).isZero();
	}

	@Test
	void aConfirmedViolationIsFailWhileAMissingScannerIsStillRecorded() throws Exception {
		activePolicy(PolicyFixtures.allScanners("baseline"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP);
		complete(scanId, ScannerType.GITLEAKS,
				(context) -> new Findings(PolicyScanner.GITLEAKS, context).finding("x").bytes());
		complete(scanId, ScannerType.SEMGREP, clean(PolicyScanner.SEMGREP));

		this.lifecycle.evaluate(scanId);

		assertCompleted(scanId, "FAIL");
		JsonNode record = evaluation(scanId);
		assertThat(reasons(record)).containsExactly("BLOCKING_FINDINGS_EXCEEDED:GITLEAKS:",
				"REQUIRED_SCANNER_NOT_PLANNED:TRIVY:");
		assertThat(record.get("violationCount").asInt()).isEqualTo(1);
		assertThat(record.get("incompleteCount").asInt()).isEqualTo(1);
	}

	@Test
	void aCrashedScannerOrACompletedJobWithoutEvidenceIsIncomplete() throws Exception {
		activePolicy(PolicyFixtures.allScanners("baseline"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		assertThat(this.worker.fail(claim(scanId, ScannerType.GITLEAKS), "RESOURCE_LIMIT_EXCEEDED"))
			.isEqualTo("ACCEPTED");
		assertThat(this.worker.complete(claim(scanId, ScannerType.SEMGREP))).as("COMPLETED, no artifact")
			.isEqualTo("ACCEPTED");
		complete(scanId, ScannerType.TRIVY, clean(PolicyScanner.TRIVY));

		this.lifecycle.evaluate(scanId);

		assertCompleted(scanId, "INCOMPLETE");
		JsonNode record = evaluation(scanId);
		assertThat(reasons(record)).containsExactly("EVIDENCE_MISSING:SEMGREP:FINDINGS_ARTIFACT",
				"SCANNER_EXECUTION_FAILED:GITLEAKS:RESOURCE_LIMIT_EXCEEDED");
		assertThat(record.get("evidence")).hasSize(1);
	}

	@Test
	void unsupportedSchemasIncompleteCoverageAndTheKnownPypiLimitationAreIncomplete() throws Exception {
		activePolicy(PolicyFixtures.allScanners("baseline"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		complete(scanId, ScannerType.GITLEAKS,
				(context) -> new Findings(PolicyScanner.GITLEAKS, context).schemaVersion(2).bytes());
		complete(scanId, ScannerType.SEMGREP,
				(context) -> new Findings(PolicyScanner.SEMGREP, context).incomplete("FILES_NOT_ANALYZED").bytes());
		complete(scanId, ScannerType.TRIVY, (context) -> new Findings(PolicyScanner.TRIVY, context)
			.incomplete("PYPI_NAME_MATCHING_UNVERIFIED")
			.bytes());

		this.lifecycle.evaluate(scanId);

		assertCompleted(scanId, "INCOMPLETE");
		assertThat(reasons(evaluation(scanId))).containsExactly("COVERAGE_INCOMPLETE:SEMGREP:",
				"COVERAGE_LIMITATION_NOT_ACCEPTED:SEMGREP:FILES_NOT_ANALYZED", "EVIDENCE_SCHEMA_UNSUPPORTED:GITLEAKS:",
				"COVERAGE_INCOMPLETE:TRIVY:", "COVERAGE_LIMITATION_NOT_ACCEPTED:TRIVY:PYPI_NAME_MATCHING_UNVERIFIED");
	}

	@Test
	void aScanWithoutAPolicyIsIncompleteAndHasNoEvaluationRecord() throws Exception {
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, clean(PolicyScanner.GITLEAKS));

		this.lifecycle.evaluate(scanId);

		assertThat(scanRow(scanId)).containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "POLICY_EVALUATION_UNAVAILABLE");
		assertThat(this.mockMvc.perform(get("/api/v1/scans/{id}/evaluation", scanId))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(404);
	}

	// --- Evidence trust -----------------------------------------------------------------

	@Test
	void evidenceThatNamesAnotherJobOrAStoredResultThatWasAlteredIsNeverTrusted() throws Exception {
		activePolicy(PolicyFixtures.allScanners("baseline"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		// A leaky document bound to another (random) job: the worker can upload it under its
		// lease, but it is not evidence about this job.
		complete(scanId, ScannerType.GITLEAKS, (context) -> new Findings(PolicyScanner.GITLEAKS,
				new JobContext(context.organizationId(), context.projectId(), context.scanId(), UUID.randomUUID(),
						context.commitSha()))
			.finding("x")
			.bytes());
		Lease semgrep = complete(scanId, ScannerType.SEMGREP, clean(PolicyScanner.SEMGREP));
		complete(scanId, ScannerType.TRIVY, clean(PolicyScanner.TRIVY));
		// The accepted result is stored as JSONB without a database-level digest check:
		// alter it after acceptance (as a database administrator could).
		this.jdbcTemplate.update(
				"UPDATE lifecycle.job_reports SET result = jsonb_set(result, '{attempt}', '2') WHERE job_id = ?",
				semgrep.jobId());

		this.lifecycle.evaluate(scanId);

		assertCompleted(scanId, "INCOMPLETE");
		assertThat(reasons(evaluation(scanId))).containsExactly("EVIDENCE_INTEGRITY_FAILED:SEMGREP:RESULT_DIGEST",
				"EVIDENCE_BINDING_MISMATCH:GITLEAKS:FINDINGS_CONTEXT");
	}

	@Test
	void evidenceFromASupersededLeaseIsNeverEvaluated() throws Exception {
		activePolicy(PolicyFixtures.gitleaksOnly("secrets"));
		UUID scanId = scan(ScannerType.GITLEAKS);
		// Attempt 1 uploads a leaky document and reports a retryable failure referencing it.
		Lease first = claim(scanId, ScannerType.GITLEAKS);
		WorkerProtocol.Upload leaky = this.worker.putEvidence(first, "findings.json", "application/json",
				new Findings(PolicyScanner.GITLEAKS, context(first)).finding("x").bytes());
		assertThat(this.worker.submit(first, "FAILED", "SCANNER_ERROR",
				List.of(WorkerProtocol.Artifact.of(leaky, "findings.json", "application/json"))))
			.isEqualTo("ACCEPTED");
		this.jdbcTemplate.update("UPDATE scan_jobs SET next_attempt_at = now() - interval '1 second' WHERE id = ?",
				first.jobId());
		// Attempt 2 (a new fencing epoch) completes with clean evidence.
		Lease second = complete(scanId, ScannerType.GITLEAKS, clean(PolicyScanner.GITLEAKS));
		assertThat(second.epoch()).isGreaterThan(first.epoch());

		this.lifecycle.evaluate(scanId);

		assertCompleted(scanId, "PASS");
		JsonNode record = evaluation(scanId);
		assertThat(record.at("/evidence/0/leaseEpoch").asLong()).isEqualTo(second.epoch());
		assertThat(record.at("/evidence/0/sha256").asString()).isNotEqualTo(leaky.sha256());
	}

	@Test
	void forgedOrInconsistentEvaluationRecordsAreRefusedByTheDatabase() throws Exception {
		UUID versionId = activePolicy(PolicyFixtures.gitleaksOnly("secrets"));
		String sha = this.jdbcTemplate.queryForObject(
				"SELECT definition_sha256 FROM policy.policy_versions WHERE id = ?", String.class, versionId);
		UUID scanId = scan(ScannerType.GITLEAKS);
		Lease lease = complete(scanId, ScannerType.GITLEAKS,
				(context) -> new Findings(PolicyScanner.GITLEAKS, context).finding("x").bytes());
		String artifactSha = this.jdbcTemplate.queryForObject(
				"SELECT sha256 FROM evidence.job_artifacts WHERE job_id = ?", String.class, lease.jobId());
		String resultSha = this.jdbcTemplate.queryForObject(
				"SELECT result_sha256 FROM lifecycle.job_reports WHERE job_id = ?", String.class, lease.jobId());
		// Evidence of record of another tenant's scan.
		UUID otherProject = createProject(createOrganization(), "other");
		UUID otherScan = UUID.fromString(json(requestScan(otherProject, randomSha(), null)).get("id").asString());
		this.lifecycle.planJob(otherScan, ScannerType.GITLEAKS);
		Lease other = this.worker.claim(otherScan, "GITLEAKS").orElseThrow();
		this.worker.completeWithEvidence(other, "findings.json",
				new Findings(PolicyScanner.GITLEAKS, context(other)).bytes());
		String otherSha = this.jdbcTemplate.queryForObject(
				"SELECT sha256 FROM evidence.job_artifacts WHERE job_id = ?", String.class, other.jobId());
		String otherResult = this.jdbcTemplate.queryForObject(
				"SELECT result_sha256 FROM lifecycle.job_reports WHERE job_id = ?", String.class, other.jobId());
		UUID foreignVersion = createPolicy(createOrganization(), PolicyFixtures.gitleaksOnly("foreign"));

		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		String ownEvidence = evidence(lease.jobId(), artifactSha, resultSha);
		String violation = "[{\"code\":\"BLOCKING_FINDINGS_EXCEEDED\",\"effect\":\"VIOLATION\",\"limit\":0,"
				+ "\"observed\":1,\"scanner\":\"GITLEAKS\",\"subject\":null}]";
		Map<String, Object[]> forgeries = Map.of(
				// PASS with no evidence, or hiding the violation.
				"PASS_NOT_JUSTIFIED", new Object[] { versionId, sha, "PASS", "[]", "[]" },
				"EVIDENCE_NOT_OF_RECORD", new Object[] { versionId, sha, "PASS", "[]",
						evidence(other.jobId(), otherSha, otherResult) },
				"DECISION_INCONSISTENT", new Object[] { versionId, sha, "INCOMPLETE", violation, ownEvidence },
				"POLICY_MISMATCH", new Object[] { foreignVersion, sha, "FAIL", violation, ownEvidence },
				"VIOLATION_WITHOUT_EVIDENCE", new Object[] { versionId, sha, "FAIL",
						violation.replace("GITLEAKS", "TRIVY"), ownEvidence });
		for (Map.Entry<String, Object[]> forgery : forgeries.entrySet()) {
			Object[] a = forgery.getValue();
			assertThatThrownBy(() -> api.queryForObject(
					"SELECT policy.record_evaluation(?, ?, ?, 'sentinelpipe-policy/1.0.0', ?, ?, ?, now())",
					String.class, scanId, a[0], a[1], a[2], a[3], a[4]))
				.as(forgery.getKey())
				.hasMessageContaining("evaluation rejected: " + forgery.getKey());
		}
		// A forged digest for the right job, and PASS through the old path, are refused too.
		assertThatThrownBy(() -> api.queryForObject(
				"SELECT policy.record_evaluation(?, ?, ?, 'sentinelpipe-policy/1.0.0', 'FAIL', ?, ?, now())",
				String.class, scanId, versionId, sha, violation, evidence(lease.jobId(), otherSha, resultSha)))
			.hasMessageContaining("EVIDENCE_NOT_OF_RECORD");
		assertThat(api.queryForObject("SELECT lifecycle.complete_evaluation(?, 'INCOMPLETE', 'POLICY_EVALUATION_UNAVAILABLE')",
				String.class, scanId))
			.isEqualTo("POLICY_EVALUATION_REQUIRED");
		assertThat(scanRow(scanId)).containsEntry("execution_status", "EVALUATING")
			.containsEntry("security_decision", "PENDING");
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.evaluations WHERE scan_id = ?",
				Integer.class, scanId))
			.isZero();

		// The engine's own record is accepted.
		assertThat(this.lifecycle.evaluate(scanId)).isTrue();
		assertCompleted(scanId, "FAIL");
	}

	private static String evidence(UUID jobId, String sha, String resultSha) {
		return "[{\"job_id\":\"%s\",\"lease_epoch\":1,\"name\":\"findings.json\",\"result_sha256\":\"%s\","
				.formatted(jobId, resultSha) + "\"scanner_type\":\"GITLEAKS\",\"sha256\":\"%s\"}]".formatted(sha);
	}

	// --- Policy versions, concurrency, audit ------------------------------------------

	@Test
	void aScanIsEvaluatedAgainstThePolicyInForceWhenItWasRequestedAndTheRecordStaysAuditable() throws Exception {
		UUID strict = activePolicy(PolicyFixtures.gitleaksOnly("secrets"));
		UUID scanId = scan(ScannerType.GITLEAKS);
		// A laxer version is activated after the scan was requested, before evaluation.
		UUID lax = createPolicy(this.organizationId,
				PolicyFixtures.gitleaksOnly("secrets").replace("\"max_blocking_findings\": 0", "\"max_blocking_findings\": 5"));
		activate(this.projectId, lax);
		complete(scanId, ScannerType.GITLEAKS,
				(context) -> new Findings(PolicyScanner.GITLEAKS, context).finding("x").bytes());

		this.lifecycle.evaluate(scanId);

		assertCompleted(scanId, "FAIL");
		JsonNode before = evaluation(scanId);
		assertThat(before.get("policyVersionId").asString()).isEqualTo(strict.toString());
		// Later activity changes nothing about the record, and the evaluated version stays readable.
		activate(this.projectId, createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("other")));
		assertThat(evaluation(scanId)).isEqualTo(before);
		JsonNode version = json(this.mockMvc.perform(get("/api/v1/policy-versions/{id}", strict)).andReturn());
		assertThat(version.get("definitionSha256").asString()).isEqualTo(before.get("policySha256").asString());
		assertThatThrownBy(() -> this.jdbcTemplate.update("UPDATE policy.evaluations SET decision = 'PASS' WHERE scan_id = ?",
				scanId))
			.hasMessageContaining("policy records are immutable");
		assertThatThrownBy(() -> this.jdbcTemplate.update("DELETE FROM policy.evaluation_evidence"))
			.hasMessageContaining("policy records are immutable");
		// The next scan is pinned to the version now in force.
		UUID next = scan(ScannerType.GITLEAKS);
		assertThat(this.jdbcTemplate.queryForObject("SELECT policy_version_id FROM policy.scan_policies WHERE scan_id = ?",
				UUID.class, next))
			.isNotIn(strict, lax);
	}

	@Test
	void concurrentEvaluationsRecordExactlyOneDecision() throws Exception {
		activePolicy(PolicyFixtures.gitleaksOnly("secrets"));
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, clean(PolicyScanner.GITLEAKS));
		int evaluators = 6;
		ExecutorService pool = Executors.newFixedThreadPool(evaluators);
		CountDownLatch start = new CountDownLatch(1);
		List<Boolean> outcomes = new ArrayList<>();
		try {
			List<Callable<Boolean>> tasks = new ArrayList<>();
			for (int i = 0; i < evaluators; i++) {
				tasks.add(() -> {
					start.await();
					return this.lifecycle.evaluate(scanId);
				});
			}
			List<Future<Boolean>> futures = new ArrayList<>();
			tasks.forEach((task) -> futures.add(pool.submit(task)));
			start.countDown();
			for (Future<Boolean> future : futures) {
				outcomes.add(future.get());
			}
		}
		finally {
			pool.shutdownNow();
		}

		assertThat(outcomes).containsOnlyOnce(true);
		assertCompleted(scanId, "PASS");
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.evaluations WHERE scan_id = ?",
				Integer.class, scanId))
			.isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = 'SCAN_COMPLETED'",
				Integer.class, scanId))
			.isEqualTo(1);
	}

	@Test
	void evaluationRecordsAreVisibleToMembersOnly() throws Exception {
		activePolicy(PolicyFixtures.gitleaksOnly("secrets"));
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, clean(PolicyScanner.GITLEAKS));
		this.lifecycle.evaluate(scanId);
		String viewer = uniqueSubject("viewer");
		grant(this.organizationId, viewer, "VIEWER");

		assertThat(this.mockMvc
			.perform(get("/api/v1/scans/{id}/evaluation", scanId).header(HttpHeaders.AUTHORIZATION,
					TestJwts.bearer(viewer)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
		assertThat(this.mockMvc
			.perform(get("/api/v1/scans/{id}/evaluation", scanId).header(HttpHeaders.AUTHORIZATION,
					TestJwts.bearer(uniqueSubject("outsider"))))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(404);
	}

}

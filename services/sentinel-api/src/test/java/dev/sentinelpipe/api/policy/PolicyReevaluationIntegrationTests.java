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
import dev.sentinelpipe.api.scan.ScanLifecycleService;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
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
 * Historical policy re-evaluation (ADR-0014) inside the control plane: completed scans
 * whose evidence was uploaded through the real worker protocol, re-evaluated through the
 * API under explicitly chosen policy versions, and records checked by
 * {@code policy.record_historical_evaluation}. Evidence documents are synthetic.
 */
class PolicyReevaluationIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private PolicyReevaluationService reevaluations;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	private UUID organizationId;

	private UUID projectId;

	@BeforeEach
	void setUp() throws Exception {
		this.worker = WorkerProtocol.asWorker(this.admin);
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "reevaluated");
	}

	// --- Helpers ------------------------------------------------------------------------

	/** Gitleaks only, up to {@code allowed} detected secrets. */
	private static String gitleaks(String name, int allowed) {
		return PolicyFixtures.gitleaksOnly(name)
			.replace("\"max_blocking_findings\": 0", "\"max_blocking_findings\": " + allowed);
	}

	private UUID createPolicy(UUID organizationId, String definition) throws Exception {
		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations/{id}/policies", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content(definition))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
		return UUID.fromString(json(result).get("id").asString());
	}

	private UUID activate(UUID versionId) throws Exception {
		MvcResult result = this.mockMvc
			.perform(put("/api/v1/projects/{id}/policy", this.projectId).contentType(MediaType.APPLICATION_JSON)
				.content("{\"policyVersionId\": \"%s\"}".formatted(versionId)))
			.andReturn();
		assertThat(result.getResponse().getStatus()).isEqualTo(200);
		return versionId;
	}

	private UUID scan(ScannerType... scanners) throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(this.projectId, randomSha(), null)).get("id").asString());
		for (ScannerType scanner : scanners) {
			this.lifecycle.planJob(scanId, scanner);
		}
		return scanId;
	}

	private Lease complete(UUID scanId, ScannerType scanner, Function<JobContext, byte[]> evidence) {
		Lease lease = this.worker.claim(scanId, scanner.name()).orElseThrow();
		assertThat(this.worker.completeWithEvidence(lease, "findings.json", evidence.apply(new JobContext(
				lease.organizationId(), lease.projectId(), lease.scanId(), lease.jobId(), lease.commitSha()))))
			.isEqualTo("ACCEPTED");
		return lease;
	}

	/** A completed Gitleaks scan with {@code secrets} detected secrets. */
	private UUID completedGitleaksScan(int secrets) throws Exception {
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, (context) -> {
			Findings findings = new Findings(PolicyScanner.GITLEAKS, context);
			for (int i = 0; i < secrets; i++) {
				findings.finding("x");
			}
			return findings.bytes();
		});
		assertThat(this.lifecycle.evaluate(scanId)).isTrue();
		return scanId;
	}

	private MvcResult reevaluate(UUID scanId, UUID versionId, String bearer) throws Exception {
		var request = post("/api/v1/scans/{id}/reevaluations", scanId).contentType(MediaType.APPLICATION_JSON)
			.content("{\"policyVersionId\": \"%s\"}".formatted(versionId));
		if (bearer != null) {
			request.header(HttpHeaders.AUTHORIZATION, bearer);
		}
		return this.mockMvc.perform(request).andReturn();
	}

	/** Re-evaluates as the organization's OWNER and expects a new record. */
	private JsonNode recorded(UUID scanId, UUID versionId) throws Exception {
		MvcResult result = reevaluate(scanId, versionId, null);
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
		assertThat(result.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("false");
		JsonNode body = json(result);
		ContractSchemas.assertValid("scan-evaluation.schema.json", body);
		assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION))
			.isEqualTo("/api/v1/scans/" + scanId + "/evaluations/" + body.get("id").asString());
		return body;
	}

	private JsonNode getJson(String path, Object... variables) throws Exception {
		MvcResult result = this.mockMvc.perform(get(path, variables)).andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return json(result);
	}

	private JsonNode history(UUID scanId, int page, int size) throws Exception {
		JsonNode body = getJson("/api/v1/scans/{id}/evaluations?page={p}&size={s}", scanId, page, size);
		ContractSchemas.assertValid("scan-evaluation-page.schema.json", body);
		return body;
	}

	private static List<String> reasons(JsonNode evaluation) {
		List<String> codes = new ArrayList<>();
		evaluation.get("reasons")
			.forEach((reason) -> codes.add(reason.get("code").asString() + ":" + reason.get("scanner").asString("")
					+ ":" + reason.get("subject").asString("")));
		return codes;
	}

	private int historicalCount(UUID scanId) {
		return this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.historical_evaluations WHERE scan_id = ?",
				Integer.class, scanId);
	}

	/** Everything a re-evaluation must leave untouched, as stored. */
	private List<Object> untouchedState(UUID scanId) {
		List<Object> state = new ArrayList<>();
		state.add(this.jdbcTemplate.queryForMap("SELECT * FROM scans WHERE id = ?", scanId));
		state.add(this.jdbcTemplate.queryForList("SELECT * FROM scan_jobs WHERE scan_id = ? ORDER BY id", scanId));
		state.add(this.jdbcTemplate.queryForList("SELECT * FROM policy.scan_policies WHERE scan_id = ?", scanId));
		state.add(this.jdbcTemplate.queryForList("SELECT * FROM policy.evaluations WHERE scan_id = ?", scanId));
		state.add(this.jdbcTemplate.queryForList(
				"SELECT * FROM policy.evaluation_evidence WHERE scan_id = ? ORDER BY job_id", scanId));
		state.add(this.jdbcTemplate.queryForList(
				"SELECT * FROM policy.project_assignments WHERE project_id = ? ORDER BY id", this.projectId));
		state.add(this.jdbcTemplate.queryForList(
				"SELECT * FROM lifecycle.execution_events WHERE scan_id = ? ORDER BY 1", scanId));
		state.add(this.jdbcTemplate.queryForObject("SELECT count(*) FROM outbox_events", Long.class));
		state.add(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans", Long.class));
		state.add(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scan_jobs", Long.class));
		return state;
	}

	// --- Decisions under another policy -------------------------------------------------

	@Test
	void anOriginalPassBecomesAHistoricalFailUnderAStricterPolicyWithoutChangingTheScan() throws Exception {
		UUID lax = activate(createPolicy(this.organizationId, gitleaks("secrets", 5)));
		UUID scanId = completedGitleaksScan(1);
		JsonNode original = getJson("/api/v1/scans/{id}/evaluation", scanId);
		assertThat(original.get("decision").asString()).isEqualTo("PASS");
		UUID strict = createPolicy(this.organizationId, gitleaks("secrets", 0));
		List<Object> before = untouchedState(scanId);

		JsonNode historical = recorded(scanId, strict);

		assertThat(historical.get("evaluationType").asString()).isEqualTo("HISTORICAL");
		assertThat(historical.get("gating").asBoolean()).isFalse();
		assertThat(historical.get("decision").asString()).isEqualTo("FAIL");
		assertThat(reasons(historical)).containsExactly("BLOCKING_FINDINGS_EXCEEDED:GITLEAKS:");
		assertThat(historical.get("policyVersionId").asString()).isEqualTo(strict.toString());
		assertThat(historical.get("engineVersion").asString()).isEqualTo(PolicyEvaluator.ENGINE_VERSION);
		// Judged as of the original decision, recorded later.
		assertThat(historical.get("evaluatedAt").asString()).isEqualTo(original.get("evaluatedAt").asString());
		assertThat(historical.get("evidence")).isEqualTo(original.get("evidence"));
		assertThat(historical.get("initiatedBy").asString()).startsWith("user:");
		// The scan, its decision, its pin, its jobs, the active policy and the original record
		// are unchanged; nothing was published.
		assertThat(untouchedState(scanId)).isEqualTo(before);
		assertThat(getJson("/api/v1/scans/{id}", scanId).get("securityDecision").asString()).isEqualTo("PASS");
		assertThat(getJson("/api/v1/scans/{id}/evaluation", scanId)).isEqualTo(original);
		assertThat(getJson("/api/v1/projects/{id}/policy", this.projectId).get("policyVersionId").asString())
			.isEqualTo(lax.toString());
	}

	@Test
	void anOriginalFailBecomesAHistoricalPassUnderAMorePermissivePolicyOnCompleteEvidence() throws Exception {
		activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(2);
		assertThat(getJson("/api/v1/scans/{id}", scanId).get("securityDecision").asString()).isEqualTo("FAIL");
		UUID permissive = createPolicy(this.organizationId, gitleaks("tolerant", 2));

		JsonNode historical = recorded(scanId, permissive);

		assertThat(historical.get("decision").asString()).isEqualTo("PASS");
		assertThat(historical.get("reasons")).isEmpty();
		assertThat(historical.get("evidence")).hasSize(1);
		assertThat(getJson("/api/v1/scans/{id}", scanId).get("securityDecision").asString()).isEqualTo("FAIL");
	}

	@Test
	void reEvaluatingUnderThePinnedVersionReproducesTheOriginalRecord() throws Exception {
		UUID pinned = activate(createPolicy(this.organizationId, PolicyFixtures.allScanners("baseline")));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		complete(scanId, ScannerType.GITLEAKS, (c) -> new Findings(PolicyScanner.GITLEAKS, c).finding("x").bytes());
		complete(scanId, ScannerType.SEMGREP,
				(c) -> new Findings(PolicyScanner.SEMGREP, c).incomplete("FILES_NOT_ANALYZED").bytes());
		complete(scanId, ScannerType.TRIVY, (c) -> new Findings(PolicyScanner.TRIVY, c).bytes());
		this.lifecycle.evaluate(scanId);
		JsonNode original = getJson("/api/v1/scans/{id}/evaluation", scanId);

		JsonNode historical = recorded(scanId, pinned);

		for (String field : List.of("policyVersionId", "policySha256", "engineVersion", "decision", "violationCount",
				"incompleteCount", "reasons", "evidence", "evaluatedAt")) {
			assertThat(historical.get(field)).as(field).isEqualTo(original.get(field));
		}
		assertThat(historical.get("id")).isNotEqualTo(original.get("id"));
	}

	@Test
	void aScanCompletedWithoutAPolicyCanBeJudgedLaterWhileStayingIncomplete() throws Exception {
		UUID scanId = completedGitleaksScan(0);
		assertThat(this.jdbcTemplate.queryForMap("SELECT security_decision, decision_reason FROM scans WHERE id = ?",
				scanId))
			.containsEntry("security_decision", "INCOMPLETE")
			.containsEntry("decision_reason", "POLICY_EVALUATION_UNAVAILABLE");
		// A version that was never activated is eligible: re-evaluation never gates.
		UUID neverActive = createPolicy(this.organizationId, gitleaks("secrets", 0));

		JsonNode historical = recorded(scanId, neverActive);

		assertThat(historical.get("decision").asString()).isEqualTo("PASS");
		// Without an original evaluation, the evidence is judged as of the scan's completion.
		assertThat(Instant.parse(historical.get("evaluatedAt").asString())).isEqualTo(this.jdbcTemplate
			.queryForObject("SELECT completed_at FROM scans WHERE id = ?", OffsetDateTime.class, scanId)
			.toInstant());
		assertThat(this.jdbcTemplate.queryForObject("SELECT security_decision FROM scans WHERE id = ?", String.class,
				scanId))
			.isEqualTo("INCOMPLETE");
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.project_assignments WHERE project_id = ?",
				Integer.class, this.projectId))
			.isZero();
	}

	@Test
	void supersededAndInactiveVersionsAreEligibleAndDifferentVersionsAreDistinguishable() throws Exception {
		UUID first = activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(1);
		UUID second = activate(createPolicy(this.organizationId, gitleaks("secrets", 3)));
		UUID other = createPolicy(this.organizationId, gitleaks("other", 1));

		JsonNode a = recorded(scanId, first);
		JsonNode b = recorded(scanId, second);
		JsonNode c = recorded(scanId, other);

		assertThat(List.of(a.get("decision").asString(), b.get("decision").asString(), c.get("decision").asString()))
			.containsExactly("FAIL", "PASS", "PASS");
		assertThat(new HashSet<>(List.of(a.get("id"), b.get("id"), c.get("id")))).hasSize(3);
		assertThat(new HashSet<>(List.of(a.get("policySha256"), b.get("policySha256"), c.get("policySha256"))))
			.hasSize(3);
		assertThat(historicalCount(scanId)).isEqualTo(3);
	}

	// --- Evidence ---------------------------------------------------------------------------

	@Test
	void missingUnsupportedOrAlteredEvidenceIsIncompleteAndAConfirmedViolationStillFails() throws Exception {
		activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID missing = scan(ScannerType.GITLEAKS);
		assertThat(this.worker.complete(this.worker.claim(missing, "GITLEAKS").orElseThrow())).isEqualTo("ACCEPTED");
		this.lifecycle.evaluate(missing);
		UUID unsupported = scan(ScannerType.GITLEAKS);
		complete(unsupported, ScannerType.GITLEAKS,
				(c) -> new Findings(PolicyScanner.GITLEAKS, c).schemaVersion(2).bytes());
		this.lifecycle.evaluate(unsupported);
		UUID altered = completedGitleaksScan(1);
		// A database-level edit of the accepted result after the original decision.
		this.jdbcTemplate.update("UPDATE lifecycle.job_reports SET result = jsonb_set(result, '{attempt}', '7')"
				+ " WHERE job_id = (SELECT id FROM scan_jobs WHERE scan_id = ?)", altered);
		UUID both = createPolicy(this.organizationId, PolicyFixtures.allScanners("both"));
		UUID lax = createPolicy(this.organizationId, gitleaks("lax", 9));

		assertThat(reasons(recorded(missing, lax))).containsExactly("EVIDENCE_MISSING:GITLEAKS:FINDINGS_ARTIFACT");
		assertThat(reasons(recorded(unsupported, lax))).containsExactly("EVIDENCE_SCHEMA_UNSUPPORTED:GITLEAKS:");
		JsonNode integrity = recorded(altered, lax);
		assertThat(integrity.get("decision").asString()).isEqualTo("INCOMPLETE");
		assertThat(reasons(integrity)).containsExactly("EVIDENCE_INTEGRITY_FAILED:GITLEAKS:RESULT_DIGEST");
		assertThat(integrity.get("evidence")).isEmpty();
		// Precedence FAIL > INCOMPLETE: a policy that also requires Semgrep and Trivy.
		UUID leaky = completedGitleaksScan(1);
		JsonNode failAndIncomplete = recorded(leaky, both);
		assertThat(failAndIncomplete.get("decision").asString()).isEqualTo("FAIL");
		// Reasons are in the engine's deterministic order (scanner, then code).
		assertThat(reasons(failAndIncomplete)).containsExactly("REQUIRED_SCANNER_NOT_PLANNED:SEMGREP:",
				"BLOCKING_FINDINGS_EXCEEDED:GITLEAKS:", "REQUIRED_SCANNER_NOT_PLANNED:TRIVY:");
		assertThat(failAndIncomplete.get("violationCount").asInt()).isEqualTo(1);
		assertThat(failAndIncomplete.get("incompleteCount").asInt()).isEqualTo(2);
	}

	@Test
	void purgedEvidenceYieldsANewRecordAndNeverRewritesTheEarlierOne() throws Exception {
		activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(0);
		UUID version = createPolicy(this.organizationId, gitleaks("again", 0));
		JsonNode before = recorded(scanId, version);
		assertThat(before.get("decision").asString()).isEqualTo("PASS");
		String path = "/api/v1/scans/{id}/evaluations/{evaluationId}";
		JsonNode stored = getJson(path, scanId, before.get("id").asString());

		// Retention purges the content (as evidence.purge_expired would).
		this.jdbcTemplate.update("UPDATE evidence.objects o SET content = NULL, purged_at = now() FROM evidence.job_artifacts u"
				+ " JOIN scan_jobs j ON j.id = u.job_id WHERE j.scan_id = ? AND o.organization_id = u.organization_id"
				+ " AND o.sha256 = u.sha256", scanId);
		JsonNode after = recorded(scanId, version);

		assertThat(after.get("id")).isNotEqualTo(before.get("id"));
		assertThat(after.get("inputsSha256")).isNotEqualTo(before.get("inputsSha256"));
		assertThat(after.get("decision").asString()).isEqualTo("INCOMPLETE");
		assertThat(reasons(after)).containsExactly("EVIDENCE_PURGED:GITLEAKS:");
		// The earlier record is read exactly as stored, never recalculated.
		assertThat(getJson(path, scanId, before.get("id").asString())).isEqualTo(stored);
		assertThat(this.jdbcTemplate.queryForObject("SELECT decision FROM policy.historical_evaluations WHERE id = ?",
				String.class, UUID.fromString(before.get("id").asString())))
			.isEqualTo("PASS");
	}

	@Test
	void scannerFindingsOrEvidenceAreNeverAcceptedFromTheCaller() throws Exception {
		activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(1);
		UUID version = createPolicy(this.organizationId, gitleaks("lax", 5));
		for (String extra : List.of("\"findings\": []", "\"evidence\": [{\"sha256\": \"%s\"}]".formatted("a".repeat(64)),
				"\"decision\": \"PASS\"", "\"asOf\": \"2026-01-01T00:00:00Z\"")) {
			MvcResult result = this.mockMvc
				.perform(post("/api/v1/scans/{id}/reevaluations", scanId).contentType(MediaType.APPLICATION_JSON)
					.content("{\"policyVersionId\": \"%s\", %s}".formatted(version, extra)))
				.andReturn();
			assertThat(result.getResponse().getStatus()).as(extra).isEqualTo(400);
		}
		for (String body : List.of("{}", "{\"policyVersionId\": \"not-a-uuid\"}", "")) {
			assertThat(this.mockMvc
				.perform(post("/api/v1/scans/{id}/reevaluations", scanId).contentType(MediaType.APPLICATION_JSON)
					.content(body))
				.andReturn()
				.getResponse()
				.getStatus()).as(body).isEqualTo(400);
		}
		assertThat(historicalCount(scanId)).isZero();
	}

	// --- Eligibility and failures -------------------------------------------------------

	@Test
	void unfinishedScansUnknownForeignOrUnusableVersionsAndTheLimitFailExplicitly() throws Exception {
		UUID version = activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID running = scan(ScannerType.GITLEAKS);
		MvcResult notCompleted = reevaluate(running, version, null);
		assertThat(notCompleted.getResponse().getStatus()).isEqualTo(409);
		assertThat(json(notCompleted).get("code").asString()).isEqualTo("scan-not-completed");

		UUID scanId = completedGitleaksScan(0);
		assertThat(reevaluate(scanId, UUID.randomUUID(), null).getResponse().getStatus()).isEqualTo(404);
		assertThat(reevaluate(UUID.randomUUID(), version, null).getResponse().getStatus()).isEqualTo(404);

		// A stored version that no longer validates (inserted directly, as only a database
		// administrator could): explicit failure, nothing recorded.
		String invalid = "{\"evidence\":{\"findings_schema_versions\":[1],\"max_age_seconds\":86400},\"name\":\"broken\","
				+ "\"scanners\":{\"GITLEAKS\":{\"accepted_limitations\":[],\"max_blocking_findings\":-1,"
				+ "\"require_complete_coverage\":true}},\"schema_version\":1}";
		UUID policy = this.jdbcTemplate.queryForObject("INSERT INTO policy.policies (organization_id, name, created_by)"
				+ " VALUES (?, 'broken', 'test') RETURNING id", UUID.class, this.organizationId);
		UUID broken = this.jdbcTemplate.queryForObject("""
				INSERT INTO policy.policy_versions (policy_id, organization_id, version, schema_version, definition,
				    definition_sha256, created_by)
				VALUES (?, ?, 1, 1, ?, encode(sha256(convert_to(?, 'UTF8')), 'hex'), 'test') RETURNING id""",
				UUID.class, policy, this.organizationId, invalid, invalid);
		MvcResult unusable = reevaluate(scanId, broken, null);
		assertThat(unusable.getResponse().getStatus()).isEqualTo(409);
		assertThat(json(unusable).get("code").asString()).isEqualTo("policy-version-unusable");
		assertThat(historicalCount(scanId)).isZero();

		// The per-scan limit, enforced by the database.
		String sha = this.jdbcTemplate.queryForObject("SELECT definition_sha256 FROM policy.policy_versions WHERE id = ?",
				String.class, version);
		for (int i = 0; i < PolicyReevaluationService.MAX_PER_SCAN; i++) {
			this.jdbcTemplate.update("""
					INSERT INTO policy.historical_evaluations (scan_id, project_id, organization_id, policy_version_id,
					    policy_sha256, engine_version, decision, violation_count, incomplete_count, reasons, reasons_sha256,
					    inputs_sha256, evaluated_as_of, requested_by)
					VALUES (?, ?, ?, ?, ?, 'test-engine', 'PASS', 0, 0, '[]', encode(sha256('[]'::bytea), 'hex'),
					    encode(sha256(gen_random_uuid()::text::bytea), 'hex'), now(), 'user:' || gen_random_uuid())""",
					scanId, this.projectId, this.organizationId, version, sha);
		}
		MvcResult limit = reevaluate(scanId, version, null);
		assertThat(limit.getResponse().getStatus()).isEqualTo(409);
		assertThat(json(limit).get("code").asString()).isEqualTo("reevaluation-limit-reached");
		assertThat(historicalCount(scanId)).isEqualTo(PolicyReevaluationService.MAX_PER_SCAN);
	}

	// --- Authorization and tenant isolation ---------------------------------------------

	@Test
	void ownersAndAdminsMayRequestViewersAndMembersMayNotAndOutsidersSeeNothing() throws Exception {
		UUID version = activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(0);
		UUID lax = createPolicy(this.organizationId, gitleaks("lax", 1));
		String admin = uniqueSubject("admin");
		String member = uniqueSubject("member");
		String viewer = uniqueSubject("viewer");
		grant(this.organizationId, admin, "ADMIN");
		grant(this.organizationId, member, "MEMBER");
		grant(this.organizationId, viewer, "VIEWER");

		assertThat(reevaluate(scanId, version, TestJwts.bearer(viewer)).getResponse().getStatus()).isEqualTo(403);
		assertThat(reevaluate(scanId, version, TestJwts.bearer(member)).getResponse().getStatus()).isEqualTo(403);
		assertThat(reevaluate(scanId, version, TestJwts.bearer(uniqueSubject("outsider"))).getResponse().getStatus())
			.isEqualTo(404);
		assertThat(historicalCount(scanId)).isZero();

		MvcResult byAdmin = reevaluate(scanId, version, TestJwts.bearer(admin));
		assertThat(byAdmin.getResponse().getStatus()).isEqualTo(201);
		MvcResult byOwner = reevaluate(scanId, lax, null);
		assertThat(byOwner.getResponse().getStatus()).isEqualTo(201);
		// The audited requester is the internal identity, never the token subject.
		UUID adminIdentity = this.jdbcTemplate.queryForObject("SELECT id FROM user_identities WHERE subject = ?",
				UUID.class, admin);
		assertThat(json(byAdmin).get("initiatedBy").asString()).isEqualTo("user:" + adminIdentity);
		assertThat(json(byAdmin).toString()).doesNotContain(admin);

		// Viewers read the history; outsiders get 404 for the list and each record.
		String recordPath = "/api/v1/scans/{id}/evaluations/{e}";
		for (String path : List.of("/api/v1/scans/{id}/evaluations", recordPath)) {
			assertThat(this.mockMvc
				.perform(get(path, scanId, json(byAdmin).get("id").asString()).header(HttpHeaders.AUTHORIZATION,
						TestJwts.bearer(viewer)))
				.andReturn()
				.getResponse()
				.getStatus()).as(path).isEqualTo(200);
			assertThat(this.mockMvc
				.perform(get(path, scanId, json(byAdmin).get("id").asString()).header(HttpHeaders.AUTHORIZATION,
						TestJwts.bearer(uniqueSubject("outsider"))))
				.andReturn()
				.getResponse()
				.getStatus()).as(path).isEqualTo(404);
		}
	}

	@Test
	void crossTenantScansPoliciesAndRecordsAreRejectedAsNotFound() throws Exception {
		UUID version = activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(1);
		// Another tenant with its own policy version and its own OWNER.
		String otherOwner = uniqueSubject("other-owner");
		UUID otherOrganization = createOrganization();
		grant(otherOrganization, otherOwner, "OWNER");
		UUID foreignVersion = createPolicy(otherOrganization, gitleaks("secrets", 9));

		// A forged policy reference: a version of another organization is not found.
		MvcResult forgedPolicy = reevaluate(scanId, foreignVersion, null);
		assertThat(forgedPolicy.getResponse().getStatus()).isEqualTo(404);
		assertThat(json(forgedPolicy).get("detail").asString()).isEqualTo("PolicyVersion was not found.");
		// A forged scan reference: the other tenant's owner, with its own policy version.
		assertThat(reevaluate(scanId, foreignVersion, TestJwts.bearer(otherOwner)).getResponse().getStatus())
			.isEqualTo(404);
		assertThat(reevaluate(scanId, version, TestJwts.bearer(otherOwner)).getResponse().getStatus()).isEqualTo(404);
		assertThat(historicalCount(scanId)).isZero();

		// A record of another scan is not readable through this scan.
		JsonNode record = recorded(scanId, version);
		UUID otherScan = completedGitleaksScan(0);
		assertThat(this.mockMvc
			.perform(get("/api/v1/scans/{id}/evaluations/{e}", otherScan, record.get("id").asString()))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(404);

		// Even through the API's database login, the function refuses a foreign version.
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		Map<String, Object> context = api.queryForMap("SELECT * FROM policy.historical_context(?)", scanId);
		String foreignSha = this.jdbcTemplate.queryForObject(
				"SELECT definition_sha256 FROM policy.policy_versions WHERE id = ?", String.class, foreignVersion);
		assertThat(api.queryForMap("SELECT * FROM policy.record_historical_evaluation(?, ?, ?, ?, 'INCOMPLETE', ?, '[]', ?,"
				+ " ?, ?)", scanId, foreignVersion, foreignSha, PolicyEvaluator.ENGINE_VERSION,
				"[{\"code\":\"EVALUATION_ERROR\",\"effect\":\"INCOMPLETE\",\"limit\":null,\"observed\":null,"
						+ "\"scanner\":null,\"subject\":null}]",
				context.get("evaluated_as_of"), context.get("inputs_sha256"), "user:" + UUID.randomUUID()))
			.containsEntry("outcome", "POLICY_VERSION_NOT_FOUND");
		// And composite keys refuse a cross-tenant row even for a superuser.
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.historical_evaluations (scan_id, project_id, organization_id, policy_version_id,
				    policy_sha256, engine_version, decision, violation_count, incomplete_count, reasons, reasons_sha256,
				    inputs_sha256, evaluated_as_of, requested_by)
				VALUES (?, ?, ?, ?, ?, 'x', 'PASS', 0, 0, '[]', encode(sha256('[]'::bytea), 'hex'), repeat('a', 64),
				    now(), 'user:' || gen_random_uuid())""", scanId, this.projectId, this.organizationId, foreignVersion,
				foreignSha))
			.hasMessageContaining("violates foreign key constraint");
	}

	// --- Idempotency, concurrency, immutability ------------------------------------------

	@Test
	void repeatedAndConcurrentIdenticalRequestsYieldExactlyOneRecord() throws Exception {
		activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(1);
		UUID version = createPolicy(this.organizationId, gitleaks("lax", 3));
		JsonNode first = recorded(scanId, version);

		MvcResult replay = reevaluate(scanId, version, null);
		assertThat(replay.getResponse().getStatus()).isEqualTo(200);
		assertThat(replay.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("true");
		assertThat(json(replay)).isEqualTo(first);

		UUID concurrent = createPolicy(this.organizationId, gitleaks("concurrent", 0));
		int requesters = 8;
		ExecutorService pool = Executors.newFixedThreadPool(requesters);
		CountDownLatch start = new CountDownLatch(1);
		List<PolicyReevaluationService.Result> results = new ArrayList<>();
		try {
			List<Future<PolicyReevaluationService.Result>> futures = new ArrayList<>();
			for (int i = 0; i < requesters; i++) {
				String actor = "user:" + UUID.randomUUID();
				Callable<PolicyReevaluationService.Result> task = () -> {
					start.await();
					return this.reevaluations.reevaluate(scanId, concurrent, actor);
				};
				futures.add(pool.submit(task));
			}
			start.countDown();
			for (Future<PolicyReevaluationService.Result> future : futures) {
				results.add(future.get());
			}
		}
		finally {
			pool.shutdownNow();
		}

		assertThat(results).extracting(PolicyReevaluationService.Result::outcome)
			.containsOnlyOnce(PolicyReevaluationService.Outcome.RECORDED);
		assertThat(new HashSet<>(results.stream().map(PolicyReevaluationService.Result::evaluationId).toList()))
			.hasSize(1);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.historical_evaluations WHERE scan_id = ? AND policy_version_id = ?",
				Integer.class, scanId, concurrent))
			.isEqualTo(1);
		assertThat(historicalCount(scanId)).isEqualTo(2);
	}

	@Test
	void historicalRecordsCannotBeChangedAndTheDatabaseRefusesForgedOnes() throws Exception {
		UUID version = activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(1);
		JsonNode record = recorded(scanId, version);
		UUID id = UUID.fromString(record.get("id").asString());
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		for (String sql : List.of("UPDATE policy.historical_evaluations SET decision = 'PASS' WHERE id = ?",
				"DELETE FROM policy.historical_evaluations WHERE id = ?",
				"DELETE FROM policy.historical_evaluation_evidence WHERE evaluation_id = ?")) {
			assertThatThrownBy(() -> api.update(sql, id)).as(sql).hasStackTraceContaining("permission denied");
			assertThatThrownBy(() -> this.jdbcTemplate.update(sql, id)).as("superuser: " + sql)
				.hasStackTraceContaining("policy records are immutable");
		}

		Map<String, Object> context = api.queryForMap("SELECT * FROM policy.historical_context(?)", scanId);
		Object asOf = context.get("evaluated_as_of");
		String inputs = (String) context.get("inputs_sha256");
		String sha = this.jdbcTemplate.queryForObject("SELECT definition_sha256 FROM policy.policy_versions WHERE id = ?",
				String.class, version);
		String evidence = this.jdbcTemplate.queryForObject("""
				SELECT json_agg(json_build_object('job_id', job_id, 'lease_epoch', lease_epoch, 'name', name,
				    'result_sha256', result_sha256, 'scanner_type', scanner_type, 'sha256', sha256))::text
				FROM policy.historical_evaluation_evidence WHERE evaluation_id = ?""", String.class, id);
		String violation = "[{\"code\":\"BLOCKING_FINDINGS_EXCEEDED\",\"effect\":\"VIOLATION\",\"limit\":0,"
				+ "\"observed\":1,\"scanner\":\"GITLEAKS\",\"subject\":null}]";
		String actor = "user:" + UUID.randomUUID();
		String call = "SELECT * FROM policy.record_historical_evaluation(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
		Map<String, Object[]> forgeries = Map.of(
				"PASS_NOT_JUSTIFIED", new Object[] { sha, "PASS", "[]", "[]", asOf, inputs, actor },
				"DECISION_INCONSISTENT", new Object[] { sha, "INCOMPLETE", violation, evidence, asOf, inputs, actor },
				"POLICY_MISMATCH", new Object[] { "b".repeat(64), "FAIL", violation, evidence, asOf, inputs, actor },
				"VIOLATION_WITHOUT_EVIDENCE", new Object[] { sha, "FAIL", violation, "[]", asOf, inputs, actor },
				"INPUTS_CHANGED", new Object[] { sha, "FAIL", violation, evidence, asOf, "c".repeat(64), actor },
				"INVALID_ARGUMENTS", new Object[] { sha, "FAIL", violation, evidence, asOf, inputs, "admin@example" });
		for (Map.Entry<String, Object[]> forgery : forgeries.entrySet()) {
			Object[] a = forgery.getValue();
			assertThatThrownBy(() -> api.queryForMap(call, scanId, version, a[0], PolicyEvaluator.ENGINE_VERSION, a[1],
					a[2], a[3], a[4], a[5], a[6]))
				.as(forgery.getKey())
				.hasMessageContaining("evaluation rejected: " + forgery.getKey());
		}
		assertThatThrownBy(() -> api.queryForMap(call, scanId, version, sha, PolicyEvaluator.ENGINE_VERSION, "FAIL",
				violation, evidence, java.sql.Timestamp.from(java.time.Instant.now()), inputs, actor))
			.hasMessageContaining("evaluation rejected: AS_OF_MISMATCH");
		// The same identity with another result is refused: a persisted decision never changes.
		String twoViolations = violation.replace("\"observed\":1", "\"observed\":2");
		assertThatThrownBy(() -> api.queryForMap(call, scanId, version, sha, PolicyEvaluator.ENGINE_VERSION, "FAIL",
				twoViolations, evidence, asOf, inputs, actor))
			.hasMessageContaining("evaluation rejected: NONDETERMINISTIC");
		assertThat(historicalCount(scanId)).isEqualTo(1);
		// Another engine version is another identity: a distinct record, the first unchanged.
		assertThat(api.queryForMap(call, scanId, version, sha, "sentinelpipe-policy/9.9.9", "FAIL", violation, evidence,
				asOf, inputs, actor))
			.containsEntry("outcome", "RECORDED");
		assertThat(this.jdbcTemplate.queryForList(
				"SELECT engine_version FROM policy.historical_evaluations WHERE scan_id = ? ORDER BY recorded_at, id",
				String.class, scanId))
			.containsExactlyInAnyOrder(PolicyEvaluator.ENGINE_VERSION, "sentinelpipe-policy/9.9.9");
		assertThat(getJson("/api/v1/scans/{id}/evaluations/{e}", scanId, id)).isEqualTo(record);
	}

	// --- History --------------------------------------------------------------------------

	@Test
	void theHistoryListsTheOriginalFirstThenReEvaluationsInStableBoundedPages() throws Exception {
		activate(createPolicy(this.organizationId, gitleaks("secrets", 0)));
		UUID scanId = completedGitleaksScan(1);
		JsonNode original = getJson("/api/v1/scans/{id}/evaluation", scanId);
		List<String> recordedIds = new ArrayList<>();
		for (int allowed = 1; allowed <= 4; allowed++) {
			recordedIds.add(recorded(scanId, createPolicy(this.organizationId, gitleaks("v", allowed))).get("id")
				.asString());
		}

		List<String> pagedIds = new ArrayList<>();
		for (int page = 0; page < 3; page++) {
			JsonNode body = history(scanId, page, 2);
			assertThat(body.at("/page/totalElements").asLong()).isEqualTo(5);
			assertThat(body.at("/page/totalPages").asInt()).isEqualTo(3);
			body.get("items").forEach((item) -> pagedIds.add(item.get("id").asString()));
		}
		JsonNode all = history(scanId, 0, 100);
		JsonNode first = all.at("/items/0");
		assertThat(first.get("evaluationType").asString()).isEqualTo("ORIGINAL");
		assertThat(first.get("gating").asBoolean()).isTrue();
		assertThat(first.get("initiatedBy").asString()).isEqualTo("supervisor");
		assertThat(first.get("inputsSha256").isNull()).isTrue();
		// The original record, written by V009, reads the same through the history.
		for (String field : List.of("id", "policyVersionId", "policySha256", "decision", "reasons", "evidence",
				"evaluatedAt", "recordedAt")) {
			assertThat(first.get(field)).as(field).isEqualTo(original.get(field));
		}
		List<String> expected = new ArrayList<>(List.of(original.get("id").asString()));
		expected.addAll(recordedIds);
		assertThat(pagedIds).containsExactlyElementsOf(expected);
		assertThat(history(scanId, 0, 100).get("items")).isEqualTo(all.get("items"));
		assertThat(history(scanId, 9, 2).get("items")).isEmpty();
		for (String query : List.of("size=101", "size=0", "page=-1", "page=10001")) {
			assertThat(this.mockMvc.perform(get("/api/v1/scans/{id}/evaluations?" + query, scanId))
				.andReturn()
				.getResponse()
				.getStatus()).as(query).isEqualTo(400);
		}
		// Raw evidence is never returned: digests and codes only.
		assertThat(all.toString()).doesNotContain("github-pat").doesNotContain("src/file");
	}

}

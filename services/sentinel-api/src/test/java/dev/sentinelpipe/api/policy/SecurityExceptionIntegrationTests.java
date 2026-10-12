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
import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import dev.sentinelpipe.api.policy.PolicyFixtures.Findings;
import dev.sentinelpipe.api.policy.PolicyFixtures.JobContext;
import dev.sentinelpipe.api.scan.ScanLifecycleService;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
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
 * Security exceptions with independent approval and the effective gate (ADR-0015), against
 * real PostgreSQL: scans completed through the worker protocol with synthetic evidence,
 * evaluated by the supervisor path, then excepted through the API. The database functions,
 * triggers and constraints are exercised directly as well, through the API's login and as
 * a superuser.
 */
class SecurityExceptionIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final String JUSTIFICATION = "Synthetic test credential, rotated; tracked in SEC-123.";

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private ExceptionRequestService exceptions;

	@Autowired
	private TestDatabaseAdmin admin;

	private WorkerProtocol worker;

	private UUID organizationId;

	private UUID projectId;

	/** ADMIN: may request, never decide. */
	private String requester;

	/** A second OWNER; the default caller (the platform admin) is the first. */
	private String approver;

	private String viewer;

	private String member;

	@BeforeEach
	void setUp() throws Exception {
		this.worker = WorkerProtocol.asWorker(this.admin);
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "excepted");
		this.requester = uniqueSubject("requester");
		this.approver = uniqueSubject("approver");
		this.viewer = uniqueSubject("viewer");
		this.member = uniqueSubject("member");
		grant(this.organizationId, this.requester, "ADMIN");
		grant(this.organizationId, this.approver, "OWNER");
		grant(this.organizationId, this.viewer, "VIEWER");
		grant(this.organizationId, this.member, "MEMBER");
	}

	// --- Helpers ------------------------------------------------------------------------

	private static String gitleaks(String name, int allowed) {
		return PolicyFixtures.gitleaksOnly(name)
			.replace("\"max_blocking_findings\": 0", "\"max_blocking_findings\": " + allowed);
	}

	private UUID createPolicy(UUID organization, String definition) throws Exception {
		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations/{id}/policies", organization).contentType(MediaType.APPLICATION_JSON)
				.content(definition))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
		return UUID.fromString(json(result).get("id").asString());
	}

	private UUID activate(String definition) throws Exception {
		UUID version = createPolicy(this.organizationId, definition);
		assertThat(this.mockMvc
			.perform(put("/api/v1/projects/{id}/policy", this.projectId).contentType(MediaType.APPLICATION_JSON)
				.content("{\"policyVersionId\": \"%s\"}".formatted(version)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
		return version;
	}

	private UUID scan(ScannerType... scanners) throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(this.projectId, randomSha(), null)).get("id").asString());
		for (ScannerType scanner : scanners) {
			this.lifecycle.planJob(scanId, scanner);
		}
		return scanId;
	}

	private void complete(UUID scanId, ScannerType scanner, Function<JobContext, byte[]> evidence) {
		Lease lease = this.worker.claim(scanId, scanner.name()).orElseThrow();
		assertThat(this.worker.completeWithEvidence(lease, "findings.json", evidence.apply(new JobContext(
				lease.organizationId(), lease.projectId(), lease.scanId(), lease.jobId(), lease.commitSha()))))
			.isEqualTo("ACCEPTED");
	}

	/** A Gitleaks scan with {@code secrets} detected secrets, completed and evaluated. */
	private UUID gitleaksScan(int secrets) throws Exception {
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, (c) -> {
			Findings findings = new Findings(PolicyScanner.GITLEAKS, c);
			for (int i = 0; i < secrets; i++) {
				findings.finding("x");
			}
			return findings.bytes();
		});
		assertThat(this.lifecycle.evaluate(scanId)).isTrue();
		return scanId;
	}

	private UUID jobOf(UUID scanId, ScannerType scanner) {
		return this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ? AND scanner_type = ?",
				UUID.class, scanId, scanner.name());
	}

	/** The fingerprint of the {@code index}-th synthetic finding of the scanner's job. */
	private String fingerprint(UUID scanId, ScannerType scanner, int index) {
		return EvidenceVerifier
			.sha256((jobOf(scanId, scanner) + "/" + index).getBytes(StandardCharsets.UTF_8));
	}

	private String identity(String subject) {
		return "user:" + this.jdbcTemplate.queryForObject("SELECT id FROM user_identities WHERE subject = ?",
				UUID.class, subject);
	}

	private String ownerIdentity() {
		return identity(TestJwts.PLATFORM_ADMIN);
	}

	private static String body(ScannerType scanner, String fingerprint, Instant expiresAt) {
		return """
				{"scanner": "%s", "findingFingerprint": "%s", "justification": "%s", "expiresAt": "%s"}
				""".formatted(scanner, fingerprint, JUSTIFICATION, expiresAt);
	}

	private MvcResult send(String path, String body, String subject, Object... variables) throws Exception {
		var request = post(path, variables).contentType(MediaType.APPLICATION_JSON).content(body);
		if (subject != null) {
			request.header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(subject));
		}
		return this.mockMvc.perform(request).andReturn();
	}

	private MvcResult requestException(UUID scanId, ScannerType scanner, String fingerprint, String subject)
			throws Exception {
		return send("/api/v1/scans/{id}/exceptions", body(scanner, fingerprint, Instant.now().plus(Duration.ofDays(1))),
				subject, scanId);
	}

	/** Requested by the ADMIN requester; returns the new request. */
	private JsonNode requested(UUID scanId, ScannerType scanner, String fingerprint) throws Exception {
		MvcResult result = requestException(scanId, scanner, fingerprint, this.requester);
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
		JsonNode body = json(result);
		ContractSchemas.assertValid("security-exception.schema.json", body);
		assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION))
			.isEqualTo("/api/v1/scans/" + scanId + "/exceptions/" + body.get("id").asString());
		return body;
	}

	private MvcResult act(UUID scanId, JsonNode exception, String action, String subject) throws Exception {
		return send("/api/v1/scans/{id}/exceptions/{e}/" + action, "{\"rationale\": \"Reviewed: %s.\"}".formatted(action),
				subject, scanId, exception.get("id").asString());
	}

	/** Approved by the default OWNER, who did not request it. */
	private JsonNode approved(UUID scanId, JsonNode exception) throws Exception {
		MvcResult result = act(scanId, exception, "approve", null);
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		JsonNode body = json(result);
		ContractSchemas.assertValid("security-exception.schema.json", body);
		return body;
	}

	private JsonNode getJson(String path, Object... variables) throws Exception {
		MvcResult result = this.mockMvc.perform(get(path, variables)).andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return json(result);
	}

	private JsonNode gate(UUID scanId) throws Exception {
		MvcResult result = this.mockMvc.perform(get("/api/v1/scans/{id}/gate", scanId)).andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		assertThat(result.getResponse().getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
		JsonNode body = json(result);
		ContractSchemas.assertValid("effective-gate.schema.json", body);
		return body;
	}

	private static List<String> gateReasons(JsonNode gate) {
		List<String> codes = new ArrayList<>();
		gate.get("reasons")
			.forEach((reason) -> codes.add(reason.get("code").asString() + ":" + reason.get("scanner").asString("") + ":"
					+ reason.get("observed").asString("")));
		return codes;
	}

	private String code(MvcResult result) throws Exception {
		return this.jsonMapper.readTree(result.getResponse().getContentAsString()).path("code").asString("");
	}

	/**
	 * Runs a superuser INSERT with the request trigger disabled, to show that the declarative
	 * keys refuse it on their own. Always rolled back: the block ends with an error.
	 */
	private void assertRefusedWithoutTrigger(String insert, String expected) {
		assertThatThrownBy(() -> this.jdbcTemplate.execute("""
				DO $$ BEGIN
				  ALTER TABLE policy.exception_requests DISABLE TRIGGER tr_exception_requests_check;
				  %s;
				  RAISE EXCEPTION 'inserted without refusal';
				END $$""".formatted(insert)))
			.hasMessageContaining(expected);
		assertThat(this.jdbcTemplate.queryForObject("""
				SELECT tgenabled FROM pg_trigger WHERE tgname = 'tr_exception_requests_check'""", String.class))
			.isEqualTo("O");
	}

	/**
	 * Moves the request's timestamps {@code amount} into the past, as if that much time had
	 * passed. Superuser fixture: triggers are bypassed only for this rewrite.
	 */
	private void travel(UUID exceptionId, Duration amount) {
		String interval = "'" + amount.getSeconds() + " seconds'";
		this.jdbcTemplate.execute("""
				DO $$ BEGIN
				  SET LOCAL session_replication_role = replica;
				  UPDATE policy.exception_requests SET requested_at = requested_at - interval %1$s,
				         expires_at = expires_at - interval %1$s WHERE id = '%2$s';
				  UPDATE policy.exception_transitions SET occurred_at = occurred_at - interval %1$s,
				         expires_at = expires_at - interval %1$s WHERE request_id = '%2$s';
				END $$""".formatted(interval, exceptionId));
	}

	private static UUID id(JsonNode exception) {
		return UUID.fromString(exception.get("id").asString());
	}

	/** Everything exception operations must leave untouched, as stored. */
	private List<Object> untouchedState(UUID scanId) {
		List<Object> state = new ArrayList<>();
		state.add(this.jdbcTemplate.queryForMap("SELECT * FROM scans WHERE id = ?", scanId));
		state.add(this.jdbcTemplate.queryForList("SELECT * FROM scan_jobs WHERE scan_id = ? ORDER BY id", scanId));
		state.add(this.jdbcTemplate.queryForList("SELECT * FROM policy.scan_policies WHERE scan_id = ?", scanId));
		state.add(this.jdbcTemplate.queryForList("SELECT * FROM policy.evaluations WHERE scan_id = ?", scanId));
		state.add(this.jdbcTemplate.queryForList(
				"SELECT * FROM policy.evaluation_evidence WHERE scan_id = ? ORDER BY job_id", scanId));
		state.add(this.jdbcTemplate.queryForList(
				"SELECT * FROM policy.historical_evaluations WHERE scan_id = ? ORDER BY id", scanId));
		state.add(this.jdbcTemplate.queryForList(
				"SELECT * FROM lifecycle.execution_events WHERE scan_id = ? ORDER BY 1", scanId));
		state.add(this.jdbcTemplate.queryForList("""
				SELECT o.sha256, encode(sha256(o.content), 'hex') AS content_sha256, o.purged_at
				FROM evidence.objects o JOIN evidence.job_artifacts u
				  ON u.organization_id = o.organization_id AND u.sha256 = o.sha256
				JOIN scan_jobs j ON j.id = u.job_id WHERE j.scan_id = ? ORDER BY 1""", scanId));
		state.add(this.jdbcTemplate.queryForObject("SELECT count(*) FROM outbox_events", Long.class));
		state.add(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans", Long.class));
		state.add(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scan_jobs", Long.class));
		return state;
	}

	// --- Independent approval -------------------------------------------------------------

	@Test
	void anIndependentOwnerApprovesAndTheEffectiveGateIsRiskAcceptedNeverPass() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		JsonNode originalEvaluation = getJson("/api/v1/scans/{id}/evaluation", scanId);
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");
		List<Object> before = untouchedState(scanId);

		JsonNode request = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0));
		assertThat(request.get("state").asString()).isEqualTo("REQUESTED");
		assertThat(request.get("status").asString()).isEqualTo("REQUESTED");
		// The binding is derived by the server from the original evaluation and its evidence.
		assertThat(request.get("evaluationId")).isEqualTo(originalEvaluation.get("id"));
		assertThat(request.get("policyVersionId")).isEqualTo(originalEvaluation.get("policyVersionId"));
		assertThat(request.get("policySha256")).isEqualTo(originalEvaluation.get("policySha256"));
		assertThat(request.get("artifactSha256")).isEqualTo(originalEvaluation.at("/evidence/0/sha256"));
		assertThat(request.get("resultSha256")).isEqualTo(originalEvaluation.at("/evidence/0/resultSha256"));
		assertThat(request.at("/finding/ruleId").asString()).isEqualTo("github-pat");
		assertThat(request.at("/finding/category").asString()).isEqualTo("SECRET");
		assertThat(request.get("requestedBy").asString()).isEqualTo(identity(this.requester));
		// A request alone changes nothing.
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");

		JsonNode approved = approved(scanId, request);

		assertThat(approved.get("state").asString()).isEqualTo("APPROVED");
		assertThat(approved.get("status").asString()).isEqualTo("ACTIVE");
		assertThat(approved.get("transitions")).hasSize(2);
		assertThat(approved.at("/transitions/1/actor").asString()).isEqualTo(ownerIdentity());
		assertThat(approved.at("/transitions/1/actorRole").asString()).isEqualTo("OWNER");
		assertThat(approved.at("/transitions/1/fromState").asString()).isEqualTo("REQUESTED");
		JsonNode gate = gate(scanId);
		assertThat(gate.get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
		assertThat(gate.get("exceptionBased").asBoolean()).isTrue();
		assertThat(gate.get("originalDecision").asString()).isEqualTo("FAIL");
		assertThat(gateReasons(gate)).containsExactly("VIOLATION_EXCEPTED:GITLEAKS:1");
		assertThat(gate.at("/appliedExceptions/0/id")).isEqualTo(request.get("id"));
		assertThat(gate.get("validUntil")).isEqualTo(request.get("expiresAt"));

		// The original decision, evaluation, evidence and jobs are unchanged; nothing was
		// published and no scanner job was created.
		assertThat(untouchedState(scanId)).isEqualTo(before);
		assertThat(getJson("/api/v1/scans/{id}", scanId).get("securityDecision").asString()).isEqualTo("FAIL");
		assertThat(getJson("/api/v1/scans/{id}/evaluation", scanId)).isEqualTo(originalEvaluation);
	}

	@Test
	void nobodyApprovesOrRejectsTheirOwnRequestWhateverTheirRole() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(2);
		// An OWNER's own request.
		MvcResult ownerRequest = requestException(scanId, ScannerType.GITLEAKS,
				fingerprint(scanId, ScannerType.GITLEAKS, 0), null);
		assertThat(ownerRequest.getResponse().getStatus()).isEqualTo(201);
		JsonNode own = json(ownerRequest);
		for (String action : List.of("approve", "reject")) {
			MvcResult self = act(scanId, own, action, null);
			assertThat(self.getResponse().getStatus()).as(action).isEqualTo(403);
			assertThat(code(self)).isEqualTo("self-decision-forbidden");
		}
		// The ADMIN requester cannot decide at all (role), not even on someone else's request.
		JsonNode adminRequest = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 1));
		MvcResult adminApproves = act(scanId, adminRequest, "approve", this.requester);
		assertThat(adminApproves.getResponse().getStatus()).isEqualTo(403);
		assertThat(code(adminApproves)).isEqualTo("insufficient-role");
		assertThat(act(scanId, own, "approve", this.requester).getResponse().getStatus()).isEqualTo(403);

		// The database refuses the same, for the API's own login.
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		assertThat(api.queryForObject("SELECT policy.transition_exception(?, 'APPROVED', ?, 'self')", String.class,
				id(own), ownerIdentity()))
			.isEqualTo("SELF_DECISION");
		assertThat(api.queryForObject("SELECT policy.transition_exception(?, 'APPROVED', ?, 'admin')", String.class,
				id(own), identity(this.requester)))
			.isEqualTo("NOT_AUTHORIZED");
		assertThat(json(this.mockMvc.perform(get("/api/v1/scans/{id}/exceptions/{e}", scanId, id(own))).andReturn())
			.get("state")
			.asString()).isEqualTo("REQUESTED");

		// An independent OWNER can approve both.
		assertThat(act(scanId, own, "approve", this.approver).getResponse().getStatus()).isEqualTo(200);
		assertThat(act(scanId, adminRequest, "approve", this.approver).getResponse().getStatus()).isEqualTo(200);
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
	}

	@Test
	void viewersAndMembersCannotRequestOrDecideAndOutsidersSeeNothing() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		String fingerprint = fingerprint(scanId, ScannerType.GITLEAKS, 0);
		assertThat(requestException(scanId, ScannerType.GITLEAKS, fingerprint, this.viewer).getResponse().getStatus())
			.isEqualTo(403);
		assertThat(requestException(scanId, ScannerType.GITLEAKS, fingerprint, this.member).getResponse().getStatus())
			.isEqualTo(403);
		String outsider = uniqueSubject("outsider");
		assertThat(requestException(scanId, ScannerType.GITLEAKS, fingerprint, outsider).getResponse().getStatus())
			.isEqualTo(404);
		JsonNode request = requested(scanId, ScannerType.GITLEAKS, fingerprint);

		for (String action : List.of("approve", "reject", "revoke")) {
			assertThat(act(scanId, request, action, this.viewer).getResponse().getStatus()).as(action).isEqualTo(403);
			assertThat(act(scanId, request, action, this.member).getResponse().getStatus()).as(action).isEqualTo(403);
			assertThat(act(scanId, request, action, outsider).getResponse().getStatus()).as(action).isEqualTo(404);
		}
		// Viewers read requests, history and the gate; outsiders get 404 for each.
		for (String path : List.of("/api/v1/scans/{id}/exceptions", "/api/v1/scans/{id}/exceptions/{e}",
				"/api/v1/scans/{id}/gate")) {
			assertThat(this.mockMvc
				.perform(get(path, scanId, request.get("id").asString()).header(HttpHeaders.AUTHORIZATION,
						TestJwts.bearer(this.viewer)))
				.andReturn()
				.getResponse()
				.getStatus()).as(path).isEqualTo(200);
			assertThat(this.mockMvc
				.perform(get(path, scanId, request.get("id").asString()).header(HttpHeaders.AUTHORIZATION,
						TestJwts.bearer(outsider)))
				.andReturn()
				.getResponse()
				.getStatus()).as(path).isEqualTo(404);
		}
		assertThat(json(this.mockMvc.perform(get("/api/v1/scans/{id}/exceptions/{e}", scanId, id(request))).andReturn())
			.get("transitions")).hasSize(1);
	}

	@Test
	void identitiesAreServerDerivedAndCannotBeSpoofed() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		String fingerprint = fingerprint(scanId, ScannerType.GITLEAKS, 0);
		String forged = "user:" + UUID.randomUUID();
		for (String extra : List.of("\"requestedBy\": \"%s\"".formatted(forged), "\"actor\": \"%s\"".formatted(forged),
				"\"status\": \"APPROVED\"", "\"evaluationId\": \"%s\"".formatted(UUID.randomUUID()),
				"\"ruleId\": \"github-pat\"")) {
			String body = body(ScannerType.GITLEAKS, fingerprint, Instant.now().plus(Duration.ofDays(1)))
				.replaceFirst("\\{", "{" + extra + ", ");
			assertThat(send("/api/v1/scans/{id}/exceptions", body, this.requester, scanId).getResponse().getStatus())
				.as(extra)
				.isEqualTo(400);
		}
		JsonNode request = requested(scanId, ScannerType.GITLEAKS, fingerprint);
		for (String extra : List.of("\"approvedBy\": \"%s\"".formatted(forged), "\"actor\": \"%s\"".formatted(forged))) {
			assertThat(send("/api/v1/scans/{id}/exceptions/{e}/approve", "{\"rationale\": \"ok\", %s}".formatted(extra),
					null, scanId, id(request))
				.getResponse()
				.getStatus()).as(extra).isEqualTo(400);
		}
		// The recorded identities are the callers' internal identities, never token subjects.
		JsonNode approved = approved(scanId, request);
		assertThat(approved.get("requestedBy").asString()).isEqualTo(identity(this.requester));
		assertThat(approved.at("/transitions/0/actor").asString()).isEqualTo(identity(this.requester));
		assertThat(approved.at("/transitions/1/actor").asString()).isEqualTo(ownerIdentity());
		assertThat(approved.toString()).doesNotContain(this.requester).doesNotContain(TestJwts.PLATFORM_ADMIN);
		// A token for an unknown identity has no membership: nothing is recorded for it.
		assertThat(act(scanId, request, "revoke", uniqueSubject("ghost")).getResponse().getStatus()).isEqualTo(404);
	}

	@Test
	void concurrentDecisionsProduceExactlyOneTransition() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		UUID exceptionId = id(requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));
		List<Callable<String>> tasks = new ArrayList<>();
		CountDownLatch start = new CountDownLatch(1);
		for (int i = 0; i < 4; i++) {
			String actor = (i % 2 == 0) ? ownerIdentity() : identity(this.approver);
			ExceptionRequestService.Action action = (i < 3) ? ExceptionRequestService.Action.APPROVE
					: ExceptionRequestService.Action.REJECT;
			tasks.add(() -> {
				start.await();
				try {
					this.exceptions.transition(scanId, exceptionId, action, actor, "concurrent " + action);
					return "OK:" + action;
				}
				catch (ConflictException ex) {
					return ex.getCode();
				}
			});
		}
		ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
		List<String> outcomes = new ArrayList<>();
		try {
			List<Future<String>> futures = new ArrayList<>();
			tasks.forEach((task) -> futures.add(pool.submit(task)));
			start.countDown();
			for (Future<String> future : futures) {
				try {
					outcomes.add(future.get());
				}
				catch (ExecutionException ex) {
					throw new AssertionError(ex.getCause());
				}
			}
		}
		finally {
			pool.shutdownNow();
		}

		assertThat(outcomes.stream().filter((o) -> o.startsWith("OK:")).count()).as(outcomes.toString()).isEqualTo(1);
		assertThat(outcomes.stream().filter((o) -> !o.startsWith("OK:")))
			.allMatch(ExceptionRequestService.INVALID_TRANSITION::equals);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.exception_transitions WHERE request_id = ? AND seq = 1", Integer.class,
				exceptionId))
			.isEqualTo(1);
	}

	// --- Scope -----------------------------------------------------------------------------

	@Test
	void forgedOrNonBlockingFingerprintsAreRejectedByTheApiAndTheDatabase() throws Exception {
		activate(PolicyFixtures.allScanners("all"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		complete(scanId, ScannerType.GITLEAKS, (c) -> new Findings(PolicyScanner.GITLEAKS, c).bytes());
		// Semgrep: one blocking ERROR and one non-blocking INFO finding.
		complete(scanId, ScannerType.SEMGREP,
				(c) -> new Findings(PolicyScanner.SEMGREP, c).finding("ERROR").finding("INFO").bytes());
		complete(scanId, ScannerType.TRIVY, (c) -> new Findings(PolicyScanner.TRIVY, c).bytes());
		this.lifecycle.evaluate(scanId);
		UUID otherScan = gitleaksScanUnderCurrentPolicy();

		Map<String, Object[]> forgeries = Map.of("random", new Object[] { ScannerType.SEMGREP, "e".repeat(64) },
				"non-blocking INFO", new Object[] { ScannerType.SEMGREP, fingerprint(scanId, ScannerType.SEMGREP, 1) },
				"scanner without violation", new Object[] { ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.SEMGREP, 0) },
				"other scan's finding", new Object[] { ScannerType.GITLEAKS, fingerprint(otherScan, ScannerType.GITLEAKS, 0) },
				"other scanner type", new Object[] { ScannerType.FIXTURE, fingerprint(scanId, ScannerType.SEMGREP, 0) });
		for (Map.Entry<String, Object[]> forgery : forgeries.entrySet()) {
			MvcResult result = requestException(scanId, (ScannerType) forgery.getValue()[0],
					(String) forgery.getValue()[1], this.requester);
			assertThat(result.getResponse().getStatus()).as(forgery.getKey()).isEqualTo(409);
			assertThat(code(result)).as(forgery.getKey()).isEqualTo("finding-not-exceptionable");
		}
		// The database derives and verifies the target itself, even for the API's login.
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		assertThat(api.queryForMap("SELECT * FROM policy.request_exception(?, 'SEMGREP', ?, ?, now() + interval '1 day', ?)",
				scanId, fingerprint(scanId, ScannerType.SEMGREP, 1), JUSTIFICATION, identity(this.requester)))
			.containsEntry("outcome", "FINDING_NOT_ELIGIBLE");
		assertThat(api.queryForMap("SELECT * FROM policy.request_exception(?, 'SEMGREP', ?, ?, now() + interval '1 day', ?)",
				scanId, "f".repeat(64), JUSTIFICATION, identity(this.requester)))
			.containsEntry("outcome", "FINDING_NOT_ELIGIBLE");
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.exception_requests WHERE scan_id = ?",
				Integer.class, scanId))
			.isZero();

		// The real blocking finding is accepted, with the values the database found.
		JsonNode request = requested(scanId, ScannerType.SEMGREP, fingerprint(scanId, ScannerType.SEMGREP, 0));
		assertThat(request.at("/finding/scannerSeverity").asString()).isEqualTo("ERROR");
		assertThat(request.at("/finding/category").asString()).isEqualTo("CODE_PATTERN");
		// A superuser cannot insert a request whose finding values differ from the evidence.
		for (String change : List.of("finding_rule_id = 'other-rule'", "finding_scanner_severity = 'WARNING'",
				"finding_fingerprint = repeat('e', 64)")) {
			assertThatThrownBy(() -> this.jdbcTemplate.update(copyRequest(change), id(request)))
				.as(change)
				.hasMessageContaining("exception rejected: FINDING_NOT_VERIFIED");
		}
	}

	/** A Gitleaks-only scan of the same project under its current (all-scanner) policy. */
	private UUID gitleaksScanUnderCurrentPolicy() throws Exception {
		UUID scanId = scan(ScannerType.GITLEAKS);
		complete(scanId, ScannerType.GITLEAKS, (c) -> new Findings(PolicyScanner.GITLEAKS, c).finding("x").bytes());
		this.lifecycle.evaluate(scanId);
		return scanId;
	}

	/** A superuser INSERT copying request {@code ?} with one column changed. */
	private static String copyRequest(String change) {
		String columns = "organization_id, project_id, scan_id, evaluation_id, policy_version_id, policy_sha256,"
				+ " engine_version, job_id, scanner_type, lease_epoch, artifact_name, artifact_sha256, result_sha256,"
				+ " finding_fingerprint, finding_rule_id, finding_category, finding_scanner_severity, justification,"
				+ " requested_by, expires_at";
		String column = change.substring(0, change.indexOf('=')).trim();
		String value = change.substring(change.indexOf('=') + 1).trim();
		String select = columns.replace(column, value + " AS " + column);
		return "INSERT INTO policy.exception_requests (" + columns + ") SELECT " + select
				+ " FROM policy.exception_requests WHERE id = ?";
	}

	@Test
	void oneExceptionNeverHidesAnotherViolation() throws Exception {
		activate(PolicyFixtures.allScanners("all"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY);
		complete(scanId, ScannerType.GITLEAKS, (c) -> new Findings(PolicyScanner.GITLEAKS, c).finding("x").finding("x")
			.bytes());
		complete(scanId, ScannerType.SEMGREP, (c) -> new Findings(PolicyScanner.SEMGREP, c).finding("WARNING").bytes());
		complete(scanId, ScannerType.TRIVY, (c) -> new Findings(PolicyScanner.TRIVY, c).bytes());
		this.lifecycle.evaluate(scanId);

		approved(scanId, requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));
		JsonNode partial = gate(scanId);
		assertThat(partial.get("effectiveDecision").asString()).isEqualTo("FAIL");
		assertThat(partial.get("exceptionBased").asBoolean()).isFalse();
		// One of two secrets remains; Semgrep's violation is untouched.
		assertThat(gateReasons(partial)).containsExactlyInAnyOrder("VIOLATION_NOT_EXCEPTED:GITLEAKS:1",
				"VIOLATION_NOT_EXCEPTED:SEMGREP:1");

		approved(scanId, requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 1)));
		assertThat(gateReasons(gate(scanId))).containsExactlyInAnyOrder("VIOLATION_EXCEPTED:GITLEAKS:2",
				"VIOLATION_NOT_EXCEPTED:SEMGREP:1");
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");

		approved(scanId, requested(scanId, ScannerType.SEMGREP, fingerprint(scanId, ScannerType.SEMGREP, 0)));
		JsonNode covered = gate(scanId);
		assertThat(covered.get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
		assertThat(covered.get("appliedExceptions")).hasSize(3);
	}

	@Test
	void duplicateRequestsNeverBypassApprovalAndARejectedRequestStaysRejected() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		String fingerprint = fingerprint(scanId, ScannerType.GITLEAKS, 0);
		JsonNode first = requested(scanId, ScannerType.GITLEAKS, fingerprint);
		MvcResult duplicate = requestException(scanId, ScannerType.GITLEAKS, fingerprint, null);
		assertThat(duplicate.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(duplicate)).isEqualTo("exception-request-exists");

		MvcResult rejected = act(scanId, first, "reject", null);
		assertThat(rejected.getResponse().getStatus()).isEqualTo(200);
		assertThat(json(rejected).get("status").asString()).isEqualTo("REJECTED");
		for (String action : List.of("approve", "reject", "withdraw", "revoke")) {
			MvcResult again = act(scanId, first, action, action.equals("withdraw") ? this.requester : this.approver);
			assertThat(again.getResponse().getStatus()).as(action).isEqualTo(409);
			assertThat(code(again)).isEqualTo("invalid-exception-transition");
		}
		// A new request after a rejection starts over and needs its own approval.
		JsonNode second = requested(scanId, ScannerType.GITLEAKS, fingerprint);
		assertThat(second.get("status").asString()).isEqualTo("REQUESTED");
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");

		// The database refuses a second way out of REQUESTED, and leaving a state never entered.
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at,
				    actor, actor_role, rationale)
				SELECT id, 1, 'REQUESTED', 'APPROVED', requested_by, expires_at, ?, 'OWNER', 'second decision'
				FROM policy.exception_requests WHERE id = ?""", identity(this.approver), id(first)))
			.hasMessageContaining("pk_exception_transitions");
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at,
				    actor, actor_role, rationale)
				SELECT id, 2, 'APPROVED', 'REVOKED', requested_by, expires_at, ?, 'OWNER', 'never approved'
				FROM policy.exception_requests WHERE id = ?""", identity(this.approver), id(first)))
			.hasMessageContaining("fk_exception_transitions_previous");
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at,
				    actor, actor_role, rationale)
				SELECT id, 2, 'REJECTED', 'REQUESTED', requested_by, expires_at, requested_by, 'ADMIN', NULL
				FROM policy.exception_requests WHERE id = ?""", id(first)))
			.hasMessageContaining("ck_exception_transitions_machine");
	}

	@Test
	void onlyTheRequesterWithdrawsAndAWithdrawnRequestCannotBeApproved() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		JsonNode request = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0));
		MvcResult byOwner = act(scanId, request, "withdraw", null);
		assertThat(byOwner.getResponse().getStatus()).isEqualTo(403);
		assertThat(code(byOwner)).isEqualTo("not-requester");

		MvcResult withdrawn = act(scanId, request, "withdraw", this.requester);
		assertThat(withdrawn.getResponse().getStatus()).isEqualTo(200);
		assertThat(json(withdrawn).get("state").asString()).isEqualTo("WITHDRAWN");
		assertThat(act(scanId, request, "approve", null).getResponse().getStatus()).isEqualTo(409);
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");
	}

	// --- Ineligible evidence ---------------------------------------------------------------

	@Test
	void missingIncompleteOrFailedEvidenceCanNeverBeExcepted() throws Exception {
		activate(gitleaks("secrets", 0));
		// Missing evidence: INCOMPLETE.
		UUID missing = scan(ScannerType.GITLEAKS);
		assertThat(this.worker.complete(this.worker.claim(missing, "GITLEAKS").orElseThrow())).isEqualTo("ACCEPTED");
		this.lifecycle.evaluate(missing);
		// Scanner failure: INCOMPLETE.
		UUID failed = scan(ScannerType.GITLEAKS);
		assertThat(this.worker.fail(this.worker.claim(failed, "GITLEAKS").orElseThrow(), "RESOURCE_LIMIT_EXCEEDED"))
			.isEqualTo("ACCEPTED");
		this.lifecycle.evaluate(failed);
		// Incomplete coverage without findings: INCOMPLETE.
		UUID incomplete = scan(ScannerType.GITLEAKS);
		complete(incomplete, ScannerType.GITLEAKS,
				(c) -> new Findings(PolicyScanner.GITLEAKS, c).incomplete("FILES_SKIPPED").bytes());
		this.lifecycle.evaluate(incomplete);
		// Still running: no decision yet.
		UUID running = scan(ScannerType.GITLEAKS);

		for (UUID scanId : List.of(missing, failed, incomplete, running)) {
			MvcResult result = requestException(scanId, ScannerType.GITLEAKS, "a".repeat(64), this.requester);
			assertThat(result.getResponse().getStatus()).isEqualTo(409);
			assertThat(code(result)).isEqualTo("scan-not-exceptionable");
			JsonNode gate = gate(scanId);
			assertThat(gate.get("effectiveDecision").asString()).isEqualTo("INCOMPLETE");
			assertThat(gate.get("exceptionBased").asBoolean()).isFalse();
		}
		assertThat(gateReasons(gate(missing))).containsExactly("ORIGINAL_INCOMPLETE::");
		assertThat(gateReasons(gate(running))).containsExactly("SCAN_NOT_COMPLETED::");
		// The database function refuses them as well.
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		assertThat(api.queryForMap("SELECT * FROM policy.request_exception(?, 'GITLEAKS', repeat('a', 64), ?,"
				+ " now() + interval '1 day', ?)", failed, JUSTIFICATION, identity(this.requester)))
			.containsEntry("outcome", "SCAN_NOT_ELIGIBLE");
	}

	@Test
	void anExceptedViolationNeverTurnsIncompleteEvidenceIntoAnOpenGate() throws Exception {
		// FAIL with incomplete conditions: the secret is a violation, coverage is incomplete,
		// and a required scanner did not run.
		activate(PolicyFixtures.allScanners("all"));
		UUID scanId = scan(ScannerType.GITLEAKS, ScannerType.SEMGREP);
		complete(scanId, ScannerType.GITLEAKS,
				(c) -> new Findings(PolicyScanner.GITLEAKS, c).incomplete("FILES_SKIPPED").finding("x").bytes());
		// Semgrep failed: its scanner failure can never be excepted.
		assertThat(this.worker.fail(this.worker.claim(scanId, "SEMGREP").orElseThrow(), "RESOURCE_LIMIT_EXCEEDED"))
			.isEqualTo("ACCEPTED");
		this.lifecycle.evaluate(scanId);
		assertThat(getJson("/api/v1/scans/{id}", scanId).get("securityDecision").asString()).isEqualTo("FAIL");
		MvcResult semgrep = requestException(scanId, ScannerType.SEMGREP, "a".repeat(64), this.requester);
		assertThat(code(semgrep)).isEqualTo("finding-not-exceptionable");

		approved(scanId, requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));

		JsonNode gate = gate(scanId);
		assertThat(gate.get("effectiveDecision").asString()).isEqualTo("INCOMPLETE");
		assertThat(gate.get("exceptionBased").asBoolean()).isFalse();
		assertThat(gate.get("validUntil").isNull()).isTrue();
		int incompleteCount = getJson("/api/v1/scans/{id}/evaluation", scanId).get("incompleteCount").asInt();
		assertThat(gateReasons(gate)).containsExactly("VIOLATION_EXCEPTED:GITLEAKS:1",
				"INCOMPLETE_CONDITIONS_REMAIN::" + incompleteCount);
	}

	@Test
	void alteredOrPurgedEvidenceCannotSupportAnExceptionAndClosesTheGate() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID altered = gitleaksScan(1);
		UUID purged = gitleaksScan(1);
		UUID approvedThenPurged = gitleaksScan(1);
		JsonNode approved = approved(approvedThenPurged,
				requested(approvedThenPurged, ScannerType.GITLEAKS, fingerprint(approvedThenPurged, ScannerType.GITLEAKS, 0)));
		assertThat(gate(approvedThenPurged).get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
		JsonNode pending = requested(purged, ScannerType.GITLEAKS, fingerprint(purged, ScannerType.GITLEAKS, 0));

		// A database-level edit of the accepted result after the original decision.
		this.jdbcTemplate.update("UPDATE lifecycle.job_reports SET result = jsonb_set(result, '{attempt}', '7')"
				+ " WHERE job_id = (SELECT id FROM scan_jobs WHERE scan_id = ?)", altered);
		// Retention purges the content (as evidence.purge_expired would).
		for (UUID scanId : List.of(purged, approvedThenPurged)) {
			this.jdbcTemplate.update("UPDATE evidence.objects o SET content = NULL, purged_at = now()"
					+ " FROM evidence.job_artifacts u JOIN scan_jobs j ON j.id = u.job_id WHERE j.scan_id = ?"
					+ " AND o.organization_id = u.organization_id AND o.sha256 = u.sha256", scanId);
		}

		MvcResult alteredRequest = requestException(altered, ScannerType.GITLEAKS,
				fingerprint(altered, ScannerType.GITLEAKS, 0), this.requester);
		assertThat(alteredRequest.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(alteredRequest)).isEqualTo("evaluation-not-reproducible");
		assertThat(gateReasons(gate(altered))).containsExactly("ORIGINAL_NOT_REPRODUCIBLE::");
		// A pending request can no longer be approved once its evidence is gone.
		MvcResult approval = act(purged, pending, "approve", null);
		assertThat(approval.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(approval)).isEqualTo("evaluation-not-reproducible");
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		assertThat(api.queryForObject("SELECT policy.transition_exception(?, 'APPROVED', ?, 'ok')", String.class,
				id(pending), ownerIdentity()))
			.isEqualTo("EVIDENCE_UNAVAILABLE");
		assertThat(api.queryForMap("SELECT * FROM policy.request_exception(?, 'GITLEAKS', ?, ?, now() + interval '1 day', ?)",
				purged, fingerprint(purged, ScannerType.GITLEAKS, 0), JUSTIFICATION, identity(this.approver)))
			.containsEntry("outcome", "EVIDENCE_UNAVAILABLE");
		// An approved exception stops supporting the gate: fail closed.
		JsonNode closed = gate(approvedThenPurged);
		assertThat(closed.get("effectiveDecision").asString()).isEqualTo("INCOMPLETE");
		assertThat(gateReasons(closed)).containsExactly("ORIGINAL_NOT_REPRODUCIBLE::");
		assertThat(getJson("/api/v1/scans/{id}/exceptions/{e}", approvedThenPurged, id(approved)).get("status")
			.asString()).isEqualTo("ACTIVE");
	}

	// --- Time ------------------------------------------------------------------------------

	@Test
	void expiredExceptionsStopApplyingWithoutASchedulerAndCannotBeApprovedOrReused() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(2);
		JsonNode active = approved(scanId, requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));
		JsonNode pending = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 1));
		approved(scanId, pending);
		JsonNode open = gate(scanId);
		assertThat(open.get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
		assertThat(Instant.parse(open.get("validUntil").asString()))
			.isEqualTo(Instant.parse(active.get("expiresAt").asString()));

		// One day and one hour later, the first approval has expired.
		travel(id(active), Duration.ofHours(25));

		JsonNode expired = getJson("/api/v1/scans/{id}/exceptions/{e}", scanId, id(active));
		assertThat(expired.get("state").asString()).isEqualTo("APPROVED");
		assertThat(expired.get("status").asString()).isEqualTo("EXPIRED");
		// The earlier result is not reusable: the gate is recomputed and closed.
		JsonNode closed = gate(scanId);
		assertThat(closed.get("effectiveDecision").asString()).isEqualTo("FAIL");
		assertThat(gateReasons(closed)).containsExactly("VIOLATION_NOT_EXCEPTED:GITLEAKS:1");
		MvcResult revoke = act(scanId, active, "revoke", null);
		assertThat(revoke.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(revoke)).isEqualTo("exception-expired");
		// The expired finding can be requested again; the new request needs a new approval.
		assertThat(requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)).get("status")
			.asString()).isEqualTo("REQUESTED");
	}

	@Test
	void approvalAfterOrCloseToExpiryIsRefusedAndTimestampsComeFromTheDatabase() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(2);
		JsonNode late = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0));
		JsonNode close = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 1));
		travel(id(late), Duration.ofDays(2));
		// Three minutes of validity left.
		travel(id(close), Duration.ofDays(1).minusMinutes(3));

		MvcResult expired = act(scanId, late, "approve", null);
		assertThat(expired.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(expired)).isEqualTo("exception-expired");
		assertThat(getJson("/api/v1/scans/{id}/exceptions/{e}", scanId, id(late)).get("status").asString())
			.isEqualTo("EXPIRED");
		MvcResult tooSoon = act(scanId, close, "approve", null);
		assertThat(tooSoon.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(tooSoon)).isEqualTo("exception-expires-too-soon");
		// Even a superuser's direct insert gets the database time, which is past the expiry
		// (an approval would also violate the approval window; a rejection shows the expiry).
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at,
				    actor, actor_role, rationale, occurred_at)
				SELECT id, 1, 'REQUESTED', 'REJECTED', requested_by, expires_at, ?, 'OWNER', 'backdated',
				       requested_at + interval '1 minute'
				FROM policy.exception_requests WHERE id = ?""", ownerIdentity(), id(late)))
			.hasMessageContaining("ck_exception_transitions_before_expiry");
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");

		// Lifetime bounds are checked against the database clock.
		for (Duration lifetime : List.of(Duration.ofMinutes(30), Duration.ofDays(91))) {
			MvcResult result = send("/api/v1/scans/{id}/exceptions",
					body(ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 1), Instant.now().plus(lifetime)),
					this.requester, scanId);
			assertThat(result.getResponse().getStatus()).as(lifetime.toString()).isEqualTo(400);
			assertThat(result.getResponse().getContentAsString()).contains("expiresAt");
		}
	}

	@Test
	void revokedExceptionsStopApplyingImmediately() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		JsonNode exception = approved(scanId,
				requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
		MvcResult adminRevokes = act(scanId, exception, "revoke", this.requester);
		assertThat(adminRevokes.getResponse().getStatus()).isEqualTo(403);

		MvcResult revoked = act(scanId, exception, "revoke", this.approver);

		assertThat(revoked.getResponse().getStatus()).isEqualTo(200);
		assertThat(json(revoked).get("status").asString()).isEqualTo("REVOKED");
		assertThat(json(revoked).get("transitions")).hasSize(3);
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");
		for (String action : List.of("approve", "revoke")) {
			assertThat(code(act(scanId, exception, action, null))).isEqualTo("invalid-exception-transition");
		}
	}

	// --- Tenancy, policy and identity changes ----------------------------------------------

	@Test
	void crossTenantReferencesAreRejectedAsNotFound() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		UUID otherScanOfThisTenant = gitleaksScan(1);
		JsonNode request = requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0));
		String otherOwner = uniqueSubject("other-owner");
		UUID otherOrganization = createOrganization();
		grant(otherOrganization, otherOwner, "OWNER");

		// Another tenant's OWNER can neither read nor decide.
		assertThat(act(scanId, request, "approve", otherOwner).getResponse().getStatus()).isEqualTo(404);
		assertThat(this.mockMvc
			.perform(get("/api/v1/scans/{id}/exceptions/{e}", scanId, id(request)).header(HttpHeaders.AUTHORIZATION,
					TestJwts.bearer(otherOwner)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(404);
		// A request is reachable only through its own scan.
		MvcResult wrongScan = act(otherScanOfThisTenant, request, "approve", null);
		assertThat(wrongScan.getResponse().getStatus()).isEqualTo(404);
		assertThat(this.mockMvc.perform(get("/api/v1/scans/{id}/exceptions/{e}", otherScanOfThisTenant, id(request)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(404);
		// The database refuses a member of another organization as an approver.
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		assertThat(api.queryForObject("SELECT policy.transition_exception(?, 'APPROVED', ?, 'foreign')", String.class,
				id(request), identity(otherOwner)))
			.isEqualTo("NOT_AUTHORIZED");
		// A superuser's cross-tenant request row is refused by the trigger, and by the
		// composite keys on their own.
		String crossTenant = copyRequest("organization_id = '" + otherOrganization + "'::uuid");
		assertThatThrownBy(() -> this.jdbcTemplate.update(crossTenant, id(request)))
			.hasMessageContaining("exception rejected: NOT_AUTHORIZED");
		assertRefusedWithoutTrigger(crossTenant.replace("?", "'" + id(request) + "'"), "violates foreign key constraint");
		assertThat(json(this.mockMvc.perform(get("/api/v1/scans/{id}/exceptions/{e}", scanId, id(request))).andReturn())
			.get("state")
			.asString()).isEqualTo("REQUESTED");
	}

	@Test
	void policyOrFindingIdentityChangesNeverExpandAnExceptionsScope() throws Exception {
		UUID pinned = activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		JsonNode exception = approved(scanId,
				requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));
		List<Object> before = untouchedState(scanId);

		// A historical re-evaluation under a permissive version is non-gating and changes nothing.
		UUID permissive = createPolicy(this.organizationId, gitleaks("permissive", 5));
		MvcResult reevaluation = this.mockMvc
			.perform(post("/api/v1/scans/{id}/reevaluations", scanId).contentType(MediaType.APPLICATION_JSON)
				.content("{\"policyVersionId\": \"%s\"}".formatted(permissive)))
			.andReturn();
		assertThat(reevaluation.getResponse().getStatus()).isEqualTo(201);
		assertThat(json(reevaluation).get("decision").asString()).isEqualTo("PASS");
		UUID historicalId = UUID.fromString(json(reevaluation).get("id").asString());
		// A new active policy does not change the scan's pin or the exception's binding.
		activate(gitleaks("stricter", 0));
		JsonNode gate = gate(scanId);
		assertThat(gate.get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
		assertThat(gate.get("evaluationId").asString())
			.isEqualTo(getJson("/api/v1/scans/{id}/evaluation", scanId).get("id").asString());
		assertThat(getJson("/api/v1/scans/{id}/exceptions/{e}", scanId, id(exception)).get("policyVersionId").asString())
			.isEqualTo(pinned.toString());
		assertThat(getJson("/api/v1/scans/{id}", scanId).get("securityDecision").asString()).isEqualTo("FAIL");
		before.set(5, this.jdbcTemplate.queryForList(
				"SELECT * FROM policy.historical_evaluations WHERE scan_id = ? ORDER BY id", scanId));
		assertThat(untouchedState(scanId)).isEqualTo(before);
		// An exception cannot be bound to a historical record.
		String historical = copyRequest("evaluation_id = '" + historicalId + "'::uuid");
		assertThatThrownBy(() -> this.jdbcTemplate.update(historical, id(exception)))
			.hasMessageContaining("exception rejected: FINDING_NOT_VERIFIED");
		assertRefusedWithoutTrigger(historical.replace("?", "'" + id(exception) + "'"), "fk_exception_requests_evaluation");

		// The same secret in a new scan is a new finding of new evidence: not excepted.
		UUID rescan = gitleaksScan(1);
		JsonNode rescanGate = gate(rescan);
		assertThat(rescanGate.get("effectiveDecision").asString()).isEqualTo("FAIL");
		assertThat(rescanGate.get("appliedExceptions")).isEmpty();
		MvcResult reuse = requestException(rescan, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0),
				this.requester);
		assertThat(code(reuse)).isEqualTo("finding-not-exceptionable");
		// Nor can an exception row be re-pointed at another job's evidence.
		String otherJob = copyRequest("job_id = '" + jobOf(rescan, ScannerType.GITLEAKS) + "'::uuid");
		assertThatThrownBy(() -> this.jdbcTemplate.update(otherJob, id(exception)))
			.hasMessageContaining("exception rejected: FINDING_NOT_VERIFIED");
		assertRefusedWithoutTrigger(otherJob.replace("?", "'" + id(exception) + "'"), "fk_exception_requests_evidence");
	}

	// --- Records ---------------------------------------------------------------------------

	@Test
	void runtimeRolesCannotRewriteHistory() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		JsonNode exception = approved(scanId,
				requested(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0)));
		UUID exceptionId = id(exception);
		JdbcTemplate api = this.admin.connectAs(DatabaseRoles.API_USER, DatabaseRoles.API_PASSWORD);
		for (String sql : List.of("UPDATE policy.exception_requests SET expires_at = expires_at + interval '1 day' WHERE id = ?",
				"DELETE FROM policy.exception_requests WHERE id = ?",
				"UPDATE policy.exception_transitions SET actor = requested_by WHERE request_id = ?",
				"DELETE FROM policy.exception_transitions WHERE request_id = ?")) {
			assertThatThrownBy(() -> api.update(sql, exceptionId)).as(sql).hasStackTraceContaining("permission denied");
			assertThatThrownBy(() -> this.jdbcTemplate.update(sql, exceptionId)).as("superuser: " + sql)
				.hasStackTraceContaining("policy records are immutable");
		}
		assertThatThrownBy(() -> api.update("""
				INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at,
				    actor, actor_role, rationale)
				SELECT id, 2, 'APPROVED', 'REVOKED', requested_by, expires_at, requested_by, 'OWNER', 'x'
				FROM policy.exception_requests WHERE id = ?""", exceptionId))
			.hasStackTraceContaining("permission denied");

		// The stored history is unchanged.
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.exception_transitions WHERE request_id = ?", Integer.class, exceptionId))
			.isEqualTo(2);
		JsonNode stored = getJson("/api/v1/scans/{id}/exceptions/{e}", scanId, exceptionId);
		assertThat(stored.get("transitions")).isEqualTo(exception.get("transitions"));
		assertThat(stored.get("expiresAt")).isEqualTo(exception.get("expiresAt"));
	}

	@Test
	void ownerSelfApprovalThroughDirectSqlIsRefusedByTheDatabase() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(1);
		MvcResult ownRequest = requestException(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 0),
				null);
		assertThat(ownRequest.getResponse().getStatus()).isEqualTo(201);
		UUID requestId = id(json(ownRequest));
		String insert = """
				INSERT INTO policy.exception_transitions (request_id, seq, from_state, to_state, requested_by, expires_at,
				    actor, actor_role, rationale)
				SELECT id, 1, 'REQUESTED', ?, requested_by, expires_at, ?, ?, 'direct'
				FROM policy.exception_requests WHERE id = ?""";
		// The requester (an OWNER) approving or rejecting their own request.
		for (String state : List.of("APPROVED", "REJECTED")) {
			assertThatThrownBy(() -> this.jdbcTemplate.update(insert, state, ownerIdentity(), "OWNER", requestId))
				.as(state)
				.hasMessageContaining("ck_exception_transitions_independent");
		}
		// An ADMIN claiming the OWNER role, and a non-member.
		assertThatThrownBy(() -> this.jdbcTemplate.update(insert, "APPROVED", identity(this.requester), "OWNER",
				requestId))
			.hasMessageContaining("exception rejected: NOT_AUTHORIZED");
		assertThatThrownBy(() -> this.jdbcTemplate.update(insert, "APPROVED", "user:" + UUID.randomUUID(), "OWNER",
				requestId))
			.hasMessageContaining("exception rejected: NOT_AUTHORIZED");
		// A valid independent approval through direct SQL gets database-controlled values.
		this.jdbcTemplate.update(insert, "APPROVED", identity(this.approver), "OWNER", requestId);
		Map<String, Object> transition = this.jdbcTemplate.queryForMap("""
				SELECT recorded_by, occurred_at > now() - interval '1 minute' AS recent
				FROM policy.exception_transitions WHERE request_id = ? AND seq = 1""", requestId);
		assertThat(transition).containsEntry("recent", true);
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED");
	}

	@Test
	void inputsAndPagesAreBoundedAndTheLimitIsEnforcedByTheDatabase() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID scanId = gitleaksScan(2);
		String fingerprint = fingerprint(scanId, ScannerType.GITLEAKS, 0);
		String expires = Instant.now().plus(Duration.ofDays(1)).toString();
		List<String> invalid = List.of(
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s\", \"justification\": \"too short\", \"expiresAt\": \"%s\"}",
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s\", \"justification\": \"" + "x".repeat(2001)
						+ "\", \"expiresAt\": \"%s\"}",
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s\", \"justification\": \" leading space justification\", \"expiresAt\": \"%s\"}",
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s\", \"justification\": \"control\\u0007 character justification\", \"expiresAt\": \"%s\"}",
				"{\"scanner\": \"NOPE\", \"findingFingerprint\": \"%s\", \"justification\": \"" + JUSTIFICATION
						+ "\", \"expiresAt\": \"%s\"}",
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s*\", \"justification\": \"" + JUSTIFICATION
						+ "\", \"expiresAt\": \"%s\"}",
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s\", \"justification\": \"" + JUSTIFICATION
						+ "\", \"expiresAt\": \"%s\", \"wildcard\": true}",
				"{\"scanner\": \"GITLEAKS\", \"findingFingerprint\": \"%s\", \"justification\": \"" + JUSTIFICATION
						+ "\", \"expiresAt\": \"not-a-time-%s\"}");
		for (String template : invalid) {
			MvcResult result = send("/api/v1/scans/{id}/exceptions", template.formatted(fingerprint, expires),
					this.requester, scanId);
			assertThat(result.getResponse().getStatus()).as(template).isEqualTo(400);
		}
		JsonNode request = requested(scanId, ScannerType.GITLEAKS, fingerprint);
		for (String body : List.of("{}", "{\"rationale\": \"\"}", "{\"rationale\": \"" + "x".repeat(1001) + "\"}",
				"{\"rationale\": \"ok\", \"state\": \"APPROVED\"}")) {
			assertThat(send("/api/v1/scans/{id}/exceptions/{e}/approve", body, null, scanId, id(request)).getResponse()
				.getStatus()).as(body).isEqualTo(400);
		}
		for (String query : List.of("size=101", "size=0", "page=-1", "page=10001")) {
			assertThat(this.mockMvc.perform(get("/api/v1/scans/{id}/exceptions?" + query, scanId))
				.andReturn()
				.getResponse()
				.getStatus()).as(query).isEqualTo(400);
		}
		JsonNode page = getJson("/api/v1/scans/{id}/exceptions?page=0&size=1", scanId);
		ContractSchemas.assertValid("security-exception-page.schema.json", page);
		assertThat(page.at("/page/totalElements").asLong()).isEqualTo(1);

		// The per-scan limit: rows inserted directly (verified by the trigger, without
		// transitions, so never active), then one more request through the API.
		this.jdbcTemplate.update(copyRequest("finding_fingerprint = finding_fingerprint")
			.replace("WHERE id = ?", "CROSS JOIN generate_series(2, " + ExceptionRequestService.MAX_PER_SCAN + ") WHERE id = ?"),
				id(request));
		MvcResult limit = requestException(scanId, ScannerType.GITLEAKS, fingerprint(scanId, ScannerType.GITLEAKS, 1),
				this.requester);
		assertThat(limit.getResponse().getStatus()).isEqualTo(409);
		assertThat(code(limit)).isEqualTo("exception-limit-reached");
		// Requests without any transition are INVALID and never apply.
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.exception_status WHERE scan_id = ? AND status = 'INVALID'", Integer.class,
				scanId))
			.isEqualTo(ExceptionRequestService.MAX_PER_SCAN - 1);
		assertThat(gate(scanId).get("effectiveDecision").asString()).isEqualTo("FAIL");
	}

	@Test
	void responsesCarryNoEvidenceContentAndPassIsDistinguishableFromAcceptedRisk() throws Exception {
		activate(gitleaks("secrets", 0));
		UUID clean = gitleaksScan(0);
		JsonNode pass = gate(clean);
		assertThat(pass.get("effectiveDecision").asString()).isEqualTo("PASS");
		assertThat(pass.get("exceptionBased").asBoolean()).isFalse();
		assertThat(pass.get("appliedExceptions")).isEmpty();
		assertThat(pass.get("reasons")).isEmpty();
		assertThat(pass.get("validUntil").isNull()).isTrue();
		MvcResult notExceptionable = requestException(clean, ScannerType.GITLEAKS, "a".repeat(64), this.requester);
		assertThat(code(notExceptionable)).isEqualTo("scan-not-exceptionable");

		UUID leaky = gitleaksScan(1);
		JsonNode exception = approved(leaky,
				requested(leaky, ScannerType.GITLEAKS, fingerprint(leaky, ScannerType.GITLEAKS, 0)));
		JsonNode accepted = gate(leaky);
		assertThat(accepted.get("effectiveDecision").asString()).isEqualTo("RISK_ACCEPTED").isNotEqualTo("PASS");
		assertThat(accepted.get("exceptionBased").asBoolean()).isTrue();
		// Records and errors carry identifiers, digests and codes; never paths or evidence.
		List<String> bodies = List.of(exception.toString(), accepted.toString(),
				getJson("/api/v1/scans/{id}/exceptions", leaky).toString(),
				requestException(leaky, ScannerType.GITLEAKS, "b".repeat(64), this.requester).getResponse()
					.getContentAsString(),
				act(leaky, exception, "approve", this.approver).getResponse().getContentAsString());
		for (String body : bodies) {
			assertThat(body).doesNotContain("src/file").doesNotContain("excerpt").doesNotContain("SQL")
				.doesNotContain("exception rejected");
		}
	}

}

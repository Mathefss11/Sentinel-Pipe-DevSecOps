package dev.sentinelpipe.api.e2e;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.DatabaseRoles;
import dev.sentinelpipe.api.ExecutionTimeTravel;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.evidence.Evidence;
import dev.sentinelpipe.api.evidence.EvidenceArtifact;
import dev.sentinelpipe.api.evidence.EvidenceStore;
import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import dev.sentinelpipe.api.scan.ExecutionSupervisor;
import dev.sentinelpipe.api.scan.ScanLifecycleService;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;

/**
 * End-to-end execution lifecycle with the real Python worker process ({@code sentinel-worker
 * execute}, harmless FIXTURE scanner in a real sandbox container, ADR-0009) and its real
 * least-privileged database login:
 * REST request, lease claim, heartbeats, report, supervisor evaluation, REST read; REST
 * cancellation of a running job; recovery after the worker process is killed; and the
 * GITLEAKS scanner on synthetic repositories (real Gitleaks container, ADR-0010), whose
 * redacted findings are stored as verified evidence without ever producing PASS; Semgrep
 * (ADR-0011); and Trivy (ADR-0012) with a verified image built from the synthetic
 * vulnerability database, including a worker that refuses a forged image lock.
 *
 * <p>
 * Requires {@code -Pe2e -Dsentinel.e2e.python=<python with sentinel-worker installed>} and
 * {@code -Dsentinel.e2e.trivy-lock=<lock of the synthetic Trivy image>}.
 */
class ScanExecutionE2ETests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private PostgreSQLContainer postgres;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private ExecutionSupervisor supervisor;

	@Autowired
	private TestDatabaseAdmin admin;

	@Autowired
	private EvidenceStore evidenceStore;

	private ExecutionTimeTravel time;

	private static String python() {
		String python = System.getProperty("sentinel.e2e.python", "");
		if (python.isBlank() || python.contains("${")) {
			throw new IllegalStateException(
					"Run with -Pe2e -Dsentinel.e2e.python=<python executable with sentinel-worker installed>");
		}
		return python;
	}

	@BeforeEach
	void setUp() {
		this.time = new ExecutionTimeTravel(this.admin);
	}

	/** Starts {@code sentinel-worker execute} with the worker's own database login. */
	private Process startWorker(double fixtureSeconds, String... arguments) throws IOException {
		return startWorker(fixtureSeconds, Map.of(), arguments);
	}

	private Process startWorker(double fixtureSeconds, Map<String, String> extraEnv, String... arguments)
			throws IOException {
		List<String> command = new java.util.ArrayList<>(List.of(python(), "-m", "sentinel_worker", "execute"));
		command.addAll(List.of(arguments));
		ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
		Map<String, String> env = builder.environment();
		env.put("SENTINEL_WORKER_DB_HOST", this.postgres.getHost());
		env.put("SENTINEL_WORKER_DB_PORT", String.valueOf(this.postgres.getMappedPort(5432)));
		env.put("SENTINEL_WORKER_DB_NAME", this.postgres.getDatabaseName());
		env.put("SENTINEL_WORKER_DB_USERNAME", DatabaseRoles.WORKER_USER);
		env.put("SENTINEL_WORKER_DB_PASSWORD", DatabaseRoles.WORKER_PASSWORD);
		env.put("SENTINEL_WORKER_DB_SSLMODE", "disable");
		env.put("SENTINEL_WORKER_ENVIRONMENT", "ci");
		env.put("SENTINEL_WORKER_LOG_LEVEL", "INFO");
		env.put("SENTINEL_WORKER_FIXTURE_ENABLED", "true");
		env.put("SENTINEL_WORKER_FIXTURE_SECONDS", String.valueOf(fixtureSeconds));
		env.put("SENTINEL_WORKER_EXECUTION_POLL_SECONDS", "0.2");
		env.putAll(extraEnv);
		return builder.start();
	}

	/** Sandbox containers of a job (by label), via the local Docker CLI. */
	private static List<String> sandboxes(UUID jobId) throws Exception {
		return docker("ps", "--all", "--filter", "label=sentinelpipe.job=" + jobId, "--format", "{{.Names}}").lines()
			.filter((line) -> !line.isBlank())
			.toList();
	}

	private static List<String> sandboxesUnchecked(UUID jobId) {
		try {
			return sandboxes(jobId);
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static String docker(String... arguments) throws Exception {
		List<String> command = new java.util.ArrayList<>(List.of("docker"));
		command.addAll(List.of(arguments));
		Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
		assertThat(process.waitFor(60, TimeUnit.SECONDS)).isTrue();
		return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
	}

	private static String finish(Process process) throws Exception {
		assertThat(process.waitFor(60, TimeUnit.SECONDS)).as("worker finished").isTrue();
		String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertThat(process.exitValue()).as(output).isZero();
		// Neither the database password nor any lease token is ever printed.
		assertThat(output).doesNotContain(DatabaseRoles.WORKER_PASSWORD).doesNotContainPattern("[0-9a-f]{64}");
		return output;
	}

	private static void await(String what, BooleanSupplier condition) throws InterruptedException {
		Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
		while (!condition.getAsBoolean()) {
			assertThat(Instant.now()).as("waiting for %s", what).isBefore(deadline);
			Thread.sleep(100);
		}
	}

	private UUID requestFixtureScan(UUID projectId) throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(projectId, randomSha(), null)).get("id").asString());
		this.lifecycle.planJob(scanId, ScannerType.FIXTURE);
		return scanId;
	}

	private String jobStatus(UUID scanId) {
		return this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE scan_id = ?",
				String.class, scanId);
	}

	private JsonNode json(String text) {
		return this.jsonMapper.readTree(text);
	}

	private JsonNode scan(UUID scanId) throws Exception {
		return json(this.mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
			.get("/api/v1/scans/{id}", scanId)).andReturn());
	}

	@Test
	void aScanRunsThroughTheWholeLifecycleAndIsNeverPassWithoutPolicy() throws Exception {
		UUID scanId = requestFixtureScan(createProject());

		String output = finish(startWorker(0.5, "--idle-timeout", "3"));

		assertThat(output).contains("execution.reported").doesNotContain("repository_content_read");
		// The worker's evidence: digest computed by PostgreSQL, verified again on read.
		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		EvidenceArtifact artifact = this.evidenceStore.list(jobId).get(0);
		assertThat(artifact.name()).isEqualTo("fixture-result.json");
		Evidence evidence = this.evidenceStore.read(jobId, artifact.leaseEpoch(), artifact.name()).orElseThrow();
		assertThat(EvidenceVerifier.sha256(evidence.content())).isEqualTo(artifact.sha256());
		JsonNode content = json(new String(evidence.content(), StandardCharsets.UTF_8));
		assertThat(content.get("job_id").asString()).isEqualTo(jobId.toString());
		assertThat(content.get("repository_content_read").asBoolean()).isFalse();
		assertThat(content.get("sandboxed").asBoolean()).as("produced inside the sandbox").isTrue();
		assertThat(sandboxes(jobId)).as("the sandbox was removed").isEmpty();
		// The accepted job-result.v1 document conforms to the contract.
		JsonNode result = json(this.jdbcTemplate.queryForObject(
				"SELECT result::text FROM lifecycle.job_reports WHERE job_id = ?", String.class, jobId));
		ContractSchemas.assertValidMessage("job-result.v1.schema.json", result);
		assertThat(result.at("/artifacts/0/sha256").asString()).isEqualTo(artifact.sha256());
		JsonNode evaluating = scan(scanId);
		assertThat(evaluating.get("executionStatus").asString()).isEqualTo("EVALUATING");
		assertThat(evaluating.at("/jobs/0/executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(evaluating.get("deadlineAt").isNull()).isFalse();

		this.supervisor.runOnce();

		JsonNode completed = scan(scanId);
		assertThat(completed.get("executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(completed.get("securityDecision").asString()).isEqualTo("INCOMPLETE");
		assertThat(completed.get("decisionReason").asString()).isEqualTo("POLICY_EVALUATION_UNAVAILABLE");
		assertThat(this.jdbcTemplate.queryForList(
				"SELECT event_type FROM lifecycle.execution_events WHERE scan_id = ? ORDER BY id", String.class,
				scanId))
			.containsExactly("SCAN_STARTED", "JOB_CLAIMED", "JOB_COMPLETED", "SCAN_EVALUATING", "SCAN_COMPLETED");
	}

	@Test
	void aRunningJobIsCancelledThroughTheApiAndTheWorkerStops() throws Exception {
		UUID projectId = createProject();
		UUID scanId = requestFixtureScan(projectId);
		// Shortest permitted lease, so the worker heartbeats every 3.75 s.
		this.jdbcTemplate.update("UPDATE scans SET lease_duration_seconds = 15 WHERE id = ?", scanId);
		Process worker = startWorker(120, "--max-jobs", "1");
		await("the worker to claim the job", () -> "RUNNING".equals(jobStatus(scanId)));

		this.mockMvc.perform(post("/api/v1/projects/{p}/scans/{s}/cancel", projectId, scanId))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.executionStatus").value("CANCELLED"));

		String output = finish(worker);
		assertThat(output).contains("execution.abandoned").contains("\"reason\": \"CANCELLED\"");
		assertThat(jobStatus(scanId)).isEqualTo("CANCELLED");
		// The running sandbox was killed and removed, not left to finish.
		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		assertThat(sandboxes(jobId)).isEmpty();
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = 'JOB_COMPLETED'",
				Integer.class, scanId))
			.isZero();
	}

	@Test
	void aKilledWorkersJobIsRecoveredByTheSupervisorAndCompletedByAnotherWorker() throws Exception {
		UUID scanId = requestFixtureScan(createProject());
		Process crashing = startWorker(120, "--max-jobs", "1");
		await("the first worker to claim the job", () -> "RUNNING".equals(jobStatus(scanId)));
		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		await("the first worker's sandbox to start", () -> !sandboxesUnchecked(jobId).isEmpty());

		// Hard crash: no shutdown handler runs, no report is sent.
		crashing.destroyForcibly();
		assertThat(crashing.waitFor(30, TimeUnit.SECONDS)).isTrue();
		// The crashed worker's sandbox is orphaned but labelled with an expiry, so a later
		// worker reaps it (verified in the worker's sandbox tests); its lease is fenced.
		List<String> orphans = sandboxes(jobId);
		assertThat(orphans).hasSize(1);
		JsonNode labels = json(docker("inspect", "--format", "{{json .Config.Labels}}", orphans.get(0)));
		assertThat(labels.get("sentinelpipe.expires-at").asString()).matches("[0-9]+");
		docker("rm", "--force", orphans.get(0));
		this.time.expireLease(jobId);
		this.supervisor.runOnce();
		assertThat(this.jdbcTemplate.queryForMap(
				"SELECT execution_status, attempt_count, failure_reason FROM scan_jobs WHERE id = ?", jobId))
			.containsEntry("execution_status", "QUEUED")
			.containsEntry("attempt_count", 1)
			.containsEntry("failure_reason", "LEASE_EXPIRED");
		this.time.makeRetryDue(jobId);

		finish(startWorker(0.2, "--idle-timeout", "3"));
		this.supervisor.runOnce();

		JsonNode recovered = scan(scanId);
		assertThat(recovered.at("/jobs/0/executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(recovered.at("/jobs/0/attemptCount").asInt()).isEqualTo(2);
		assertThat(recovered.get("executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(recovered.get("securityDecision").asString()).isEqualTo("INCOMPLETE");
	}

	// --- Gitleaks (ADR-0010) ------------------------------------------------------------

	@TempDir
	private Path fixtures;

	/**
	 * A synthetic GitHub token, assembled at run time so that no credential-shaped literal
	 * exists in the source tree. It is not a real credential.
	 */
	private static String syntheticToken(char fill) {
		return "ghp" + "_" + "Sx9" + String.valueOf(fill).repeat(3) + "Q7mK2pLw4Rt8Vy1Zb6Nc3Hd5Jf0Gs" + fill;
	}

	private Map<String, String> gitleaksWorker() {
		Map<String, String> env = new HashMap<>();
		env.put("SENTINEL_WORKER_FIXTURE_ENABLED", "false");
		env.put("SENTINEL_WORKER_GITLEAKS_ENABLED", "true");
		env.put("SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR", this.fixtures.toAbsolutePath().toString());
		return env;
	}

	/** A project whose repository acme/{name} is a synthetic fixture with these files. */
	private UUID gitleaksScan(String name, Map<String, String> files) throws Exception {
		return fixtureScan(name, files, ScannerType.GITLEAKS);
	}

	private UUID fixtureScan(String name, Map<String, String> files, ScannerType scanner) throws Exception {
		Path repository = Files.createDirectories(this.fixtures.resolve("acme").resolve(name));
		for (Map.Entry<String, String> file : files.entrySet()) {
			Path target = repository.resolve(file.getKey());
			Files.createDirectories(target.getParent());
			Files.writeString(target, file.getValue(), StandardCharsets.UTF_8);
		}
		UUID projectId = createProject(createOrganization(), name);
		UUID scanId = UUID.fromString(json(requestScan(projectId, randomSha(), null)).get("id").asString());
		this.lifecycle.planJob(scanId, scanner);
		return scanId;
	}

	private JsonNode findings(UUID jobId) {
		List<EvidenceArtifact> artifacts = this.evidenceStore.list(jobId);
		assertThat(artifacts).extracting(EvidenceArtifact::name).containsExactly("findings.json");
		EvidenceArtifact artifact = artifacts.get(0);
		Evidence evidence = this.evidenceStore.read(jobId, artifact.leaseEpoch(), artifact.name()).orElseThrow();
		assertThat(EvidenceVerifier.sha256(evidence.content())).isEqualTo(artifact.sha256());
		JsonNode document = json(new String(evidence.content(), StandardCharsets.UTF_8));
		ContractSchemas.assertValidMessage("findings.v1.schema.json", document);
		return document;
	}

	private void assertCompletedButNeverPass(UUID scanId) throws Exception {
		assertThat(scan(scanId).get("executionStatus").asString()).isEqualTo("EVALUATING");
		this.supervisor.runOnce();
		JsonNode completed = scan(scanId);
		assertThat(completed.at("/jobs/0/executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(completed.get("executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(completed.get("securityDecision").asString()).isEqualTo("INCOMPLETE");
		assertThat(completed.get("decisionReason").asString()).isEqualTo("POLICY_EVALUATION_UNAVAILABLE");
	}

	@Test
	void gitleaksFindsSyntheticSecretsAndStoresOnlyRedactedFindings() throws Exception {
		String token = syntheticToken('A');
		String allowed = syntheticToken('B');
		String inName = syntheticToken('C');
		UUID scanId = gitleaksScan("leaky-" + UUID.randomUUID().toString().substring(0, 8), Map.of(
				"src/settings.py", "DEBUG = False\nGITHUB_TOKEN = \"" + token + "\"\n",
				// Repository-controlled suppression must not hide findings.
				"tools/deploy.py", "TOKEN = \"" + allowed + "\"  # gitleaks:allow\n",
				".gitleaks.toml", "title = \"allow everything\"\n[allowlist]\npaths = ['''.*''']\n",
				".gitleaksignore", "src/settings.py:github-pat:2\n",
				"README.md", "Synthetic test repository.\n",
				// A credential committed as a file name (security review D2).
				"keys/" + inName + ".txt", "harmless\n",
				// A file name upstream's default ruleset would skip (security review D1).
				"assets/logo.png", "KEY = \"" + token + "\"\n"));

		String output = finish(startWorker(0, gitleaksWorker(), "--idle-timeout", "3"));

		assertThat(output).contains("scanner.completed")
			.doesNotContain(token)
			.doesNotContain(allowed)
			.doesNotContain(inName);
		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		JsonNode document = findings(jobId);
		assertThat(document.toString()).doesNotContain(token).doesNotContain(allowed).doesNotContain(inName);
		assertThat(document.at("/scanner/version").asString()).isEqualTo("8.30.1");
		assertThat(document.at("/context/job_id").asString()).isEqualTo(jobId.toString());
		assertThat(document.at("/execution/status").asString()).isEqualTo("FINDINGS_DETECTED");
		assertThat(document.at("/execution/exit_code").asInt()).as("content and file-name leaks").isEqualTo(43);
		assertThat(document.at("/input/commit_verified").asBoolean()).isFalse();
		assertThat(document.at("/input/skipped/suppression_file").asInt()).isEqualTo(1);
		// Both files are reported despite the suppression attempts; overlapping built-in rules
		// (for example generic-api-key) may add distinct findings at the same location.
		assertThat(document.get("finding_count").asInt()).isEqualTo(document.get("findings").size());
		List<String> located = new java.util.ArrayList<>();
		for (JsonNode finding : document.get("findings")) {
			located.add(finding.at("/location/path").asString() + ":" + finding.get("rule_id").asString());
		}
		assertThat(located).contains("src/settings.py:github-pat", "tools/deploy.py:github-pat",
				"assets/logo.png:github-pat", "keys/[redacted-1]:github-pat");
		assertThat(document.get("findings").findValuesAsString("path")).containsOnly("src/settings.py",
				"tools/deploy.py", "assets/logo.png", "keys/[redacted-1]");
		assertThat(document.at("/input/paths_redacted").asInt()).isEqualTo(1);
		for (JsonNode finding : document.get("findings")) {
			assertThat(finding.at("/evidence/redacted").asBoolean()).isTrue();
			assertThat(finding.at("/evidence/excerpt").isNull()).isTrue();
			assertThat(finding.get("severity").isNull()).as("Gitleaks provides no severity").isTrue();
		}
		// No raw secret anywhere in stored evidence or results, for any tenant.
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM evidence.objects WHERE position(? IN content) > 0 OR position(? IN content) > 0"
						+ " OR position(? IN content) > 0",
				Integer.class, token.getBytes(StandardCharsets.UTF_8), allowed.getBytes(StandardCharsets.UTF_8),
				inName.getBytes(StandardCharsets.UTF_8)))
			.isZero();
		for (String secret : List.of(token, allowed, inName)) {
			assertThat(this.jdbcTemplate.queryForObject(
					"SELECT (SELECT count(*) FROM lifecycle.job_reports WHERE position(? IN result::text) > 0)"
							+ " + (SELECT count(*) FROM lifecycle.execution_events e"
							+ " WHERE position(? IN row_to_json(e)::text) > 0)",
					Integer.class, secret, secret))
				.isZero();
		}
		assertThat(sandboxes(jobId)).isEmpty();
		// Findings are evidence, not a decision: without policy evaluation the scan is INCOMPLETE.
		assertCompletedButNeverPass(scanId);
	}

	@Test
	void aCleanGitleaksScanIsNeverPass() throws Exception {
		UUID scanId = gitleaksScan("clean-" + UUID.randomUUID().toString().substring(0, 8),
				Map.of("app.py", "print('hello')\n", "docs/notes.txt", "Nothing sensitive here.\n"));

		finish(startWorker(0, gitleaksWorker(), "--idle-timeout", "3"));

		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		JsonNode document = findings(jobId);
		assertThat(document.get("finding_count").asInt()).isZero();
		assertThat(document.at("/execution/status").asString()).isEqualTo("NO_FINDINGS");
		assertThat(document.at("/input/files_scanned").asInt()).isEqualTo(2);
		assertThat(sandboxes(jobId)).isEmpty();
		assertCompletedButNeverPass(scanId);
	}

	// --- Semgrep (ADR-0011) -------------------------------------------------------------

	private Map<String, String> semgrepWorker() {
		Map<String, String> env = new HashMap<>();
		env.put("SENTINEL_WORKER_FIXTURE_ENABLED", "false");
		env.put("SENTINEL_WORKER_SEMGREP_ENABLED", "true");
		env.put("SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR", this.fixtures.toAbsolutePath().toString());
		return env;
	}

	private static final String PROPRIETARY_MARKER = "SENTINEL_PROPRIETARY_SOURCE_" + "E".repeat(24);

	@Test
	void semgrepReportsCodePatternsInEveryLanguageWithoutSourceExcerptsAndIsNeverPass() throws Exception {
		String inName = syntheticToken('D');
		UUID scanId = fixtureScan("sast-" + UUID.randomUUID().toString().substring(0, 8), Map.of(
				"src/Users.java", """
						import java.sql.*;
						class Users {
						  ResultSet find(Statement s, String id) throws Exception {
						    return s.executeQuery("SELECT * FROM users WHERE id = " + id);
						  }
						}
						""",
				"app/handlers.py", "# " + PROPRIETARY_MARKER + "\nimport subprocess\n\ndef run(cmd):\n"
						+ "    subprocess.run(cmd, shell=True)\n",
				"web/server.js", "function handle(input) {\n  eval(input);\n}\n",
				"web/client.ts", "export function handle(input: string, el: HTMLElement): void {\n"
						+ "  el.innerHTML = input;\n}\n",
				// Repository-controlled suppression must not hide findings.
				".semgrepignore", "*\n",
				"tests/test_app.py", "def t(x):\n    eval(x)  # nosemgrep\n",
				"keys/" + inName + ".py", "eval(input())\n",
				"README.md", "Synthetic test repository.\n"), ScannerType.SEMGREP);

		String output = finish(startWorker(0, semgrepWorker(), "--idle-timeout", "3"));

		assertThat(output).contains("scanner.completed").doesNotContain(PROPRIETARY_MARKER).doesNotContain(inName);
		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		JsonNode document = findings(jobId);
		assertThat(document.toString()).doesNotContain(PROPRIETARY_MARKER).doesNotContain(inName);
		assertThat(document.at("/scanner/name").asString()).isEqualTo("semgrep");
		assertThat(document.at("/scanner/version").asString()).isEqualTo("1.179.0");
		assertThat(document.at("/execution/exit_code").asInt()).isEqualTo(41);
		assertThat(document.at("/input/skipped/suppression_file").asInt()).isEqualTo(1);
		assertThat(document.at("/coverage/files_supported").asInt()).isEqualTo(6);
		assertThat(document.at("/coverage/files_analyzed").asInt()).isEqualTo(6);
		assertThat(document.at("/coverage/files_unsupported").asInt()).isEqualTo(1);
		List<String> located = new java.util.ArrayList<>();
		for (JsonNode finding : document.get("findings")) {
			located.add(finding.at("/location/path").asString() + ":" + finding.get("rule_id").asString());
			assertThat(finding.get("category").asString()).isEqualTo("CODE_PATTERN");
			assertThat(finding.at("/evidence/excerpt").isNull()).isTrue();
			assertThat(finding.get("severity").isNull()).as("not mapped onto a normalized scale").isTrue();
			assertThat(finding.get("scanner_severity").asString()).isIn("ERROR", "WARNING");
			assertThat(finding.at("/classification/cwe/0").asString()).startsWith("CWE-");
		}
		assertThat(located).containsExactlyInAnyOrder(
				"src/Users.java:sentinelpipe.java.sql-injection-string-concatenation",
				"app/handlers.py:sentinelpipe.python.command-injection-shell",
				"web/server.js:sentinelpipe.javascript.code-injection-eval",
				"web/client.ts:sentinelpipe.javascript.dom-xss-inner-html",
				"tests/test_app.py:sentinelpipe.python.code-injection-eval",
				"keys/[redacted-1]:sentinelpipe.python.code-injection-eval");
		for (String sensitive : List.of(PROPRIETARY_MARKER, inName)) {
			assertThat(this.jdbcTemplate.queryForObject(
					"SELECT (SELECT count(*) FROM evidence.objects WHERE position(? IN content) > 0)"
							+ " + (SELECT count(*) FROM lifecycle.job_reports WHERE position(? IN result::text) > 0)"
							+ " + (SELECT count(*) FROM lifecycle.execution_events e"
							+ " WHERE position(? IN row_to_json(e)::text) > 0)",
					Integer.class, sensitive.getBytes(StandardCharsets.UTF_8), sensitive, sensitive))
				.isZero();
		}
		assertThat(sandboxes(jobId)).isEmpty();
		// Code patterns are not proof of exploitability and not a decision: INCOMPLETE until M4.
		assertCompletedButNeverPass(scanId);
	}

	@Test
	void aCleanSemgrepScanIsNeverPass() throws Exception {
		UUID scanId = fixtureScan("sast-clean-" + UUID.randomUUID().toString().substring(0, 8),
				Map.of("app.py", "import hashlib\n\ndef h(b):\n    return hashlib.sha256(b).hexdigest()\n",
						"web/app.ts", "export const add = (a: number, b: number): number => a + b;\n"),
				ScannerType.SEMGREP);

		finish(startWorker(0, semgrepWorker(), "--idle-timeout", "3"));

		UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
				scanId);
		JsonNode document = findings(jobId);
		assertThat(document.get("finding_count").asInt()).isZero();
		assertThat(document.at("/execution/status").asString()).isEqualTo("NO_FINDINGS");
		assertThat(document.at("/coverage/complete").asBoolean()).isTrue();
		assertThat(sandboxes(jobId)).isEmpty();
		assertCompletedButNeverPass(scanId);
	}

	// --- Trivy (ADR-0012) ---------------------------------------------------------------

	/**
	 * The lock of a verified Trivy image built from the SYNTHETIC vulnerability database
	 * (scripts/trivy/build-fixture-db.sh, then {@code sentinel-worker trivy-image build}).
	 */
	// --- Security policy engine (ADR-0013) -----------------------------------------------

	/**
	 * The whole M4 path with real components: a policy created and activated through the
	 * API, scans pinned at request time, the real worker running real Gitleaks in the
	 * sandbox, verified evidence, and the supervisor's policy evaluation. Clean evidence
	 * that satisfies the policy (including the limitations it explicitly accepts) is PASS;
	 * a detected secret is FAIL. Both decisions come with an auditable record.
	 */
	@Test
	void anActivePolicyTurnsRealGitleaksEvidenceIntoPassOrFailWithAnAuditableRecord() throws Exception {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		UUID organizationId = createOrganization();
		JsonNode version = json(this.mockMvc
			.perform(post("/api/v1/organizations/{id}/policies", organizationId)
				.contentType(org.springframework.http.MediaType.APPLICATION_JSON)
				.content(dev.sentinelpipe.api.policy.PolicyFixtures.gitleaksOnly("secrets")))
			.andExpect(status().isCreated())
			.andReturn());
		Map<String, UUID> scans = new HashMap<>();
		Map<String, Map<String, String>> repositories = Map.of("policy-clean-" + suffix,
				Map.of("app.py", "print('hello')\n", "docs/notes.txt", "Nothing sensitive here.\n"),
				"policy-leaky-" + suffix, Map.of("src/settings.py", "TOKEN = \"" + syntheticToken('P') + "\"\n"));
		for (Map.Entry<String, Map<String, String>> repository : repositories.entrySet()) {
			Path root = Files.createDirectories(this.fixtures.resolve("acme").resolve(repository.getKey()));
			for (Map.Entry<String, String> file : repository.getValue().entrySet()) {
				Path target = root.resolve(file.getKey());
				Files.createDirectories(target.getParent());
				Files.writeString(target, file.getValue(), StandardCharsets.UTF_8);
			}
			UUID projectId = createProject(organizationId, repository.getKey());
			this.mockMvc
				.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
					.put("/api/v1/projects/{id}/policy", projectId)
					.contentType(org.springframework.http.MediaType.APPLICATION_JSON)
					.content("{\"policyVersionId\": \"%s\"}".formatted(version.get("id").asString())))
				.andExpect(status().isOk());
			UUID scanId = UUID.fromString(json(requestScan(projectId, randomSha(), null)).get("id").asString());
			this.lifecycle.planJob(scanId, ScannerType.GITLEAKS);
			scans.put(repository.getKey().startsWith("policy-clean") ? "clean" : "leaky", scanId);
		}

		finish(startWorker(0, gitleaksWorker(), "--idle-timeout", "3"));
		this.supervisor.runOnce();

		Map<String, String> expected = Map.of("clean", "PASS", "leaky", "FAIL");
		for (Map.Entry<String, UUID> scan : scans.entrySet()) {
			UUID scanId = scan.getValue();
			JsonNode completed = scan(scanId);
			assertThat(completed.get("executionStatus").asString()).isEqualTo("COMPLETED");
			assertThat(completed.get("securityDecision").asString()).as(scan.getKey())
				.isEqualTo(expected.get(scan.getKey()));
			assertThat(completed.get("decisionReason").asString()).isEqualTo("POLICY_EVALUATED");
			JsonNode record = json(this.mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
				.get("/api/v1/scans/{id}/evaluation", scanId)).andExpect(status().isOk()).andReturn());
			ContractSchemas.assertValid("policy-evaluation.schema.json", record);
			assertThat(record.get("policyVersionId").asString()).isEqualTo(version.get("id").asString());
			assertThat(record.get("policySha256").asString()).isEqualTo(version.get("definitionSha256").asString());
			// The record references the verified evidence of record of the real run.
			UUID jobId = this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class,
					scanId);
			EvidenceArtifact artifact = this.evidenceStore.list(jobId).get(0);
			assertThat(record.at("/evidence/0/jobId").asString()).isEqualTo(jobId.toString());
			assertThat(record.at("/evidence/0/sha256").asString()).isEqualTo(artifact.sha256());
			findings(jobId);
		}
		JsonNode leaky = json(this.mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
			.get("/api/v1/scans/{id}/evaluation", scans.get("leaky"))).andReturn());
		assertThat(leaky.at("/reasons/0/code").asString()).isEqualTo("BLOCKING_FINDINGS_EXCEEDED");
		assertThat(leaky.at("/reasons/0/observed").asInt()).isGreaterThanOrEqualTo(1);
		// Reasons are codes and counts only: the synthetic secret is nowhere in the record.
		assertThat(leaky.toString()).doesNotContain(syntheticToken('P'));
		assertThat(json(this.mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
			.get("/api/v1/scans/{id}/evaluation", scans.get("clean"))).andReturn()).get("reasons")).isEmpty();
	}

	private static Path trivyLock() {
		String lock = System.getProperty("sentinel.e2e.trivy-lock", "");
		if (lock.isBlank() || lock.contains("${") || !Files.isRegularFile(Path.of(lock))) {
			throw new IllegalStateException("Run with -Pe2e -Dsentinel.e2e.trivy-lock=<lock of the synthetic"
					+ " Trivy image> (scripts/trivy/build-fixture-db.sh, sentinel-worker trivy-image build)");
		}
		return Path.of(lock).toAbsolutePath();
	}

	private Map<String, String> trivyWorker(Path lock) {
		Map<String, String> env = new HashMap<>();
		env.put("SENTINEL_WORKER_FIXTURE_ENABLED", "false");
		env.put("SENTINEL_WORKER_TRIVY_ENABLED", "true");
		env.put("SENTINEL_WORKER_TRIVY_IMAGE_LOCK", lock.toString());
		env.put("SENTINEL_WORKER_REPOSITORY_FIXTURES_DIR", this.fixtures.toAbsolutePath().toString());
		return env;
	}

	/** package-lock.json v3 with one vulnerable runtime dependency (synthetic advisory). */
	private static String npmLock(String version) {
		return """
				{"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": {
				  "": {"name": "app", "version": "1.0.0", "dependencies": {"sentinelpipe-fixture-vulnerable": "%s"}},
				  "node_modules/sentinelpipe-fixture-vulnerable": {"version": "%s"}}}
				""".formatted(version, version);
	}

	private static final String VULNERABLE_POM = """
			<project><modelVersion>4.0.0</modelVersion><groupId>dev.sentinelpipe.example</groupId>
			<artifactId>app</artifactId><version>1.0.0</version><dependencies><dependency>
			<groupId>dev.sentinelpipe.fixture</groupId><artifactId>vulnerable-parser</artifactId>
			<version>1.4.0</version></dependency></dependencies></project>
			""";

	private UUID jobOf(UUID scanId) {
		return this.jdbcTemplate.queryForObject("SELECT id FROM scan_jobs WHERE scan_id = ?", UUID.class, scanId);
	}

	private UUID organizationOf(UUID scanId) {
		return this.jdbcTemplate.queryForObject(
				"SELECT p.organization_id FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = ?",
				UUID.class, scanId);
	}

	@Test
	void trivyFindsVulnerableDependenciesWithVerifiedProvenanceAndKeepsTenantsApart() throws Exception {
		Path lock = trivyLock();
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		UUID vulnerable = fixtureScan("sca-" + suffix,
				Map.of("web/package-lock.json", npmLock("2.0.0"), "web/package.json", "{}", "svc/pom.xml",
						VULNERABLE_POM,
						// Repository-controlled Trivy configuration must not hide findings.
						".trivyignore", "CVE-2099-0001\nGHSA-2f2f-3g3g-4h4h\n", "trivy.yaml", "severity: [LOW]\n"),
				ScannerType.TRIVY);
		UUID clean = fixtureScan("sca-clean-" + suffix, Map.of("package-lock.json", npmLock("2.0.1")),
				ScannerType.TRIVY);

		String output = finish(startWorker(0, trivyWorker(lock), "--idle-timeout", "3"));

		assertThat(output).contains("scanner.completed");
		UUID vulnerableJob = jobOf(vulnerable);
		UUID cleanJob = jobOf(clean);
		JsonNode document = findings(vulnerableJob);
		assertThat(document.at("/scanner/name").asString()).isEqualTo("trivy");
		assertThat(document.at("/scanner/version").asString()).isEqualTo("0.75.0");
		assertThat(document.at("/context/organization_id").asString())
			.isEqualTo(organizationOf(vulnerable).toString());
		assertThat(document.at("/context/scan_id").asString()).isEqualTo(vulnerable.toString());
		assertThat(document.at("/vulnerability_database/source/kind").asString()).isEqualTo("SYNTHETIC_FIXTURE");
		assertThat(document.at("/vulnerability_database/freshness").asString()).isEqualTo("FRESH");
		assertThat(document.at("/vulnerability_database/schema_version").asInt()).isEqualTo(2);
		List<String> limitations = new java.util.ArrayList<>();
		document.at("/coverage/limitations").forEach((value) -> limitations.add(value.asString()));
		assertThat(limitations).contains("SYNTHETIC_VULNERABILITY_DATABASE", "ADVISORY_DATA_POINT_IN_TIME",
				"REACHABILITY_NOT_ANALYZED", "PARTIAL_DEPENDENCY_RESOLUTION");
		assertThat(document.at("/coverage/complete").asBoolean()).isFalse();
		List<String> located = new java.util.ArrayList<>();
		for (JsonNode finding : document.get("findings")) {
			located.add(finding.at("/location/path").asString() + ":" + finding.get("rule_id").asString() + ":"
					+ finding.at("/package/ecosystem").asString());
			assertThat(finding.get("category").asString()).isEqualTo("DEPENDENCY_VULNERABILITY");
			assertThat(finding.at("/location/target").asString()).isEqualTo("DEPENDENCY_MANIFEST");
			assertThat(finding.at("/evidence/excerpt").isNull()).isTrue();
			assertThat(finding.get("severity").isNull()).as("not mapped onto a normalized scale").isTrue();
		}
		assertThat(located).containsExactlyInAnyOrder("web/package-lock.json:CVE-2099-0001:npm",
				"svc/pom.xml:GHSA-2f2f-3g3g-4h4h:maven");
		// Advisory prose of the synthetic database is never stored anywhere.
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT (SELECT count(*) FROM evidence.objects WHERE position(? IN content) > 0)"
						+ " + (SELECT count(*) FROM lifecycle.job_reports WHERE position(? IN result::text) > 0)",
				Integer.class, "SYNTHETIC SentinelPipe".getBytes(StandardCharsets.UTF_8), "SYNTHETIC SentinelPipe"))
			.isZero();

		JsonNode cleanDocument = findings(cleanJob);
		assertThat(cleanDocument.get("finding_count").asInt()).isZero();
		assertThat(cleanDocument.at("/context/organization_id").asString())
			.isEqualTo(organizationOf(clean).toString())
			.isNotEqualTo(organizationOf(vulnerable).toString());
		// Evidence is stored per tenant: the clean tenant's objects never hold the other's.
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM evidence.objects WHERE organization_id = ? AND position(? IN content) > 0",
				Integer.class, organizationOf(clean), "CVE-2099-0001".getBytes(StandardCharsets.UTF_8)))
			.isZero();

		assertThat(sandboxes(vulnerableJob)).isEmpty();
		assertThat(sandboxes(cleanJob)).isEmpty();
		// Findings are version matches, not a decision: INCOMPLETE until M4, never PASS.
		assertCompletedButNeverPass(vulnerable);
		// The supervisor run above evaluated the clean scan too: completed, still INCOMPLETE.
		JsonNode cleanScan = scan(clean);
		assertThat(cleanScan.get("executionStatus").asString()).isEqualTo("COMPLETED");
		assertThat(cleanScan.get("securityDecision").asString()).isEqualTo("INCOMPLETE");
		assertThat(cleanScan.get("decisionReason").asString()).isEqualTo("POLICY_EVALUATION_UNAVAILABLE");
	}

	@Test
	void aWorkerWithAForgedTrivyLockRefusesToStartAndRunsNoJob() throws Exception {
		JsonNode genuine = this.jsonMapper.readTree(Files.readString(trivyLock()));
		// Everything genuine except the database date (security review S3-2).
		((tools.jackson.databind.node.ObjectNode) genuine.at("/database/metadata"))
			.put("updated_at", "2099-01-01T00:00:00.000000Z")
			.put("next_update", "2099-01-02T00:00:00.000000Z");
		Path forged = Files.createTempFile(this.fixtures, "forged-", ".lock");
		Files.writeString(forged, genuine.toString());
		UUID scanId = fixtureScan("sca-forged-" + UUID.randomUUID().toString().substring(0, 8),
				Map.of("package-lock.json", npmLock("2.0.0")), ScannerType.TRIVY);

		Process worker = startWorker(0, trivyWorker(forged), "--idle-timeout", "3");
		assertThat(worker.waitFor(120, TimeUnit.SECONDS)).isTrue();
		String output = new String(worker.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

		assertThat(worker.exitValue()).as(output).isEqualTo(2);
		assertThat(output).contains("trivy image rejected (METADATA_MISMATCH)");
		assertThat(jobStatus(scanId)).isEqualTo("QUEUED");
		assertThat(this.evidenceStore.list(jobOf(scanId))).isEmpty();
	}

}

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
 * redacted findings are stored as verified evidence without ever producing PASS.
 *
 * <p>
 * Requires {@code -Pe2e -Dsentinel.e2e.python=<python with sentinel-worker installed>}.
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

}

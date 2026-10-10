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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;

/**
 * End-to-end execution lifecycle with the real Python worker process ({@code sentinel-worker
 * execute}, harmless FIXTURE scanner in a real sandbox container, ADR-0009) and its real
 * least-privileged database login:
 * REST request, lease claim, heartbeats, report, supervisor evaluation, REST read; REST
 * cancellation of a running job; and recovery after the worker process is killed.
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

}

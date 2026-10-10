package dev.sentinelpipe.api.e2e;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.messaging.CrashingPublishers;
import dev.sentinelpipe.api.messaging.MessagingTopology;
import dev.sentinelpipe.api.messaging.OutboxPublisher;
import dev.sentinelpipe.api.messaging.OutboxStore;
import io.micrometer.core.instrument.MeterRegistry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.rabbitmq.RabbitMQContainer;
import tools.jackson.databind.JsonNode;

/**
 * End to end across both services: authenticated scan request (Java, PostgreSQL) →
 * transactional outbox → publisher with confirms → RabbitMQ → the real Python worker
 * process → durable receipt (SQLite).
 *
 * <p>
 * Runs only in the {@code e2e} Maven profile and requires
 * {@code -Dsentinel.e2e.python=<python with sentinel-worker installed>}. It fails (never
 * skips) when that interpreter is missing.
 */
class ScanDeliveryE2ETests extends AbstractDomainApiIntegrationTest {

	private static final String WORKER_USER = "sentinel-worker-e2e";

	private static final String WORKER_PASSWORD = "e2e-" + UUID.randomUUID();

	@Autowired
	private RabbitMQContainer rabbit;

	@Autowired
	private ConnectionFactory connectionFactory;

	@Autowired
	private OutboxPublisher publisher;

	@Autowired
	private OutboxStore outboxStore;

	@Autowired
	private RabbitTemplate rabbitTemplate;

	@Autowired
	private MeterRegistry meterRegistry;

	@Autowired
	private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

	private Path receiptDb;

	private static String python() {
		String python = System.getProperty("sentinel.e2e.python", "");
		if (python.isBlank() || python.contains("${")) {
			throw new IllegalStateException(
					"Run with -Pe2e -Dsentinel.e2e.python=<python executable with sentinel-worker installed>");
		}
		return python;
	}

	@BeforeEach
	void prepare() throws Exception {
		this.jdbcTemplate.update("DELETE FROM outbox_events");
		RabbitAdmin admin = new RabbitAdmin(this.connectionFactory);
		admin.purgeQueue(MessagingTopology.SCAN_REQUESTS_QUEUE, false);
		admin.purgeQueue(MessagingTopology.DEAD_LETTER_QUEUE, false);
		admin.purgeQueue(MessagingTopology.RETRY_QUEUE, false);
		// Least-privileged worker user, exactly as documented in docs/runbooks/messaging.md.
		this.rabbit.execInContainer("rabbitmqctl", "delete_user", WORKER_USER);
		assertThat(this.rabbit.execInContainer("rabbitmqctl", "add_user", WORKER_USER, WORKER_PASSWORD).getExitCode())
			.isZero();
		assertThat(this.rabbit
			.execInContainer("rabbitmqctl", "set_permissions", "-p", "/", WORKER_USER, "^$",
					"^sentinel\\.scan-requests\\.(dlx|retry)$", "^sentinel\\.scan-requests\\.worker$")
			.getExitCode()).isZero();
		this.receiptDb = Files.createTempDirectory("sentinel-e2e").resolve("receipts.sqlite3");
	}

	/** Output of a finished worker process. */
	record WorkerRun(int exitCode, String output) {
	}

	private WorkerRun runWorker(int maxMessages) throws Exception {
		ProcessBuilder builder = new ProcessBuilder(python(), "-m", "sentinel_worker", "consume", "--max-messages",
				String.valueOf(maxMessages), "--idle-timeout", "20");
		Map<String, String> env = builder.environment();
		env.put("SENTINEL_WORKER_RABBITMQ_HOST", this.rabbit.getHost());
		env.put("SENTINEL_WORKER_RABBITMQ_PORT", String.valueOf(this.rabbit.getAmqpPort()));
		env.put("SENTINEL_WORKER_RABBITMQ_VHOST", "/");
		env.put("SENTINEL_WORKER_RABBITMQ_USERNAME", WORKER_USER);
		env.put("SENTINEL_WORKER_RABBITMQ_PASSWORD", WORKER_PASSWORD);
		env.put("SENTINEL_WORKER_RECEIPT_DB", this.receiptDb.toString());
		env.put("SENTINEL_WORKER_LOG_LEVEL", "DEBUG");
		builder.redirectErrorStream(true);
		Process process = builder.start();
		String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertThat(process.waitFor(90, TimeUnit.SECONDS)).as("worker finished").isTrue();
		return new WorkerRun(process.exitValue(), output);
	}

	/** Reads receipts with the worker's own interpreter (SQLite from the standard library). */
	private List<JsonNode> receipts() throws IOException, InterruptedException {
		// Single line: Windows process-argument quoting does not preserve newlines.
		String script = "import json, sqlite3, sys; rows = sqlite3.connect(sys.argv[1]).execute("
				+ "'SELECT receipt_json FROM processing_receipts ORDER BY received_at').fetchall(); "
				+ "print(json.dumps([json.loads(r[0]) for r in rows]))";
		Process process = new ProcessBuilder(python(), "-c", script, this.receiptDb.toString())
			.redirectErrorStream(true)
			.start();
		String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
		assertThat(process.waitFor(30, TimeUnit.SECONDS)).isTrue();
		assertThat(process.exitValue()).as(output).isZero();
		List<JsonNode> receipts = new ArrayList<>();
		this.jsonMapper.readTree(output).forEach(receipts::add);
		return receipts;
	}

	private static Map<String, Object> outcomes(WorkerRun run, tools.jackson.databind.json.JsonMapper mapper) {
		String line = run.output()
			.lines()
			.filter((l) -> l.contains("\"event\": \"consumer.stopped\""))
			.reduce((first, second) -> second)
			.orElseThrow(() -> new AssertionError("no consumer.stopped line in worker output:\n" + run.output()));
		return mapper.convertValue(mapper.readTree(line.substring(line.indexOf('{'))).get("outcomes"), Map.class);
	}

	private long workerQueueDepth() {
		return new RabbitAdmin(this.connectionFactory).getQueueInfo(MessagingTopology.SCAN_REQUESTS_QUEUE)
			.getMessageCount();
	}

	@Test
	void anAuthorizedScanRequestReachesTheWorkerAndLeavesADurableReceipt() throws Exception {
		UUID organizationId = createOrganization();
		UUID projectId = createProject(organizationId, "e2e-confidential-repo");
		String sha = randomSha();
		UUID scanId = UUID.fromString(json(requestScan(projectId, sha, "e2e-key")).get("id").asString());
		Map<String, Object> event = this.jdbcTemplate.queryForMap(
				"SELECT id, correlation_id, payload::text AS payload FROM outbox_events WHERE aggregate_id = ?", scanId);

		assertThat(this.publisher.publishBatch().published()).isEqualTo(1);
		WorkerRun run = runWorker(1);

		assertThat(run.exitCode()).as(run.output()).isZero();
		assertThat(outcomes(run, this.jsonMapper)).containsEntry("accepted", 1);
		List<JsonNode> receipts = receipts();
		assertThat(receipts).hasSize(1);
		JsonNode receipt = receipts.getFirst();
		ContractSchemas.assertValidMessage("processing-receipt.v1.schema.json", receipt);
		assertThat(receipt.get("event_id").asString()).isEqualTo(event.get("id").toString());
		assertThat(receipt.get("scan_id").asString()).isEqualTo(scanId.toString());
		assertThat(receipt.get("project_id").asString()).isEqualTo(projectId.toString());
		assertThat(receipt.get("organization_id").asString()).isEqualTo(organizationId.toString());
		assertThat(receipt.get("commit_sha").asString()).isEqualTo(sha);
		assertThat(receipt.get("correlation_id").asString()).isEqualTo(event.get("correlation_id").toString());
		// Byte-exact: the worker hashed exactly the payload committed in the outbox.
		String expectedDigest = HexFormat.of()
			.formatHex(MessageDigest.getInstance("SHA-256")
				.digest(((String) event.get("payload")).getBytes(StandardCharsets.UTF_8)));
		assertThat(receipt.get("message_sha256").asString()).isEqualTo(expectedDigest);
		// A receipt means accepted for processing, not scanned: the scan is still queued.
		assertThat(receipt.get("outcome").asString()).isEqualTo("ACCEPTED");
		this.mockMvc.perform(get("/api/v1/scans/{id}", scanId))
			.andExpect(jsonPath("$.executionStatus").value("QUEUED"))
			.andExpect(jsonPath("$.securityDecision").value("PENDING"));
		assertThat(workerQueueDepth()).isZero();
		// Worker logs contain identifiers only: no credentials, no payload content.
		assertThat(run.output()).contains(event.get("id").toString())
			.doesNotContain(WORKER_PASSWORD)
			.doesNotContain("e2e-confidential-repo");
	}

	@Test
	void aPublisherCrashAfterTheBrokerConfirmCausesADuplicateThatTheWorkerAbsorbs() throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(createProject(), randomSha(), null)).get("id").asString());
		UUID eventId = this.jdbcTemplate.queryForObject("SELECT id FROM outbox_events WHERE aggregate_id = ?",
				UUID.class, scanId);
		// First publication is confirmed by the broker, but the outbox row is never marked.
		assertThatThrownBy(() -> CrashingPublishers
			.crashAfterBrokerConfirm(this.namedParameterJdbcTemplate, this.rabbitTemplate, this.meterRegistry,
					this.outboxStore)
			.publishBatch()).isInstanceOf(CrashingPublishers.SimulatedCrash.class);
		assertThat(this.jdbcTemplate.queryForObject("SELECT status FROM outbox_events WHERE id = ?", String.class,
				eventId))
			.isEqualTo("PENDING");
		this.jdbcTemplate.update("UPDATE outbox_events SET lease_expires_at = now() - interval '1 second' WHERE id = ?",
				eventId);
		assertThat(this.publisher.publishBatch().published()).isEqualTo(1);
		assertThat(workerQueueDepth()).isEqualTo(2);

		WorkerRun run = runWorker(2);

		assertThat(run.exitCode()).as(run.output()).isZero();
		assertThat(outcomes(run, this.jsonMapper)).containsEntry("accepted", 1).containsEntry("duplicate", 1);
		assertThat(receipts()).hasSize(1);
		assertThat(workerQueueDepth()).isZero();
	}

	@Test
	void theTestFailsInsteadOfSkippingWithoutAWorkerInterpreter() {
		String previous = System.getProperty("sentinel.e2e.python");
		System.clearProperty("sentinel.e2e.python");
		try {
			assertThatThrownBy(ScanDeliveryE2ETests::python).isInstanceOf(IllegalStateException.class);
		}
		finally {
			if (previous != null) {
				System.setProperty("sentinel.e2e.python", previous);
			}
		}
	}

}

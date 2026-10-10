package dev.sentinelpipe.api.e2e;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.DatabaseRoles;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.messaging.CrashingPublishers;
import dev.sentinelpipe.api.messaging.MessagingTopology;
import dev.sentinelpipe.api.messaging.OutboxPublisher;
import dev.sentinelpipe.api.messaging.OutboxStore;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
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
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.rabbitmq.RabbitMQContainer;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;

/**
 * End to end across both services: authenticated scan request (Java, PostgreSQL) →
 * transactional outbox → publisher with confirms → RabbitMQ → the real Python worker
 * process → shared receipt in PostgreSQL ({@code worker.processing_receipts}), verified
 * by the database against the committed outbox event.
 * <p>
 * Broker users and database logins come from the production provisioning scripts
 * (rabbitmq/provision.sh, postgres/provision-roles.sh): the API runs as the
 * least-privileged API login, and the worker and operator as members of the
 * {@code sentinel_worker} and {@code sentinel_operator} group roles.
 *
 * <p>
 * Runs only in the {@code e2e} Maven profile and requires
 * {@code -Dsentinel.e2e.python=<python with sentinel-worker installed>}. It fails (never
 * skips) when that interpreter is missing.
 */
class ScanDeliveryE2ETests extends AbstractDomainApiIntegrationTest {

	private static final String WORKER_USER = "sentinel-worker";

	private static final String OPERATOR_USER = "sentinel-operator";

	// No leading "-": rabbitmqctl would parse such an argument as an option.
	private static final String WORKER_PASSWORD = "e2e" + UUID.randomUUID().toString().replace("-", "");

	private static final String OPERATOR_PASSWORD = "e2o" + UUID.randomUUID().toString().replace("-", "");

	// Database logins created by the production provisioning script (DatabaseRoles).
	private static final String WORKER_DB_USER = DatabaseRoles.WORKER_USER;

	private static final String OPERATOR_DB_USER = DatabaseRoles.OPERATOR_USER;

	private static final Path RABBITMQ_PROVISIONING = Path.of("..", "..", "infrastructure", "docker", "rabbitmq")
		.toAbsolutePath()
		.normalize();

	@Autowired
	private RabbitMQContainer rabbit;

	@Autowired
	private PostgreSQLContainer postgres;

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
		// Least-privileged broker users from the production provisioning script.
		for (String file : new String[] { "provision.sh", "definitions.json" }) {
			this.rabbit.copyFileToContainer(MountableFile.forHostPath(RABBITMQ_PROVISIONING.resolve(file)),
					"/etc/sentinelpipe/rabbitmq/" + file);
		}
		ExecResult provisioned = this.rabbit.execInContainer("sh", "-c",
				"SENTINEL_RABBITMQ_PUBLISHER_PASSWORD=p" + WORKER_PASSWORD + " SENTINEL_WORKER_RABBITMQ_PASSWORD="
						+ WORKER_PASSWORD + " SENTINEL_OPERATOR_RABBITMQ_PASSWORD=" + OPERATOR_PASSWORD
						+ " sh /etc/sentinelpipe/rabbitmq/provision.sh");
		assertThat(provisioned.getExitCode()).as("provision.sh").isZero();
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
		env.put("SENTINEL_WORKER_RECEIPT_BACKEND", "postgres");
		env.put("SENTINEL_WORKER_DB_HOST", this.postgres.getHost());
		env.put("SENTINEL_WORKER_DB_PORT", String.valueOf(this.postgres.getMappedPort(5432)));
		env.put("SENTINEL_WORKER_DB_NAME", this.postgres.getDatabaseName());
		env.put("SENTINEL_WORKER_DB_USERNAME", WORKER_DB_USER);
		env.put("SENTINEL_WORKER_DB_PASSWORD", DatabaseRoles.WORKER_PASSWORD);
		env.put("SENTINEL_WORKER_DB_SSLMODE", "disable");
		env.put("SENTINEL_WORKER_ENVIRONMENT", "ci");
		env.put("SENTINEL_WORKER_LOG_LEVEL", "DEBUG");
		builder.redirectErrorStream(true);
		Process process = builder.start();
		String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertThat(process.waitFor(90, TimeUnit.SECONDS)).as("worker finished").isTrue();
		return new WorkerRun(process.exitValue(), output);
	}

	/** Receipts for the given events, read from the shared PostgreSQL store. */
	private List<JsonNode> receipts(Object... eventIds) {
		List<JsonNode> receipts = new ArrayList<>();
		for (Object eventId : eventIds) {
			this.jdbcTemplate
				.queryForList("SELECT receipt::text FROM worker.processing_receipts WHERE event_id = ?::uuid",
						String.class, eventId.toString())
				.forEach((json) -> receipts.add(this.jsonMapper.readTree(json)));
		}
		return receipts;
	}

	/** Runs an operator command of the worker CLI with the operator identities. */
	private WorkerRun runOperator(String... arguments) throws Exception {
		List<String> command = new ArrayList<>(List.of(python(), "-m", "sentinel_worker"));
		command.addAll(List.of(arguments));
		ProcessBuilder builder = new ProcessBuilder(command);
		Map<String, String> env = builder.environment();
		env.put("SENTINEL_OPERATOR_RABBITMQ_HOST", this.rabbit.getHost());
		env.put("SENTINEL_OPERATOR_RABBITMQ_PORT", String.valueOf(this.rabbit.getAmqpPort()));
		env.put("SENTINEL_OPERATOR_RABBITMQ_USERNAME", OPERATOR_USER);
		env.put("SENTINEL_OPERATOR_RABBITMQ_PASSWORD", OPERATOR_PASSWORD);
		env.put("SENTINEL_OPERATOR_DB_HOST", this.postgres.getHost());
		env.put("SENTINEL_OPERATOR_DB_PORT", String.valueOf(this.postgres.getMappedPort(5432)));
		env.put("SENTINEL_OPERATOR_DB_NAME", this.postgres.getDatabaseName());
		env.put("SENTINEL_OPERATOR_DB_USERNAME", OPERATOR_DB_USER);
		env.put("SENTINEL_OPERATOR_DB_PASSWORD", DatabaseRoles.OPERATOR_PASSWORD);
		env.put("SENTINEL_WORKER_DB_SSLMODE", "disable");
		env.put("SENTINEL_WORKER_ENVIRONMENT", "ci");
		builder.redirectErrorStream(true);
		Process process = builder.start();
		String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertThat(process.waitFor(60, TimeUnit.SECONDS)).as("operator command finished").isTrue();
		return new WorkerRun(process.exitValue(), output);
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
		List<JsonNode> receipts = receipts(event.get("id"));
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
		// The database stored the authoritative relationships, not the payload's claims.
		assertThat(this.jdbcTemplate.queryForMap(
				"SELECT organization_id, scan_id FROM worker.processing_receipts WHERE event_id = ?", event.get("id")))
			.containsEntry("organization_id", organizationId)
			.containsEntry("scan_id", scanId);
		// Worker logs contain identifiers only: no credentials, no payload content.
		assertThat(run.output()).contains(event.get("id").toString())
			.doesNotContain(WORKER_PASSWORD)
			.doesNotContain(DatabaseRoles.WORKER_PASSWORD)
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
		assertThat(receipts(eventId)).hasSize(1);
		assertThat(workerQueueDepth()).isZero();
	}

	@Test
	void aMessageForgedWithoutTheControlPlaneIsDeadLetteredAndNeverAccepted() throws Exception {
		// A genuine event, altered by someone with broker write access.
		UUID scanId = UUID.fromString(json(requestScan(createProject(), randomSha(), null)).get("id").asString());
		Map<String, Object> genuine = this.jdbcTemplate
			.queryForMap("SELECT id, payload::text AS payload FROM outbox_events WHERE aggregate_id = ?", scanId);
		String forgedBody = ((String) genuine.get("payload")).replace("\"branch\": \"main\"",
				"\"branch\": \"attacker\"");
		assertThat(forgedBody).isNotEqualTo(genuine.get("payload"));
		this.rabbitTemplate.send(MessagingTopology.SCAN_REQUESTS_EXCHANGE, MessagingTopology.SCAN_REQUESTED_ROUTING_KEY,
				scanRequestedMessage(genuine.get("id").toString(), forgedBody));

		WorkerRun run = runWorker(1);

		assertThat(run.exitCode()).as(run.output()).isZero();
		assertThat(outcomes(run, this.jsonMapper)).containsEntry("dead_lettered", 1);
		assertThat(receipts(genuine.get("id"))).isEmpty();
		assertThat(run.output()).contains("DIGEST_MISMATCH");
		assertThat(this.jdbcTemplate.queryForObject("SELECT reason FROM worker.delivery_rejections WHERE event_id = ?",
				String.class, genuine.get("id")))
			.isEqualTo("DIGEST_MISMATCH");
	}

	@Test
	void anAuditedDeadLetterReplayThroughTheOperatorCliIsReprocessed() throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(createProject(), randomSha(), null)).get("id").asString());
		Map<String, Object> event = this.jdbcTemplate
			.queryForMap("SELECT id, payload::text AS payload FROM outbox_events WHERE aggregate_id = ?", scanId);
		// As after a long database outage: the genuine message sits in the dead-letter queue.
		this.rabbitTemplate.send(MessagingTopology.DEAD_LETTER_EXCHANGE, "",
				scanRequestedMessage(event.get("id").toString(), (String) event.get("payload")));

		WorkerRun replay = runOperator("dlq-replay", "--operator", "e2e-operator", "--reason", "E2E replay",
				"--max-messages", "5");

		assertThat(replay.exitCode()).as(replay.output()).isZero();
		assertThat(this.jsonMapper.readTree(replay.output()).get("replayed").asInt()).isEqualTo(1);
		assertThat(replay.output()).doesNotContain(OPERATOR_PASSWORD).doesNotContain(DatabaseRoles.OPERATOR_PASSWORD);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT operator FROM ops.recovery_actions WHERE action = 'DEAD_LETTER_REPLAY' AND event_id = ?",
				String.class, event.get("id")))
			.isEqualTo("e2e-operator");
		WorkerRun run = runWorker(1);
		assertThat(outcomes(run, this.jsonMapper)).containsEntry("accepted", 1);
		assertThat(receipts(event.get("id"))).hasSize(1);
	}

	private static Message scanRequestedMessage(String eventId, String body) {
		return MessageBuilder.withBody(body.getBytes(StandardCharsets.UTF_8))
			.setContentType("application/json")
			.setMessageId(eventId)
			.setType("scan.requested.v1")
			.build();
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

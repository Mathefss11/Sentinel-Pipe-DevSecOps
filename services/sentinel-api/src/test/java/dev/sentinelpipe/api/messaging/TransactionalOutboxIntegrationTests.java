package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.scan.ScanService;
import dev.sentinelpipe.api.scan.TriggerType;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;

/** Scan creation and outbox event creation are one atomic unit. */
class TransactionalOutboxIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private JdbcTemplate applicationJdbc;

	@Autowired
	private ScanService scanService;

	@Autowired
	private PlatformTransactionManager transactionManager;

	private List<Map<String, Object>> eventsFor(UUID scanId) {
		return this.jdbcTemplate.queryForList("SELECT * FROM outbox_events WHERE aggregate_id = ?", scanId);
	}

	private int eventsForProject(UUID projectId) {
		return this.jdbcTemplate.queryForObject("""
				SELECT count(*) FROM outbox_events o JOIN scans s ON s.id = o.aggregate_id WHERE s.project_id = ?
				""", Integer.class, projectId);
	}

	private JsonNode payloadOf(UUID scanId) throws Exception {
		return this.jsonMapper.readTree(this.jdbcTemplate.queryForObject(
				"SELECT payload::text FROM outbox_events WHERE aggregate_id = ?", String.class, scanId));
	}

	@Test
	void scanRequestAppendsOneContractValidEventFromServerSideState() throws Exception {
		UUID organizationId = createOrganization();
		UUID projectId = createProject(organizationId, "outbox-repo");
		String sha = randomSha();

		JsonNode scan = json(requestScan(projectId, sha, null));
		UUID scanId = UUID.fromString(scan.get("id").asString());

		List<Map<String, Object>> events = eventsFor(scanId);
		assertThat(events).hasSize(1);
		Map<String, Object> event = events.getFirst();
		assertThat(event).containsEntry("event_type", "scan.requested")
			.containsEntry("schema_version", 1)
			.containsEntry("aggregate_type", "scan")
			.containsEntry("organization_id", organizationId)
			.containsEntry("status", "PENDING")
			.containsEntry("attempts", 0);
		assertThat(event.get("published_at")).isNull();

		JsonNode payload = payloadOf(scanId);
		ContractSchemas.assertValidMessage("scan-requested.v1.schema.json", payload);
		assertThat(payload.get("event_id").asString()).isEqualTo(event.get("id").toString());
		assertThat(payload.get("correlation_id").asString()).isEqualTo(event.get("correlation_id").toString());
		assertThat(payload.get("scan_id").asString()).isEqualTo(scanId.toString());
		assertThat(payload.get("project_id").asString()).isEqualTo(projectId.toString());
		assertThat(payload.get("organization_id").asString()).isEqualTo(organizationId.toString());
		assertThat(payload.get("commit_sha").asString()).isEqualTo(sha);
		assertThat(payload.get("occurred_at").asString()).isEqualTo(scan.get("requestedAt").asString());
		assertThat(payload.get("repository").get("name").asString()).isEqualTo("outbox-repo");
	}

	@Test
	void payloadContainsNoCredentialsOrUserIdentity() throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(createProject(), randomSha(), null)).get("id").asString());

		String payload = payloadOf(scanId).toString();
		assertThat(payload).doesNotContain(TestJwts.PLATFORM_ADMIN, TestJwts.ISSUER, "Bearer", "token", "password",
				"subject");
	}

	@Test
	void idempotentReplaysDoNotAppendEvents() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();

		UUID first = UUID.fromString(json(requestScan(projectId, sha, "outbox-replay")).get("id").asString());
		requestScan(projectId, sha, "outbox-replay");
		requestScan(projectId, sha, "outbox-replay");

		assertThat(eventsFor(first)).hasSize(1);
		assertThat(eventsForProject(projectId)).isEqualTo(1);
	}

	@Test
	void concurrentRetriesWithOneKeyAppendExactlyOneEvent() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();
		int threads = 8;
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<UUID>> attempts = new ArrayList<>();
		for (int i = 0; i < threads; i++) {
			attempts.add(() -> {
				start.await();
				return this.scanService.requestScan(projectId, sha, "main", TriggerType.PUSH, "outbox-race")
					.details()
					.scan()
					.getId();
			});
		}
		Set<UUID> scanIds = new HashSet<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(threads)) {
			List<Future<UUID>> futures = attempts.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<UUID> future : futures) {
				scanIds.add(future.get());
			}
		}

		assertThat(scanIds).hasSize(1);
		assertThat(eventsForProject(projectId)).isEqualTo(1);
	}

	@Test
	void concurrentDistinctRequestsAppendOneEventEach() throws Exception {
		UUID projectId = createProject();
		int threads = 8;
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<UUID>> requests = new ArrayList<>();
		for (int i = 0; i < threads; i++) {
			String sha = randomSha();
			requests.add(() -> {
				start.await();
				return this.scanService.requestScan(projectId, sha, "main", TriggerType.PUSH, null)
					.details()
					.scan()
					.getId();
			});
		}
		try (ExecutorService executor = Executors.newFixedThreadPool(threads)) {
			List<Future<UUID>> futures = requests.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<UUID> future : futures) {
				assertThat(eventsFor(future.get())).hasSize(1);
			}
		}

		assertThat(eventsForProject(projectId)).isEqualTo(threads);
	}

	@Test
	void rollingBackTheScanTransactionDiscardsTheEventToo() throws Exception {
		UUID projectId = createProject();
		TransactionTemplate outer = new TransactionTemplate(this.transactionManager);

		UUID scanId = outer.execute((status) -> {
			UUID id = this.scanService.requestScan(projectId, randomSha(), "main", TriggerType.PUSH, null)
				.details()
				.scan()
				.getId();
			// Both rows exist inside the transaction (read through the application's own,
			// transaction-bound connection; the fixture connection cannot see them) ...
			assertThat(this.applicationJdbc.queryForObject("SELECT count(*) FROM outbox_events WHERE aggregate_id = ?",
					Integer.class, id))
				.isEqualTo(1);
			status.setRollbackOnly();
			return id;
		});

		// ... and neither survives the rollback.
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans WHERE id = ?", Integer.class, scanId))
			.isZero();
		assertThat(eventsFor(scanId)).isEmpty();
	}

	@Test
	void rejectedScanRequestsAppendNoEvent() throws Exception {
		UUID projectId = createProject();
		this.jdbcTemplate.update("UPDATE projects SET enabled = false WHERE id = ?", projectId);

		assertThat(requestScan(projectId, randomSha(), null).getResponse().getStatus()).isEqualTo(409);
		String viewer = uniqueSubject("viewer");
		UUID organizationId = this.jdbcTemplate.queryForObject("SELECT organization_id FROM projects WHERE id = ?",
				UUID.class, projectId);
		grant(organizationId, viewer, "VIEWER");
		this.jdbcTemplate.update("UPDATE projects SET enabled = true WHERE id = ?", projectId);
		this.mockMvc
			.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
				.post("/api/v1/projects/{id}/scans", projectId)
				.header(org.springframework.http.HttpHeaders.AUTHORIZATION, TestJwts.bearer(viewer))
				.contentType(org.springframework.http.MediaType.APPLICATION_JSON)
				.content("{\"commitSha\": \"%s\", \"branch\": \"main\", \"triggerType\": \"PUSH\"}"
					.formatted(randomSha())))
			.andReturn();

		assertThat(eventsForProject(projectId)).isZero();
	}

	@Test
	void databaseRejectsASecondEventOfTheSameTypeForOneScan() throws Exception {
		UUID scanId = UUID.fromString(json(requestScan(createProject(), randomSha(), null)).get("id").asString());

		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO outbox_events (id, event_type, schema_version, aggregate_type, aggregate_id,
				    organization_id, correlation_id, payload, status, next_attempt_at, created_at, updated_at)
				SELECT gen_random_uuid(), event_type, schema_version, aggregate_type, aggregate_id,
				    organization_id, correlation_id, payload, 'PENDING', now(), now(), now()
				FROM outbox_events WHERE aggregate_id = ?
				""", scanId))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_outbox_events_aggregate_event_type");
	}

	@Test
	void eventsCarryTheOwningOrganizationOfTheirProject() throws Exception {
		UUID orgA = createOrganization();
		UUID orgB = createOrganization();
		UUID scanA = UUID.fromString(json(requestScan(createProject(orgA, "a"), randomSha(), null)).get("id").asString());
		UUID scanB = UUID.fromString(json(requestScan(createProject(orgB, "b"), randomSha(), null)).get("id").asString());

		assertThat(payloadOf(scanA).get("organization_id").asString()).isEqualTo(orgA.toString());
		assertThat(payloadOf(scanB).get("organization_id").asString()).isEqualTo(orgB.toString());
	}

}

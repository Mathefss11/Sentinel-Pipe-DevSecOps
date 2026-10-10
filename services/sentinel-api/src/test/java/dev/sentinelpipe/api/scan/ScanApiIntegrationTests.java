package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.common.IdempotencyKeyReuseException;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

class ScanApiIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	private int countScans(UUID projectId) {
		return this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans WHERE project_id = ?", Integer.class,
				projectId);
	}

	@Test
	void queuesScanWith202AndPendingDecision() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();

		MvcResult result = this.mockMvc
			.perform(post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"commitSha": "%s", "branch": "feature/login", "triggerType": "PULL_REQUEST"}
						""".formatted(sha.toUpperCase())))
			.andExpect(status().isAccepted())
			.andExpect(jsonPath("$.projectId").value(projectId.toString()))
			.andExpect(jsonPath("$.commitSha").value(sha))
			.andExpect(jsonPath("$.branch").value("feature/login"))
			.andExpect(jsonPath("$.triggerType").value("PULL_REQUEST"))
			.andExpect(jsonPath("$.executionStatus").value("QUEUED"))
			.andExpect(jsonPath("$.securityDecision").value("PENDING"))
			.andExpect(jsonPath("$.startedAt").isEmpty())
			.andExpect(jsonPath("$.completedAt").isEmpty())
			.andExpect(jsonPath("$.jobs").isEmpty())
			.andReturn();
		String id = json(result).get("id").asString();

		assertThat(result.getResponse().getHeader("Location")).isEqualTo("/api/v1/scans/" + id);
		assertThat(result.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("false");
		this.mockMvc.perform(get("/api/v1/scans/{id}", id))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.executionStatus").value("QUEUED"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "abc123", "4f2c8e1", "HEAD", "main", "not-a-sha-not-a-sha-not-a-sha-not-a-sha!" })
	void rejectsInvalidCommitShas(String sha) throws Exception {
		UUID projectId = createProject();
		this.mockMvc.perform(post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"commitSha": "%s", "branch": "main", "triggerType": "PUSH"}
					""".formatted(sha)))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[0].field").value("commitSha"));
		assertThat(countScans(projectId)).isZero();
	}

	@Test
	void rejectsInvalidBranchesAndMissingFields() throws Exception {
		UUID projectId = createProject();
		this.mockMvc.perform(post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"commitSha": "%s", "branch": "refs/heads/main", "triggerType": "PUSH"}
					""".formatted(randomSha())))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[0].field").value("branch"));
		this.mockMvc.perform(post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
			.content("{}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors.length()").value(3));
	}

	@Test
	void clientsCannotSupplyStatusDecisionOrIdentifiers() throws Exception {
		UUID projectId = createProject();
		this.mockMvc.perform(post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"commitSha": "%s", "branch": "main", "triggerType": "PUSH",
					 "executionStatus": "COMPLETED", "securityDecision": "PASS"}
					""".formatted(randomSha())))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:malformed-request"));
		assertThat(countScans(projectId)).isZero();
	}

	@Test
	void scanOfUnknownProjectIsNotFound() throws Exception {
		this.mockMvc.perform(post("/api/v1/projects/{id}/scans", UUID.randomUUID())
			.contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"commitSha": "%s", "branch": "main", "triggerType": "PUSH"}
					""".formatted(randomSha())))
			.andExpect(status().isNotFound());
		this.mockMvc.perform(get("/api/v1/scans/{id}", UUID.randomUUID())).andExpect(status().isNotFound());
	}

	@Test
	void disabledProjectDoesNotAcceptScans() throws Exception {
		UUID projectId = createProject();
		this.jdbcTemplate.update("UPDATE projects SET enabled = false WHERE id = ?", projectId);

		MvcResult result = requestScan(projectId, randomSha(), null);

		assertThat(result.getResponse().getStatus()).isEqualTo(409);
		assertThat(json(result).get("code").asString()).isEqualTo("project-disabled");
		assertThat(countScans(projectId)).isZero();
	}

	@Test
	void requestsWithoutIdempotencyKeyAlwaysCreateNewScans() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();

		requestScan(projectId, sha, null);
		requestScan(projectId, sha, null);

		assertThat(countScans(projectId)).isEqualTo(2);
	}

	@Test
	void retryWithSameIdempotencyKeyReplaysTheOriginalScan() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();

		MvcResult first = requestScan(projectId, sha, "gh-run-1-attempt-1");
		MvcResult retry = requestScan(projectId, sha.toUpperCase(), "gh-run-1-attempt-1");

		assertThat(first.getResponse().getStatus()).isEqualTo(202);
		assertThat(retry.getResponse().getStatus()).isEqualTo(202);
		assertThat(json(retry).get("id")).isEqualTo(json(first).get("id"));
		assertThat(retry.getResponse().getHeader("Location")).isEqualTo(first.getResponse().getHeader("Location"));
		assertThat(retry.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("true");
		assertThat(countScans(projectId)).isEqualTo(1);
	}

	@Test
	void reusingAnIdempotencyKeyForADifferentRequestIsRejected() throws Exception {
		UUID projectId = createProject();
		requestScan(projectId, randomSha(), "key-1");

		MvcResult conflicting = requestScan(projectId, randomSha(), "key-1");

		assertThat(conflicting.getResponse().getStatus()).isEqualTo(422);
		assertThat(json(conflicting).get("type").asString())
			.isEqualTo("urn:sentinelpipe:problem:idempotency-key-reused");
		assertThat(countScans(projectId)).isEqualTo(1);
	}

	@Test
	void idempotencyKeysAreScopedPerProject() throws Exception {
		UUID first = createProject();
		UUID second = createProject();
		String sha = randomSha();

		MvcResult a = requestScan(first, sha, "shared-key");
		MvcResult b = requestScan(second, sha, "shared-key");

		assertThat(a.getResponse().getStatus()).isEqualTo(202);
		assertThat(b.getResponse().getStatus()).isEqualTo(202);
		assertThat(json(a).get("id")).isNotEqualTo(json(b).get("id"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "has space", "semi;colon", "slash/key", "ünïcode" })
	void rejectsMalformedIdempotencyKeys(String key) throws Exception {
		UUID projectId = createProject();

		this.mockMvc.perform(post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
			.header("Idempotency-Key", key)
			.content("""
					{"commitSha": "%s", "branch": "main", "triggerType": "PUSH"}
					""".formatted(randomSha())))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[0].field").value("Idempotency-Key"));
		assertThat(countScans(projectId)).isZero();
	}

	@Test
	void rejectsOverlongIdempotencyKeys() throws Exception {
		UUID projectId = createProject();

		assertThat(requestScan(projectId, randomSha(), "k".repeat(129)).getResponse().getStatus()).isEqualTo(400);
		assertThat(requestScan(projectId, randomSha(), "k".repeat(128)).getResponse().getStatus()).isEqualTo(202);
	}

	@Test
	void concurrentRetriesWithTheSameKeyCreateExactlyOneScan() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();
		int threads = 10;
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<UUID>> attempts = new ArrayList<>();
		for (int i = 0; i < threads; i++) {
			attempts.add(() -> {
				start.await();
				return this.scanService.requestScan(projectId, sha, "main", TriggerType.PUSH, "concurrent-key")
					.details()
					.scan()
					.getId();
			});
		}

		Set<UUID> ids = new HashSet<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(threads)) {
			List<Future<UUID>> futures = attempts.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<UUID> future : futures) {
				ids.add(future.get());
			}
		}

		assertThat(ids).hasSize(1);
		assertThat(countScans(projectId)).isEqualTo(1);
	}

	@Test
	void concurrentConflictingRequestsWithTheSameKeyNeverCreateTwoScans() throws Exception {
		UUID projectId = createProject();
		int threads = 6;
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<UUID>> attempts = new ArrayList<>();
		for (int i = 0; i < threads; i++) {
			String sha = randomSha();
			attempts.add(() -> {
				start.await();
				return this.scanService.requestScan(projectId, sha, "main", TriggerType.PUSH, "contested-key")
					.details()
					.scan()
					.getId();
			});
		}

		int succeeded = 0;
		int rejected = 0;
		try (ExecutorService executor = Executors.newFixedThreadPool(threads)) {
			List<Future<UUID>> futures = attempts.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<UUID> future : futures) {
				try {
					future.get();
					succeeded++;
				}
				catch (ExecutionException ex) {
					assertThat(ex.getCause()).isInstanceOf(IdempotencyKeyReuseException.class);
					rejected++;
				}
			}
		}

		assertThat(succeeded).isEqualTo(1);
		assertThat(rejected).isEqualTo(threads - 1);
		assertThat(countScans(projectId)).isEqualTo(1);
	}

	@Test
	void scanResponseIncludesPlannedJobs() throws Exception {
		UUID projectId = createProject();
		UUID scanId = UUID.fromString(json(requestScan(projectId, randomSha(), null)).get("id").asString());
		this.lifecycle.planJob(scanId, ScannerType.SEMGREP);
		this.lifecycle.planJob(scanId, ScannerType.GITLEAKS);

		this.mockMvc.perform(get("/api/v1/scans/{id}", scanId))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.jobs.length()").value(2))
			.andExpect(jsonPath("$.jobs[0].scannerType").value("GITLEAKS"))
			.andExpect(jsonPath("$.jobs[0].scanId").value(scanId.toString()))
			.andExpect(jsonPath("$.jobs[0].executionStatus").value("QUEUED"))
			.andExpect(jsonPath("$.jobs[0].attemptCount").value(0))
			.andExpect(jsonPath("$.jobs[1].scannerType").value("SEMGREP"));
	}

	@Test
	void listsScansNewestFirstWithPagination() throws Exception {
		UUID projectId = createProject();
		List<String> ids = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			ids.add(json(requestScan(projectId, randomSha(), null)).get("id").asString());
		}
		this.lifecycle.planJob(UUID.fromString(ids.get(2)), ScannerType.TRIVY);

		this.mockMvc.perform(get("/api/v1/projects/{id}/scans", projectId).param("size", "2"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.items.length()").value(2))
			.andExpect(jsonPath("$.items[0].id").value(ids.get(2)))
			.andExpect(jsonPath("$.items[0].jobs[0].scannerType").value("TRIVY"))
			.andExpect(jsonPath("$.items[1].id").value(ids.get(1)))
			.andExpect(jsonPath("$.items[1].jobs").isEmpty())
			.andExpect(jsonPath("$.page.totalElements").value(3))
			.andExpect(jsonPath("$.page.totalPages").value(2));
		this.mockMvc.perform(get("/api/v1/projects/{id}/scans", projectId).param("page", "1").param("size", "2"))
			.andExpect(jsonPath("$.items.length()").value(1))
			.andExpect(jsonPath("$.items[0].id").value(ids.get(0)));
		this.mockMvc.perform(get("/api/v1/projects/{id}/scans", projectId).param("size", "101"))
			.andExpect(status().isBadRequest());
		this.mockMvc.perform(get("/api/v1/projects/{id}/scans", UUID.randomUUID())).andExpect(status().isNotFound());
	}

	@Test
	void noPublicEndpointChangesScanState() throws Exception {
		UUID projectId = createProject();
		String id = json(requestScan(projectId, randomSha(), null)).get("id").asString();

		for (var request : List.of(
				org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/api/v1/scans/{id}", id),
				org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/api/v1/scans/{id}", id),
				org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/api/v1/scans/{id}", id),
				post("/api/v1/scans/{id}/complete", id), post("/api/v1/scans/{id}/jobs", id))) {
			int status = this.mockMvc.perform(request.contentType(MediaType.APPLICATION_JSON).content("{}"))
				.andReturn()
				.getResponse()
				.getStatus();
			assertThat(status).isIn(404, 405);
		}
		this.mockMvc.perform(get("/api/v1/scans/{id}", id)).andExpect(jsonPath("$.executionStatus").value("QUEUED"));
	}

	@Test
	void serviceRejectsInvalidInputEvenWithoutTheRestLayer() {
		assertThatThrownBy(() -> this.scanService.requestScan(UUID.randomUUID(), "abc", "main", TriggerType.PUSH, null))
			.isInstanceOf(dev.sentinelpipe.api.common.DomainValidationException.class);
		assertThatThrownBy(
				() -> this.scanService.requestScan(UUID.randomUUID(), randomSha(), "main", TriggerType.PUSH, "bad key"))
			.isInstanceOf(dev.sentinelpipe.api.common.DomainValidationException.class);
	}

}

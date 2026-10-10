package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Idempotency-Key expiry against real PostgreSQL: replay inside the retention window,
 * expiry at the boundary, lazy release on reuse, bounded cleanup, and concurrency between
 * cleanup and request creation. Scans are aged by moving {@code requested_at} back.
 */
class IdempotencyKeyLifecycleIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanService scanService;

	@Autowired
	private IdempotencyKeyCleanup cleanup;

	@Autowired
	private IdempotencyProperties properties;

	@Autowired
	private NamedParameterJdbcTemplate namedJdbc;

	@Autowired
	private PlatformTransactionManager transactionManager;

	private UUID requestWithKey(UUID projectId, String sha, String key) throws Exception {
		MvcResult result = requestScan(projectId, sha, key);
		assertThat(result.getResponse().getStatus()).isIn(200, 202);
		return UUID.fromString(json(result).get("id").asString());
	}

	private void age(UUID scanId, Duration by) {
		this.jdbcTemplate.update("UPDATE scans SET requested_at = requested_at - make_interval(secs => ?) WHERE id = ?",
				(double) by.toMillis() / 1000, scanId);
	}

	private String keyOf(UUID scanId) {
		return this.jdbcTemplate.queryForObject("SELECT idempotency_key FROM scans WHERE id = ?", String.class, scanId);
	}

	private long outboxEvents(UUID scanId) {
		return this.jdbcTemplate.queryForObject("SELECT count(*) FROM outbox_events WHERE aggregate_id = ?", Long.class,
				scanId);
	}

	@Test
	void theDefaultRetentionIsDocumentedAndValid() {
		assertThat(this.properties.getRetention()).isEqualTo(Duration.ofHours(24));
		this.properties.validate();
	}

	@Test
	void aKeyReplaysItsScanInsideTheRetentionWindow() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();
		UUID first = requestWithKey(projectId, sha, "within-window");
		age(first, this.properties.getRetention().minusMinutes(5));

		MvcResult replay = requestScan(projectId, sha, "within-window");

		assertThat(replay.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("true");
		assertThat(json(replay).get("id").asString()).isEqualTo(first.toString());
	}

	@Test
	void anExpiredKeyCreatesANewScanAndKeepsTheOldScanAndItsEvidence() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();
		UUID old = requestWithKey(projectId, sha, "expired-key");
		age(old, this.properties.getRetention().plusSeconds(1));

		MvcResult reuse = requestScan(projectId, sha, "expired-key");

		assertThat(reuse.getResponse().getStatus()).isEqualTo(202);
		assertThat(reuse.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("false");
		UUID fresh = UUID.fromString(json(reuse).get("id").asString());
		assertThat(fresh).isNotEqualTo(old);
		// The key moved to the new scan; the old scan and its outbox event are untouched.
		assertThat(keyOf(fresh)).isEqualTo("expired-key");
		assertThat(keyOf(old)).isNull();
		assertThat(outboxEvents(old)).isEqualTo(1);
		assertThat(outboxEvents(fresh)).isEqualTo(1);
	}

	@Test
	void anExpiredKeyMayBeReusedWithADifferentRequest() throws Exception {
		UUID projectId = createProject();
		UUID old = requestWithKey(projectId, randomSha(), "reused-differently");
		age(old, this.properties.getRetention().plusMinutes(1));

		// Within the window this would be 422 (key reused with a different payload).
		MvcResult reuse = requestScan(projectId, randomSha(), "reused-differently");

		assertThat(reuse.getResponse().getStatus()).isEqualTo(202);
		assertThat(reuse.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("false");
	}

	@Test
	void expiryIsInclusiveAtTheExactRetentionBoundary() {
		Instant now = Instant.parse("2026-10-10T12:00:00Z");
		Duration retention = this.properties.getRetention();

		assertThat(this.properties.isExpired(now.minus(retention), now)).isTrue();
		assertThat(this.properties.isExpired(now.minus(retention).plusNanos(1000), now)).isFalse();
		assertThat(this.properties.isExpired(now.minus(retention).minusNanos(1000), now)).isTrue();
		assertThat(this.properties.isExpired(now, now)).isFalse();
	}

	@Test
	void concurrentReusesOfAnExpiredKeyCreateExactlyOneNewScan() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();
		UUID old = requestWithKey(projectId, sha, "contested-expired");
		age(old, this.properties.getRetention().plusMinutes(1));
		int threads = 8;
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<UUID>> attempts = new ArrayList<>();
		for (int i = 0; i < threads; i++) {
			attempts.add(() -> {
				start.await();
				return this.scanService.requestScan(projectId, sha, "main", TriggerType.PUSH, "contested-expired")
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

		assertThat(ids).hasSize(1).doesNotContain(old);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM scans WHERE project_id = ? AND idempotency_key = 'contested-expired'", Long.class,
				projectId))
			.isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans WHERE project_id = ?", Long.class,
				projectId))
			.isEqualTo(2);
	}

	@Test
	void cleanupReleasesOnlyExpiredKeysInBoundedBatchesAndDeletesNothing() throws Exception {
		UUID projectId = createProject();
		List<UUID> expired = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			UUID scan = requestWithKey(projectId, randomSha(), "cleanup-" + i);
			age(scan, this.properties.getRetention().plusMinutes(10 + i));
			expired.add(scan);
		}
		UUID live = requestWithKey(projectId, randomSha(), "cleanup-live");
		long scansBefore = this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans", Long.class);
		long eventsBefore = this.jdbcTemplate.queryForObject("SELECT count(*) FROM outbox_events", Long.class);
		Instant cutoff = this.properties.cutoff(Instant.now());

		int firstBatch = this.cleanup.releaseBatch(cutoff);
		assertThat(firstBatch).isPositive();

		int released = this.cleanup.run();

		assertThat(expired).allSatisfy((scan) -> assertThat(keyOf(scan)).isNull());
		assertThat(keyOf(live)).isEqualTo("cleanup-live");
		assertThat(firstBatch + released).isGreaterThanOrEqualTo(expired.size());
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans", Long.class)).isEqualTo(scansBefore);
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM outbox_events", Long.class))
			.isEqualTo(eventsBefore);
		assertThat(this.cleanup.run()).as("idempotent").isZero();
	}

	@Test
	void cleanupHonorsTheBatchSize() throws Exception {
		UUID projectId = createProject();
		for (int i = 0; i < 3; i++) {
			age(requestWithKey(projectId, randomSha(), "batch-" + i), this.properties.getRetention().plusHours(1));
		}
		IdempotencyProperties settings = new IdempotencyProperties();
		settings.setCleanupBatchSize(1);
		settings.setCleanupMaxBatches(2);
		IdempotencyKeyCleanup bounded = new IdempotencyKeyCleanup(this.namedJdbc, this.transactionManager, settings,
				Clock.systemUTC(), new SimpleMeterRegistry());

		// Two batches of one key per run, even though more keys have expired.
		assertThat(bounded.run()).isEqualTo(2);
		assertThat(bounded.run()).isGreaterThanOrEqualTo(1);
	}

	@Test
	void concurrentCleanupAndRequestCreationNeverFailOrDuplicateAKey() throws Exception {
		UUID projectId = createProject();
		String sha = randomSha();
		int keys = 6;
		for (int i = 0; i < keys; i++) {
			age(requestWithKey(projectId, sha, "race-" + i), this.properties.getRetention().plusMinutes(1));
		}
		CountDownLatch start = new CountDownLatch(1);
		List<Callable<Object>> work = new ArrayList<>();
		for (int round = 0; round < 3; round++) {
			work.add(() -> {
				start.await();
				return this.cleanup.run();
			});
			for (int i = 0; i < keys; i++) {
				String key = "race-" + i;
				work.add(() -> {
					start.await();
					return this.scanService.requestScan(projectId, sha, "main", TriggerType.PUSH, key);
				});
			}
		}

		try (ExecutorService executor = Executors.newFixedThreadPool(12)) {
			List<Future<Object>> futures = work.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<Object> future : futures) {
				future.get();
			}
		}

		// Every key is held by exactly one (new, live) scan; old scans are kept.
		for (int i = 0; i < keys; i++) {
			assertThat(this.jdbcTemplate.queryForObject(
					"SELECT count(*) FROM scans WHERE project_id = ? AND idempotency_key = ?", Long.class, projectId,
					"race-" + i))
				.isEqualTo(1);
		}
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans WHERE project_id = ?", Long.class,
				projectId))
			.isEqualTo(2L * keys);
	}

}

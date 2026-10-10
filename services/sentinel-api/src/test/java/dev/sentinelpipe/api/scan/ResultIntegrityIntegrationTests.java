package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.ExecutionTimeTravel;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Artifact;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.WorkerProtocol.Upload;
import dev.sentinelpipe.api.contract.ContractSchemas;
import dev.sentinelpipe.api.evidence.Evidence;
import dev.sentinelpipe.api.evidence.EvidenceArtifact;
import dev.sentinelpipe.api.evidence.EvidenceStore;
import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import dev.sentinelpipe.api.scanjob.ScannerType;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import tools.jackson.databind.JsonNode;

/**
 * Result integrity (Flyway V008, ADR-0008) against real PostgreSQL with the real worker
 * login: job-result.v1 validation, database-computed evidence digests, lease-bound and
 * tenant-scoped artifact references, idempotency, rejection deduplication, retention and
 * absence of sensitive data in the audit trail.
 */
class ResultIntegrityIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final String JSON = "application/json";

	private static final byte[] EVIDENCE = "{\"fixture\":\"harmless\",\"ok\":true}".getBytes(StandardCharsets.UTF_8);

	@Autowired
	private ScanService scanService;

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private TestDatabaseAdmin admin;

	@Autowired
	private EvidenceStore evidenceStore;

	@Autowired
	private ExecutionSupervisor supervisor;

	@Autowired
	private MeterRegistry meterRegistry;

	private WorkerProtocol worker;

	@BeforeEach
	void setUp() {
		this.worker = WorkerProtocol.asWorker(this.admin);
	}

	private Lease claimedFixture() throws Exception {
		return claimedFixture(createProject());
	}

	private Lease claimedFixture(UUID projectId) {
		UUID scanId = this.scanService.requestScan(projectId, randomSha(), "main", TriggerType.PUSH, null)
			.details()
			.scan()
			.getId();
		this.lifecycle.planJob(scanId, ScannerType.FIXTURE);
		return this.worker.claimFixtureOrFail(scanId);
	}

	private String jobStatus(Lease lease) {
		return this.jdbcTemplate.queryForObject("SELECT execution_status FROM scan_jobs WHERE id = ?", String.class,
				lease.jobId());
	}

	private Artifact upload(Lease lease, String name, byte[] content) {
		Upload upload = this.worker.putEvidence(lease, name, JSON, content);
		assertThat(upload.status()).isEqualTo("STORED");
		return Artifact.of(upload, name, JSON);
	}

	private static String sqlState(Throwable ex) {
		return ((SQLException) ((DataAccessException) ex).getMostSpecificCause()).getSQLState();
	}

	private JsonNode json(String text) {
		return this.jsonMapper.readTree(text);
	}

	// ---------------------------------------------------------------------------------
	// Valid results and verified evidence
	// ---------------------------------------------------------------------------------

	@Test
	void aValidResultWithEvidenceIsAcceptedAndTheEvidenceIsVerifiedOnRead() throws Exception {
		Lease lease = claimedFixture();
		Artifact artifact = upload(lease, "fixture-result.json", EVIDENCE);
		Map<String, Object> document = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of(artifact));
		String canonical = WorkerProtocol.canonical(document);
		ContractSchemas.assertValidMessage("job-result.v1.schema.json", json(canonical));

		assertThat(this.worker.submit(lease.token(), document)).isEqualTo("ACCEPTED");

		assertThat(jobStatus(lease)).isEqualTo("COMPLETED");
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT result_sha256 FROM lifecycle.job_reports WHERE job_id = ? AND lease_epoch = ?", String.class,
				lease.jobId(), lease.epoch()))
			.isEqualTo(EvidenceVerifier.sha256(canonical.getBytes(StandardCharsets.UTF_8)));
		List<EvidenceArtifact> listed = this.evidenceStore.list(lease.jobId());
		assertThat(listed).singleElement().satisfies((item) -> {
			assertThat(item.name()).isEqualTo("fixture-result.json");
			assertThat(item.sha256()).isEqualTo(EvidenceVerifier.sha256(EVIDENCE));
			assertThat(item.sizeBytes()).isEqualTo(EVIDENCE.length);
			assertThat(item.purged()).isFalse();
		});
		Evidence evidence = this.evidenceStore.read(lease.jobId(), lease.epoch(), "fixture-result.json").orElseThrow();
		assertThat(evidence.content()).isEqualTo(EVIDENCE);
		assertThat(evidence.toString()).doesNotContain("harmless");
	}

	@Test
	void theDatabaseComputesTheDigestFromTheBytesItReceived() throws Exception {
		Lease lease = claimedFixture();

		Upload upload = this.worker.putEvidence(lease, "report.txt", "text/plain", EVIDENCE);

		assertThat(upload.sha256()).isEqualTo(EvidenceVerifier.sha256(EVIDENCE));
		assertThat(upload.sizeBytes()).isEqualTo(EVIDENCE.length);
		assertThat(this.worker.putEvidence(lease, "report.txt", "text/plain", EVIDENCE).status()).isEqualTo("DUPLICATE");
	}

	@Test
	void unreferencedUploadsAreNotEvidenceOfRecord() throws Exception {
		Lease lease = claimedFixture();
		upload(lease, "scratch.json", EVIDENCE);

		assertThat(this.worker.complete(lease)).isEqualTo("ACCEPTED");

		assertThat(this.evidenceStore.list(lease.jobId())).isEmpty();
		assertThat(this.evidenceStore.read(lease.jobId(), lease.epoch(), "scratch.json")).isEmpty();
	}

	// ---------------------------------------------------------------------------------
	// Forged digests, modified bytes, missing and substituted artifacts
	// ---------------------------------------------------------------------------------

	@Test
	void aForgedDigestIsRejectedEvenForUploadedEvidence() throws Exception {
		Lease lease = claimedFixture();
		Artifact genuine = upload(lease, "fixture-result.json", EVIDENCE);
		String forged = EvidenceVerifier.sha256("{\"ok\":false}".getBytes(StandardCharsets.UTF_8));

		assertThat(this.worker.submit(lease, "COMPLETED", null,
				List.of(new Artifact(genuine.name(), JSON, forged, genuine.sizeBytes()))))
			.isEqualTo("REJECTED_ARTIFACT_MISMATCH");
		assertThat(this.worker.submit(lease, "COMPLETED", null,
				List.of(new Artifact(genuine.name(), JSON, genuine.sha256(), genuine.sizeBytes() + 1))))
			.isEqualTo("REJECTED_ARTIFACT_MISMATCH");
		assertThat(this.worker.submit(lease, "COMPLETED", null,
				List.of(new Artifact(genuine.name(), "text/plain", genuine.sha256(), genuine.sizeBytes()))))
			.isEqualTo("REJECTED_ARTIFACT_MISMATCH");

		assertThat(jobStatus(lease)).isEqualTo("RUNNING");
		assertThat(this.worker.submit(lease, "COMPLETED", null, List.of(genuine))).isEqualTo("ACCEPTED");
	}

	@Test
	void modifiedEvidenceBytesCannotReplaceStoredEvidence() throws Exception {
		Lease lease = claimedFixture();
		Artifact original = upload(lease, "fixture-result.json", EVIDENCE);
		byte[] modified = Arrays.copyOf(EVIDENCE, EVIDENCE.length);
		modified[modified.length - 2] = 'X';

		// Re-uploading different bytes under the same name and lease is a conflict.
		assertThat(this.worker.putEvidence(lease, "fixture-result.json", JSON, modified).status()).isEqualTo("CONFLICT");
		// Claiming the digest of the modified bytes for the stored name is a mismatch.
		assertThat(this.worker.submit(lease, "COMPLETED", null, List.of(new Artifact("fixture-result.json", JSON,
				EvidenceVerifier.sha256(modified), modified.length))))
			.isEqualTo("REJECTED_ARTIFACT_MISMATCH");
		// Not even the superuser can store bytes that do not match their address.
		assertThatThrownBy(() -> this.jdbcTemplate.update(
				"UPDATE evidence.objects SET content = ? WHERE sha256 = ?", modified, original.sha256()))
			.isInstanceOf(DataAccessException.class)
			.satisfies((ex) -> assertThat(sqlState(ex)).isEqualTo("23514"));
		assertThat(this.worker.submit(lease, "COMPLETED", null, List.of(original))).isEqualTo("ACCEPTED");
	}

	@Test
	void evidenceAlteredInStorageIsDetectedOnRead() {
		String recorded = EvidenceVerifier.sha256(EVIDENCE);
		byte[] tampered = EVIDENCE.clone();
		tampered[0] = '[';

		assertThatThrownBy(() -> EvidenceVerifier.verify("fixture-result.json", recorded, EVIDENCE.length, tampered))
			.isInstanceOf(dev.sentinelpipe.api.evidence.EvidenceIntegrityException.class)
			.hasMessageContaining("fixture-result.json")
			.hasMessageNotContaining("harmless");
		assertThatThrownBy(() -> EvidenceVerifier.verify("x", recorded, EVIDENCE.length + 1, EVIDENCE))
			.isInstanceOf(dev.sentinelpipe.api.evidence.EvidenceIntegrityException.class);
	}

	@Test
	void aReferenceToEvidenceThatWasNeverUploadedIsRejected() throws Exception {
		Lease lease = claimedFixture();

		assertThat(this.worker.submit(lease, "COMPLETED", null, List.of(new Artifact("fixture-result.json", JSON,
				EvidenceVerifier.sha256(EVIDENCE), EVIDENCE.length))))
			.isEqualTo("REJECTED_MISSING_ARTIFACT");
		assertThat(jobStatus(lease)).isEqualTo("RUNNING");
	}

	@Test
	void anotherTenantsEvidenceCannotBeSubstituted() throws Exception {
		Lease victim = claimedFixture();
		Lease attacker = claimedFixture();
		Artifact victimEvidence = upload(victim, "fixture-result.json", EVIDENCE);

		// The attacker references the victim's artifact (same name, digest and size).
		assertThat(this.worker.submit(attacker, "COMPLETED", null, List.of(victimEvidence)))
			.isEqualTo("REJECTED_MISSING_ARTIFACT");
		// Identical bytes uploaded by both tenants are stored as two tenant-scoped objects.
		upload(attacker, "fixture-result.json", EVIDENCE);
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM evidence.objects WHERE sha256 = ?",
				Integer.class, victimEvidence.sha256()))
			.isGreaterThanOrEqualTo(2);
		assertThat(this.worker.submit(attacker, "COMPLETED", null, List.of(victimEvidence))).isEqualTo("ACCEPTED");
		assertThat(this.jdbcTemplate.queryForObject("""
				SELECT u.organization_id = p.organization_id
				FROM evidence.job_artifacts u JOIN scan_jobs j ON j.id = u.job_id
				JOIN scans s ON s.id = j.scan_id JOIN projects p ON p.id = s.project_id
				WHERE u.job_id = ?""", Boolean.class, attacker.jobId()))
			.isTrue();
	}

	@Test
	void evidenceOfAnEarlierAttemptCannotBeReused() throws Exception {
		Lease first = claimedFixture();
		Artifact earlier = upload(first, "fixture-result.json", EVIDENCE);
		this.worker.fail(first, "SANDBOX_ERROR");
		new ExecutionTimeTravel(this.admin).makeRetryDue(first.jobId());
		Lease second = this.worker.claimFixtureOrFail(first.scanId());

		assertThat(this.worker.submit(second, "COMPLETED", null, List.of(earlier)))
			.isEqualTo("REJECTED_MISSING_ARTIFACT");
		assertThat(this.worker.putEvidence(first, "fixture-result.json", JSON, EVIDENCE).status())
			.isEqualTo("REJECTED_STALE_EPOCH");
	}

	@Test
	void uploadsRequireTheCurrentLease() throws Exception {
		Lease lease = claimedFixture();

		assertThat(this.worker.putEvidence(lease.withToken("a".repeat(64)), "x.json", JSON, EVIDENCE).status())
			.isEqualTo("REJECTED_TOKEN_MISMATCH");
		assertThat(this.worker.putEvidence(lease.withEpoch(lease.epoch() + 1), "x.json", JSON, EVIDENCE).status())
			.isEqualTo("REJECTED_UNKNOWN_EPOCH");
		assertThat(this.worker.putEvidence(UUID.randomUUID(), 1, lease.token(), "x.json", JSON, EVIDENCE).status())
			.isEqualTo("REJECTED_UNKNOWN_JOB");
		this.worker.complete(lease);
		assertThat(this.worker.putEvidence(lease, "late.json", JSON, EVIDENCE).status())
			.isEqualTo("REJECTED_JOB_NOT_RUNNING");
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM evidence.job_artifacts WHERE job_id = ?",
				Integer.class, lease.jobId()))
			.isZero();
	}

	// ---------------------------------------------------------------------------------
	// Authoritative context
	// ---------------------------------------------------------------------------------

	@Test
	void claimsThatContradictTheAuthoritativeRecordsAreRejected() throws Exception {
		Lease lease = claimedFixture();
		List<Consumer<Map<String, Object>>> forgeries = List.of(
				(doc) -> doc.put("organization_id", UUID.randomUUID().toString()),
				(doc) -> doc.put("project_id", UUID.randomUUID().toString()),
				(doc) -> doc.put("commit_sha", "f".repeat(40)), (doc) -> doc.put("scanner_type", "SEMGREP"),
				(doc) -> doc.put("attempt", 2));

		for (Consumer<Map<String, Object>> forgery : forgeries) {
			Map<String, Object> document = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of());
			forgery.accept(document);
			assertThat(this.worker.submit(lease.token(), document)).isEqualTo("REJECTED_CONTEXT_MISMATCH");
		}

		assertThat(jobStatus(lease)).isEqualTo("RUNNING");
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT occurrences FROM lifecycle.report_rejections WHERE job_id = ? AND detail = 'CONTEXT_MISMATCH'",
				Integer.class, lease.jobId()))
			.isEqualTo(forgeries.size());
	}

	// ---------------------------------------------------------------------------------
	// Idempotency, conflicts and concurrency
	// ---------------------------------------------------------------------------------

	@Test
	void identicalResultsAreDuplicatesAndDifferentOnesConflict() throws Exception {
		Lease lease = claimedFixture();
		Artifact artifact = upload(lease, "fixture-result.json", EVIDENCE);
		Map<String, Object> document = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of(artifact));
		assertThat(this.worker.submit(lease.token(), document)).isEqualTo("ACCEPTED");

		assertThat(this.worker.submit(lease.token(), document)).isEqualTo("DUPLICATE");
		document.put("finished_at", "2026-10-10T12:00:09Z");
		assertThat(this.worker.submit(lease.token(), document)).isEqualTo("CONFLICT");
		assertThat(this.worker.submit(lease, "COMPLETED", null, List.of())).isEqualTo("CONFLICT");
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'REPORT_CONFLICT'",
				Integer.class, lease.jobId()))
			.isEqualTo(1);
		assertThat(this.evidenceStore.list(lease.jobId())).hasSize(1);
	}

	@Test
	void concurrentSubmissionsAndUploadsApplyExactlyOnce() throws Exception {
		Lease lease = claimedFixture();
		List<Callable<String>> uploads = new ArrayList<>();
		for (int i = 0; i < 6; i++) {
			uploads.add(() -> this.worker.putEvidence(lease, "fixture-result.json", JSON, EVIDENCE).status());
		}
		assertThat(race(uploads)).containsOnlyOnce("STORED").filteredOn("DUPLICATE"::equals).hasSize(5);
		Map<String, Object> document = WorkerProtocol.resultDocument(lease, "COMPLETED", null,
				List.of(new Artifact("fixture-result.json", JSON, EvidenceVerifier.sha256(EVIDENCE), EVIDENCE.length)));
		List<Callable<String>> submissions = new ArrayList<>();
		for (int i = 0; i < 6; i++) {
			submissions.add(() -> this.worker.submit(lease.token(), document));
		}

		assertThat(race(submissions)).containsOnlyOnce("ACCEPTED").filteredOn("DUPLICATE"::equals).hasSize(5);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'JOB_COMPLETED'",
				Integer.class, lease.jobId()))
			.isEqualTo(1);
	}

	private static List<String> race(List<Callable<String>> tasks) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
		try {
			List<String> results = new ArrayList<>();
			for (Future<String> future : pool.invokeAll(tasks)) {
				results.add(future.get());
			}
			return results;
		}
		finally {
			pool.shutdownNow();
		}
	}

	// ---------------------------------------------------------------------------------
	// Contract enforcement
	// ---------------------------------------------------------------------------------

	@Test
	void unsupportedContractVersionsAreRejected() throws Exception {
		Lease lease = claimedFixture();
		Map<String, Object> document = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of());
		document.put("schema_version", 2);

		assertThat(this.worker.submit(lease.token(), document)).isEqualTo("REJECTED_UNSUPPORTED_SCHEMA_VERSION");
		assertThat(ContractSchemas.validateMessage("job-result.v1.schema.json",
				json(WorkerProtocol.canonical(document))))
			.isNotEmpty();
		assertThat(jobStatus(lease)).isEqualTo("RUNNING");
	}

	@Test
	void malformedAndOversizedResultsAreRejectedByTheDatabaseAndTheContract() throws Exception {
		Lease lease = claimedFixture();
		Artifact artifact = upload(lease, "a.json", EVIDENCE);
		Map<String, Object> reference = Map.<String, Object>of("name", "a.json", "media_type", JSON, "sha256",
				artifact.sha256(), "size_bytes", artifact.sizeBytes());
		List<Consumer<Map<String, Object>>> schemaViolations = List.of((doc) -> doc.put("token", lease.token()),
				(doc) -> doc.remove("commit_sha"), (doc) -> doc.put("attempt", 1.5),
				(doc) -> doc.put("attempt", "1"), (doc) -> doc.put("schema_version", "1"),
				(doc) -> doc.put("outcome", "PASS"), (doc) -> doc.put("failure_reason", "SCANNER_ERROR"),
				(doc) -> doc.put("started_at", "2026-10-10 12:00:00"), (doc) -> doc.put("started_at", "yesterday"),
				(doc) -> doc.put("job_id", "not-a-uuid"), (doc) -> doc.put("commit_sha", "main"),
				(doc) -> doc.put("artifacts", "a.json"),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "name", "../../etc/passwd"))),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "name", "reports/a.json"))),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "name", "https://evil.example/a"))),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "name", "A.json"))),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "media_type", "text/html"))),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "size_bytes", -1))),
				(doc) -> doc.put("artifacts", List.of(withEntry(reference, "url", "s3://bucket/key"))),
				(doc) -> doc.put("artifacts", java.util.Collections.nCopies(17, reference)));

		for (Consumer<Map<String, Object>> violation : schemaViolations) {
			Map<String, Object> document = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of());
			violation.accept(document);
			String text = WorkerProtocol.canonical(document);
			assertThat(ContractSchemas.validateMessage("job-result.v1.schema.json", json(text))).as(text).isNotEmpty();
			assertMalformed(lease, text);
		}
		// Rules the schema cannot express: canonical artifact order, unique names, duplicate
		// keys, size, time order, and syntax.
		String valid = WorkerProtocol
			.canonical(WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of(artifact)));
		Map<String, Object> reversed = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of());
		reversed.put("artifacts", List.of(withEntry(reference, "name", "b.json"), reference));
		Map<String, Object> repeated = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of());
		repeated.put("artifacts", List.of(reference, reference));
		Map<String, Object> backwards = WorkerProtocol.resultDocument(lease, "COMPLETED", null, List.of());
		backwards.put("finished_at", "2026-10-09T12:00:00Z");
		for (String text : List.of(WorkerProtocol.canonical(reversed), WorkerProtocol.canonical(repeated),
				WorkerProtocol.canonical(backwards), valid.replace("{\"artifacts\"", "{\"outcome\":\"FAILED\",\"artifacts\""),
				valid.substring(0, valid.length() - 1) + ",\"padding\":\"" + "x".repeat(17_000) + "\"}", "[]", "null",
				"{", "not json", valid.replace("\"attempt\":1", "\"attempt\":1e0"))) {
			assertMalformed(lease, text);
		}
		assertThat(jobStatus(lease)).isEqualTo("RUNNING");
		assertThat(this.worker.submitRaw(lease.token(), valid)).isEqualTo("ACCEPTED");
	}

	private void assertMalformed(Lease lease, String text) {
		assertThatThrownBy(() -> this.worker.submitRaw(lease.token(), text)).as(text)
			.isInstanceOf(DataAccessException.class)
			.satisfies((ex) -> {
				assertThat(sqlState(ex)).isEqualTo("22023");
				// The rejected document (and the token) are never echoed.
				assertThat(((DataAccessException) ex).getMostSpecificCause().getMessage()).contains("invalid job result")
					.doesNotContain(lease.token())
					.doesNotContain(lease.commitSha());
			});
	}

	private static Map<String, Object> withEntry(Map<String, Object> base, String key, Object value) {
		Map<String, Object> copy = new java.util.TreeMap<>(base);
		copy.put(key, value);
		return copy;
	}

	@Test
	void evidenceSizeAndCountAreBounded() throws Exception {
		Lease lease = claimedFixture();
		byte[] megabyte = new byte[1024 * 1024];

		assertThatThrownBy(() -> this.worker.putEvidence(lease, "big.txt", "text/plain", new byte[1024 * 1024 + 1]))
			.satisfies((ex) -> assertThat(sqlState(ex)).isEqualTo("22023"));
		for (String name : List.of("../x", "a/b", "x.json?y", "", ".hidden")) {
			assertThatThrownBy(() -> this.worker.putEvidence(lease, name, JSON, EVIDENCE)).as(name)
				.satisfies((ex) -> assertThat(sqlState(ex)).isEqualTo("22023"));
		}
		assertThatThrownBy(() -> this.worker.putEvidence(lease, "x.html", "text/html", EVIDENCE))
			.satisfies((ex) -> assertThat(sqlState(ex)).isEqualTo("22023"));
		for (int i = 0; i < 8; i++) {
			megabyte[0] = (byte) i;
			assertThat(this.worker.putEvidence(lease, "part-" + i + ".txt", "text/plain", megabyte).status())
				.isEqualTo("STORED");
		}
		assertThat(this.worker.putEvidence(lease, "one-more.txt", "text/plain", new byte[1]).status())
			.isEqualTo("REJECTED_QUOTA_EXCEEDED");

		Lease many = claimedFixture();
		for (int i = 0; i < 16; i++) {
			upload(many, "n" + i + ".json", ("{\"n\":" + i + "}").getBytes(StandardCharsets.UTF_8));
		}
		assertThat(this.worker.putEvidence(many, "n16.json", JSON, EVIDENCE).status())
			.isEqualTo("REJECTED_QUOTA_EXCEEDED");
	}

	// ---------------------------------------------------------------------------------
	// Audit growth, retention, metrics and sensitive data
	// ---------------------------------------------------------------------------------

	@Test
	void repeatedRejectionsAreCountedWithoutGrowingTheAuditTrail() throws Exception {
		Lease lease = claimedFixture();
		Lease forged = lease.withToken("b".repeat(64));

		for (int i = 0; i < 50; i++) {
			assertThat(this.worker.complete(forged)).isEqualTo("REJECTED_TOKEN_MISMATCH");
			this.worker.complete(forged.withEpoch(1_000 + i));
		}

		assertThat(this.jdbcTemplate.queryForList(
				"SELECT detail FROM lifecycle.execution_events WHERE job_id = ? AND event_type = 'REPORT_REJECTED'",
				String.class, lease.jobId()))
			.containsExactlyInAnyOrder("TOKEN_MISMATCH", "UNKNOWN_EPOCH");
		assertThat(this.jdbcTemplate.queryForList(
				"SELECT detail, occurrences FROM lifecycle.report_rejections WHERE job_id = ? ORDER BY detail",
				lease.jobId()))
			.extracting((row) -> row.get("detail") + "=" + row.get("occurrences"))
			.containsExactly("TOKEN_MISMATCH=50", "UNKNOWN_EPOCH=50");

		this.supervisor.runOnce();
		assertThat(this.meterRegistry.get(ExecutionSupervisor.RESULT_REJECTIONS)
			.tags("reason", "TOKEN_MISMATCH")
			.gauge()
			.value()).isGreaterThanOrEqualTo(50);
	}

	@Test
	void evidenceContentIsPurgedAfterRetentionWhileItsDigestRemains() throws Exception {
		Lease lease = claimedFixture();
		Artifact artifact = upload(lease, "fixture-result.json", EVIDENCE);
		this.worker.submit(lease, "COMPLETED", null, List.of(artifact));
		this.jdbcTemplate.update("""
				UPDATE evidence.objects SET retain_until = now() - interval '1 second'
				WHERE sha256 = ? AND organization_id = ?""", artifact.sha256(), lease.organizationId());

		assertThat(this.supervisor.runOnce().evidencePurged()).isPositive();

		assertThat(this.evidenceStore.list(lease.jobId())).singleElement().satisfies((item) -> {
			assertThat(item.purged()).isTrue();
			assertThat(item.sha256()).isEqualTo(artifact.sha256());
		});
		assertThat(this.evidenceStore.read(lease.jobId(), lease.epoch(), "fixture-result.json")).isEmpty();
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT result ->> 'outcome' FROM lifecycle.job_reports WHERE job_id = ?", String.class, lease.jobId()))
			.isEqualTo("COMPLETED");
	}

	@Test
	void retentionIsTakenFromTheScanAtUploadTime() throws Exception {
		Lease lease = claimedFixture();
		upload(lease, "fixture-result.json", EVIDENCE);

		assertThat(this.jdbcTemplate.queryForObject("""
				SELECT o.retain_until - o.stored_at FROM evidence.objects o
				WHERE o.organization_id = ? AND o.sha256 = ?""", String.class, lease.organizationId(),
				EvidenceVerifier.sha256(EVIDENCE)))
			.isEqualTo("90 days");
	}

	@Test
	void tokensAndEvidenceContentNeverReachTheAuditRecords() throws Exception {
		Lease lease = claimedFixture();
		byte[] secretLooking = "{\"aws_key\":\"AKIAFAKEFAKEFAKE0000\"}".getBytes(StandardCharsets.UTF_8);
		Artifact artifact = upload(lease, "fixture-result.json", secretLooking);
		this.worker.complete(lease.withToken("c".repeat(64)));
		this.worker.submit(lease, "COMPLETED", null, List.of(artifact));

		String audit = String.join("\n", this.jdbcTemplate.queryForList("""
				SELECT row_to_json(e)::text FROM lifecycle.execution_events e WHERE e.job_id = ? OR e.scan_id = ?
				UNION ALL SELECT row_to_json(r)::text FROM lifecycle.report_rejections r WHERE r.job_id = ?
				UNION ALL SELECT row_to_json(j)::text FROM lifecycle.job_reports j WHERE j.job_id = ?
				UNION ALL SELECT row_to_json(a)::text FROM evidence.job_artifacts a WHERE a.job_id = ?""", String.class,
				lease.jobId(), lease.scanId(), lease.jobId(), lease.jobId(), lease.jobId()));
		assertThat(audit).isNotBlank()
			.doesNotContain(lease.token())
			.doesNotContain("c".repeat(64))
			.doesNotContain("AKIAFAKEFAKEFAKE0000");
	}

}

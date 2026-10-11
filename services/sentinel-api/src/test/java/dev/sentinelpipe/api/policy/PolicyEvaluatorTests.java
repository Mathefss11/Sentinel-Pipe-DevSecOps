package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import dev.sentinelpipe.api.policy.EvaluationInputs.Artifact;
import dev.sentinelpipe.api.policy.EvaluationInputs.JobEvidence;
import dev.sentinelpipe.api.policy.EvaluationInputs.ScanContext;
import dev.sentinelpipe.api.policy.PolicyEvaluator.Evaluation;
import dev.sentinelpipe.api.policy.PolicyFixtures.Findings;
import dev.sentinelpipe.api.policy.PolicyFixtures.JobContext;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * The deterministic decision matrix of the policy engine (ADR-0013), without a database:
 * evidence is built exactly as the database returns it (accepted result of record plus the
 * referenced artifact). None of these tests assumes a scanner is comprehensive; they test
 * how evidence and its stated limits are judged.
 */
class PolicyEvaluatorTests {

	private static final Instant NOW = Instant.parse("2026-10-11T12:00:00Z");

	private static final Instant COMPLETED = NOW.minusSeconds(30);

	private final PolicyEvaluator evaluator = new PolicyEvaluator();

	private final ScanContext scan = new ScanContext(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
			"a".repeat(40), NOW);

	private final Map<ScannerType, UUID> jobIds = new EnumMap<>(ScannerType.class);

	private JobContext context(ScannerType type) {
		return new JobContext(this.scan.organizationId(), this.scan.projectId(), this.scan.scanId(),
				this.jobIds.computeIfAbsent(type, (t) -> UUID.randomUUID()), this.scan.commitSha());
	}

	private Findings findings(PolicyScanner scanner) {
		return new Findings(scanner, context(scanner.scannerType()));
	}

	/** Trivy evidence with a database one hour old at job completion (no wall clock). */
	private Findings trivy() {
		return findings(PolicyScanner.TRIVY).database(COMPLETED.minusSeconds(3600), 3600);
	}

	/** A COMPLETED job with an accepted result referencing {@code content} as findings.json. */
	private JobEvidence completed(ScannerType type, byte[] content) {
		return completed(type, content, UnaryOperator.identity(), COMPLETED);
	}

	private JobEvidence completed(ScannerType type, byte[] content, UnaryOperator<ObjectNode> alterResult,
			Instant completedAt) {
		UUID jobId = context(type).jobId();
		String sha = EvidenceVerifier.sha256(content);
		ObjectNode result = JsonNodeFactory.instance.objectNode();
		result.put("schema_version", 1);
		result.put("job_id", jobId.toString());
		result.put("scan_id", this.scan.scanId().toString());
		result.put("project_id", this.scan.projectId().toString());
		result.put("organization_id", this.scan.organizationId().toString());
		result.put("commit_sha", this.scan.commitSha());
		result.put("scanner_type", type.name());
		result.put("attempt", 1);
		result.put("lease_epoch", 1);
		result.put("outcome", "COMPLETED");
		result.putNull("failure_reason");
		result.put("started_at", "2026-10-11T11:59:00Z");
		result.put("finished_at", "2026-10-11T11:59:30Z");
		ArrayNode artifacts = result.putArray("artifacts");
		ObjectNode reference = artifacts.addObject();
		reference.put("name", "findings.json");
		reference.put("media_type", "application/json");
		reference.put("sha256", sha);
		reference.put("size_bytes", content.length);
		String canonical = CanonicalJson.write(alterResult.apply(result));
		return new JobEvidence(jobId, type, "COMPLETED", null, 1, completedAt,
				EvidenceVerifier.sha256(canonical.getBytes(StandardCharsets.UTF_8)), canonical,
				List.of(new Artifact("findings.json", "application/json", sha, content.length, content)));
	}

	private JobEvidence failed(ScannerType type, String status, String reason) {
		return new JobEvidence(context(type).jobId(), type, status, reason, 3, COMPLETED, null, null, List.of());
	}

	private List<JobEvidence> cleanJobs() {
		return new ArrayList<>(List.of(completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).bytes()),
				completed(ScannerType.SEMGREP, findings(PolicyScanner.SEMGREP).bytes()),
				completed(ScannerType.TRIVY, trivy().bytes())));
	}

	private Evaluation evaluate(String policy, List<JobEvidence> jobs) {
		return this.evaluator.evaluate(PolicyFixtures.parse(policy), this.scan, jobs);
	}

	private Evaluation evaluate(List<JobEvidence> jobs) {
		return evaluate(PolicyFixtures.allScanners("baseline"), jobs);
	}

	private static List<String> codes(Evaluation evaluation) {
		return evaluation.reasons().stream().map((r) -> r.code().name() + ":" + r.scanner() + ":" + r.subject()).toList();
	}

	// --- PASS --------------------------------------------------------------------------

	@Test
	void allMandatoryScannersCompleteWithoutFindingsAndFullCoverageIsPass() {
		Evaluation evaluation = evaluate(cleanJobs());

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.PASS);
		assertThat(evaluation.reasons()).isEmpty();
		assertThat(evaluation.evidence()).extracting(EvaluationInputs.EvidenceReference::scannerType)
			.containsExactly(ScannerType.SEMGREP, ScannerType.GITLEAKS, ScannerType.TRIVY);
	}

	@Test
	void nonBlockingFindingsWithinEachScannersOwnScaleArePermitted() {
		List<JobEvidence> jobs = List.of(completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).bytes()),
				completed(ScannerType.SEMGREP, findings(PolicyScanner.SEMGREP).finding("INFO").bytes()),
				completed(ScannerType.TRIVY,
						trivy().finding("MEDIUM").finding("LOW").finding("UNKNOWN").bytes()));

		assertThat(evaluate(jobs).decision()).isEqualTo(PolicyDecision.PASS);
	}

	@Test
	void blockingFindingsUpToTheLimitPassAndBeyondItFail() {
		String tolerant = PolicyFixtures.gitleaksOnly("tolerant").replace("\"max_blocking_findings\": 0",
				"\"max_blocking_findings\": 2");

		Evaluation two = evaluate(tolerant,
				List.of(completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).finding("x").finding("x").bytes())));
		this.jobIds.clear();
		Evaluation three = evaluate(tolerant, List.of(completed(ScannerType.GITLEAKS,
				findings(PolicyScanner.GITLEAKS).finding("x").finding("x").finding("x").bytes())));

		assertThat(two.decision()).isEqualTo(PolicyDecision.PASS);
		assertThat(three.decision()).isEqualTo(PolicyDecision.FAIL);
		assertThat(three.reasons()).containsExactly(
				Reason.measured(ReasonCode.BLOCKING_FINDINGS_EXCEEDED, ScannerType.GITLEAKS, 3, 2L));
	}

	// --- FAIL --------------------------------------------------------------------------

	@Test
	void aMandatoryScannerDetectingAViolationIsFail() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(0, completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).finding("x").bytes()));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.FAIL);
		assertThat(evaluation.reasons()).containsExactly(
				Reason.measured(ReasonCode.BLOCKING_FINDINGS_EXCEEDED, ScannerType.GITLEAKS, 1, 0L));
	}

	@Test
	void severityThresholdsUseEachScannersOwnLabels() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(1, completed(ScannerType.SEMGREP, findings(PolicyScanner.SEMGREP).finding("WARNING").bytes()));
		jobs.set(2, completed(ScannerType.TRIVY, trivy().finding("CRITICAL").finding("HIGH").bytes()));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.FAIL);
		assertThat(evaluation.reasons()).containsExactly(
				Reason.measured(ReasonCode.BLOCKING_FINDINGS_EXCEEDED, ScannerType.SEMGREP, 1, 0L),
				Reason.measured(ReasonCode.BLOCKING_FINDINGS_EXCEEDED, ScannerType.TRIVY, 2, 0L));
	}

	// --- Precedence --------------------------------------------------------------------

	@Test
	void aConfirmedViolationIsFailEvenWhenAnotherScannerIsMissingAndBothAreRecorded() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(0, completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).finding("x").bytes()));
		jobs.remove(2);

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.FAIL);
		assertThat(codes(evaluation)).containsExactly("BLOCKING_FINDINGS_EXCEEDED:GITLEAKS:null",
				"REQUIRED_SCANNER_NOT_PLANNED:TRIVY:null");
		assertThat(evaluation.reasons()).extracting(Reason::effect)
			.containsExactly(ReasonEffect.VIOLATION, ReasonEffect.INCOMPLETE);
	}

	@Test
	void aViolationInDiscardedEvidenceNeverCountsAsFail() {
		List<JobEvidence> jobs = cleanJobs();
		// A leaky document bound to another tenant: discarded, so INCOMPLETE, not FAIL.
		JobContext foreign = new JobContext(UUID.randomUUID(), this.scan.projectId(), this.scan.scanId(),
				context(ScannerType.GITLEAKS).jobId(), this.scan.commitSha());
		jobs.set(0, completed(ScannerType.GITLEAKS, new Findings(PolicyScanner.GITLEAKS, foreign).finding("x").bytes()));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("EVIDENCE_BINDING_MISMATCH:GITLEAKS:FINDINGS_CONTEXT");
	}

	// --- INCOMPLETE: execution and presence ----------------------------------------------

	@Test
	void aMissingRequiredScannerIsIncomplete() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.remove(2);

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("REQUIRED_SCANNER_NOT_PLANNED:TRIVY:null");
	}

	@Test
	void aCrashedCancelledOrUnfinishedScannerIsIncomplete() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(0, failed(ScannerType.GITLEAKS, "FAILED", "SCANNER_ERROR"));
		jobs.set(1, failed(ScannerType.SEMGREP, "CANCELLED", null));
		jobs.set(2, failed(ScannerType.TRIVY, "RUNNING", null));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("SCANNER_EXECUTION_CANCELLED:SEMGREP:null",
				"SCANNER_EXECUTION_FAILED:GITLEAKS:SCANNER_ERROR", "SCANNER_EXECUTION_UNFINISHED:TRIVY:null");
		assertThat(evaluation.evidence()).isEmpty();
	}

	@Test
	void aCompletedJobWithoutValidEvidenceIsIncomplete() {
		JobEvidence noResult = new JobEvidence(context(ScannerType.GITLEAKS).jobId(), ScannerType.GITLEAKS,
				"COMPLETED", null, 1, COMPLETED, null, null, List.of());
		JobEvidence clean = completed(ScannerType.SEMGREP, findings(PolicyScanner.SEMGREP).bytes());
		JobEvidence noArtifact = new JobEvidence(clean.jobId(), clean.scannerType(), "COMPLETED", null, 1, COMPLETED,
				clean.resultSha256(), clean.result(), List.of());
		JobEvidence notJson = completed(ScannerType.TRIVY, "not json".getBytes(StandardCharsets.UTF_8));

		Evaluation evaluation = evaluate(List.of(noResult, noArtifact, notJson));

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("EVIDENCE_MISSING:SEMGREP:FINDINGS_ARTIFACT",
				"EVIDENCE_MISSING:GITLEAKS:RESULT", "EVIDENCE_INVALID:TRIVY:JSON");
	}

	@Test
	void purgedEvidenceCannotBeReverifiedAndIsIncomplete() {
		JobEvidence clean = completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).bytes());
		Artifact artifact = clean.artifacts().get(0);
		JobEvidence purged = new JobEvidence(clean.jobId(), clean.scannerType(), "COMPLETED", null, 1, COMPLETED,
				clean.resultSha256(), clean.result(), List.of(new Artifact(artifact.name(), artifact.mediaType(),
						artifact.sha256(), artifact.sizeBytes(), null)));

		Evaluation evaluation = evaluate(PolicyFixtures.gitleaksOnly("p"), List.of(purged));

		assertThat(codes(evaluation)).containsExactly("EVIDENCE_PURGED:GITLEAKS:null");
	}

	// --- INCOMPLETE: integrity, validity, binding -------------------------------------

	@Test
	void anEvidenceDigestMismatchIsIncomplete() {
		byte[] content = findings(PolicyScanner.GITLEAKS).bytes();
		JobEvidence clean = completed(ScannerType.GITLEAKS, content);
		byte[] altered = findings(PolicyScanner.GITLEAKS).finding("x").bytes();
		// The stored bytes changed but the recorded digest did not.
		Artifact recorded = clean.artifacts().get(0);
		JobEvidence tampered = new JobEvidence(clean.jobId(), clean.scannerType(), "COMPLETED", null, 1, COMPLETED,
				clean.resultSha256(), clean.result(), List.of(new Artifact(recorded.name(), recorded.mediaType(),
						recorded.sha256(), recorded.sizeBytes(), altered)));

		Evaluation evaluation = evaluate(PolicyFixtures.gitleaksOnly("p"), List.of(tampered));

		assertThat(evaluation.decision()).as("a violation in tampered evidence is not FAIL")
			.isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("EVIDENCE_INTEGRITY_FAILED:GITLEAKS:ARTIFACT_DIGEST");
		assertThat(evaluation.evidence()).isEmpty();
	}

	@Test
	void aStoredResultThatDiffersFromItsDigestOrReferencesOtherEvidenceIsIncomplete() {
		byte[] content = findings(PolicyScanner.GITLEAKS).bytes();
		JobEvidence clean = completed(ScannerType.GITLEAKS, content);
		JobEvidence resultEdited = new JobEvidence(clean.jobId(), clean.scannerType(), "COMPLETED", null, 1, COMPLETED,
				clean.resultSha256(), clean.result().replace("\"attempt\":1", "\"attempt\":2"), clean.artifacts());
		JobEvidence otherArtifact = completed(ScannerType.GITLEAKS, content, (result) -> {
			((ObjectNode) result.get("artifacts").get(0)).put("sha256", "0".repeat(64));
			return result;
		}, COMPLETED);
		JobEvidence otherJob = completed(ScannerType.GITLEAKS, content, (result) -> result.put("job_id",
				UUID.randomUUID().toString()), COMPLETED);

		assertThat(codes(evaluate(PolicyFixtures.gitleaksOnly("p"), List.of(resultEdited))))
			.containsExactly("EVIDENCE_INTEGRITY_FAILED:GITLEAKS:RESULT_DIGEST");
		assertThat(codes(evaluate(PolicyFixtures.gitleaksOnly("p"), List.of(otherArtifact))))
			.containsExactly("EVIDENCE_INTEGRITY_FAILED:GITLEAKS:RESULT_ARTIFACT");
		assertThat(codes(evaluate(PolicyFixtures.gitleaksOnly("p"), List.of(otherJob))))
			.containsExactly("EVIDENCE_BINDING_MISMATCH:GITLEAKS:RESULT_CONTEXT");
	}

	@Test
	void anUnsupportedEvidenceSchemaIsIncomplete() {
		Evaluation evaluation = evaluate(PolicyFixtures.gitleaksOnly("p"),
				List.of(completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).schemaVersion(2).bytes())));

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(evaluation.reasons()).containsExactly(
				new Reason(ReasonCode.EVIDENCE_SCHEMA_UNSUPPORTED, ScannerType.GITLEAKS, null, 2L, null));
	}

	@Test
	void evidenceForAnotherScannerOrInconsistentEvidenceIsDiscarded() {
		// A Gitleaks document submitted as Trivy's evidence.
		JobContext trivyJob = context(ScannerType.TRIVY);
		byte[] wrongScanner = new Findings(PolicyScanner.GITLEAKS, trivyJob).bytes();
		ObjectNode miscounted = findings(PolicyScanner.SEMGREP).finding("ERROR").node();
		miscounted.put("finding_count", 0);

		Evaluation evaluation = evaluate(List.of(
				completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).bytes()),
				completed(ScannerType.SEMGREP, CanonicalJson.write(miscounted).getBytes(StandardCharsets.US_ASCII)),
				completed(ScannerType.TRIVY, wrongScanner)));

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("EVIDENCE_INCONSISTENT:SEMGREP:FINDING_COUNT",
				"EVIDENCE_BINDING_MISMATCH:TRIVY:SCANNER");
	}

	// --- INCOMPLETE: coverage ----------------------------------------------------------

	@Test
	void incompleteSemgrepCoverageIsIncomplete() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(1, completed(ScannerType.SEMGREP,
				findings(PolicyScanner.SEMGREP).incomplete("FILES_NOT_ANALYZED").bytes()));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("COVERAGE_INCOMPLETE:SEMGREP:null",
				"COVERAGE_LIMITATION_NOT_ACCEPTED:SEMGREP:FILES_NOT_ANALYZED");
	}

	@Test
	void theKnownPypiNameMatchingLimitationIsIncompleteWhenFullCoverageIsRequired() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(2, completed(ScannerType.TRIVY,
				trivy().incomplete("PYPI_NAME_MATCHING_UNVERIFIED").bytes()));

		Evaluation required = evaluate(jobs);

		assertThat(required.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(required)).containsExactly("COVERAGE_INCOMPLETE:TRIVY:null",
				"COVERAGE_LIMITATION_NOT_ACCEPTED:TRIVY:PYPI_NAME_MATCHING_UNVERIFIED");
		// Only an explicit, recorded acceptance changes that: the policy text says so.
		String accepting = PolicyFixtures.allScanners("accepting")
			.replace("\"SYNTHETIC_VULNERABILITY_DATABASE\"]",
					"\"SYNTHETIC_VULNERABILITY_DATABASE\", \"PYPI_NAME_MATCHING_UNVERIFIED\"]")
			.replace("\"TRIVY\": {\"require_complete_coverage\": true", "\"TRIVY\": {\"require_complete_coverage\": false");
		assertThat(evaluate(accepting, jobs).decision()).isEqualTo(PolicyDecision.PASS);
	}

	/**
	 * Final review M4-6: a lax policy (complete coverage not required) must never pass a gap
	 * the evidence does not name. Incomplete coverage always comes with a limitation that
	 * explains it, and a limitation that implies a gap never comes with complete coverage.
	 */
	@Test
	void incompleteCoverageWithoutAnExplainingLimitationIsInconsistentEvenUnderALaxPolicy() {
		String lax = PolicyFixtures.allScanners("lax").replace("\"require_complete_coverage\": true",
				"\"require_complete_coverage\": false");
		List<JobEvidence> jobs = cleanJobs();
		// coverage.complete = false, but only the accepted, inherent limitations are listed.
		ObjectNode unexplained = trivy().node();
		((ObjectNode) unexplained.get("coverage")).put("complete", false);
		jobs.set(2, completed(ScannerType.TRIVY, CanonicalJson.write(unexplained).getBytes(StandardCharsets.US_ASCII)));
		// A gap-implying limitation with coverage.complete = true.
		ObjectNode contradictory = findings(PolicyScanner.GITLEAKS).limitation("FILES_SKIPPED").node();
		jobs.set(0, completed(ScannerType.GITLEAKS,
				CanonicalJson.write(contradictory).getBytes(StandardCharsets.US_ASCII)));

		Evaluation evaluation = evaluate(lax, jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("EVIDENCE_INCONSISTENT:GITLEAKS:COVERAGE",
				"EVIDENCE_INCONSISTENT:TRIVY:COVERAGE");
	}

	@Test
	void anExplainedGapIsAcceptedOnlyWhenThePolicyNamesItsLimitation() {
		String lax = PolicyFixtures.allScanners("lax").replace("\"require_complete_coverage\": true",
				"\"require_complete_coverage\": false");
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(1, completed(ScannerType.SEMGREP,
				findings(PolicyScanner.SEMGREP).incomplete("FILES_NOT_ANALYZED").bytes()));

		assertThat(codes(evaluate(lax, jobs)))
			.containsExactly("COVERAGE_LIMITATION_NOT_ACCEPTED:SEMGREP:FILES_NOT_ANALYZED");
		String accepting = lax.replace("\"RULESET_MINIMAL\"]", "\"RULESET_MINIMAL\", \"FILES_NOT_ANALYZED\"]");
		assertThat(evaluate(accepting, jobs).decision()).isEqualTo(PolicyDecision.PASS);
	}

	@Test
	void emptyFindingsWithMissingCoverageMetadataIsIncomplete() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(1, completed(ScannerType.SEMGREP, findings(PolicyScanner.SEMGREP).withoutFileCoverage().bytes()));
		ObjectNode noCoverage = findings(PolicyScanner.GITLEAKS).node();
		noCoverage.remove("coverage");
		jobs.set(0, completed(ScannerType.GITLEAKS, CanonicalJson.write(noCoverage).getBytes(StandardCharsets.US_ASCII)));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("COVERAGE_METADATA_MISSING:SEMGREP:FILE_COVERAGE",
				"EVIDENCE_INVALID:GITLEAKS:SCHEMA");
	}

	@Test
	void anEmptyInputCanNeverPass() {
		Evaluation evaluation = evaluate(PolicyFixtures.gitleaksOnly("p"),
				List.of(completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).emptyInput().bytes())));

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("COVERAGE_LIMITATION_NOT_ACCEPTED:GITLEAKS:EMPTY_INPUT");
	}

	@Test
	void unsupportedScannerSeveritiesAreReportedNeverGuessed() {
		List<JobEvidence> jobs = cleanJobs();
		// A Trivy label on a Semgrep finding, and a Semgrep finding with no label at all.
		jobs.set(1, completed(ScannerType.SEMGREP, findings(PolicyScanner.SEMGREP).finding("CRITICAL").finding(null).bytes()));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(evaluation.reasons()).containsExactly(
				Reason.measured(ReasonCode.UNSUPPORTED_SCANNER_SEVERITY, ScannerType.SEMGREP, 2, null));
	}

	// --- INCOMPLETE: freshness ---------------------------------------------------------

	@Test
	void aTrivyDatabaseOlderThanThePolicyAllowsIsIncomplete() {
		List<JobEvidence> jobs = cleanJobs();
		Instant updated = COMPLETED.minus(Duration.ofDays(3));
		jobs.set(2, completed(ScannerType.TRIVY, trivy().incomplete("VULNERABILITY_DB_STALE")
			.database(updated, Duration.ofDays(3).toSeconds())
			.bytes()));

		Evaluation evaluation = evaluate(jobs);

		assertThat(evaluation.decision()).isEqualTo(PolicyDecision.INCOMPLETE);
		assertThat(codes(evaluation)).containsExactly("COVERAGE_INCOMPLETE:TRIVY:null",
				"COVERAGE_LIMITATION_NOT_ACCEPTED:TRIVY:VULNERABILITY_DB_STALE",
				"VULNERABILITY_DATABASE_TOO_OLD:TRIVY:null");
		assertThat(evaluation.reasons().get(2).observed()).isEqualTo(Duration.ofDays(3).toSeconds());
		assertThat(evaluation.reasons().get(2).limit()).isEqualTo(172800L);
	}

	@Test
	void theDatabaseAgeIsMeasuredWithTheDatabaseClockNotOnlyTheWorkersClaim() {
		List<JobEvidence> jobs = cleanJobs();
		// The worker claims an age of one hour, but the metadata says three days.
		Instant updated = COMPLETED.minus(Duration.ofDays(3));
		jobs.set(2, completed(ScannerType.TRIVY, trivy().database(updated, 3600).bytes()));

		assertThat(codes(evaluate(jobs))).contains("VULNERABILITY_DATABASE_TOO_OLD:TRIVY:null");

		jobs.set(2, completed(ScannerType.TRIVY,
				trivy().database(COMPLETED.plus(Duration.ofDays(1)), 0).bytes()));
		assertThat(codes(evaluate(jobs))).contains("VULNERABILITY_DATABASE_METADATA_INVALID:TRIVY:null");
	}

	@Test
	void staleEvidenceIsIncomplete() {
		Instant longAgo = NOW.minus(Duration.ofDays(2));
		Evaluation evaluation = evaluate(PolicyFixtures.gitleaksOnly("p"), List.of(completed(ScannerType.GITLEAKS,
				findings(PolicyScanner.GITLEAKS).bytes(), UnaryOperator.identity(), longAgo)));

		assertThat(evaluation.reasons()).containsExactly(Reason.measured(ReasonCode.EVIDENCE_STALE,
				ScannerType.GITLEAKS, Duration.ofDays(2).toSeconds(), 86400L));
	}

	// --- Scope and determinism ---------------------------------------------------------

	@Test
	void aScannerThePolicyDoesNotGovernIsIncomplete() {
		JobEvidence fixture = new JobEvidence(UUID.randomUUID(), ScannerType.FIXTURE, "COMPLETED", null, 1, COMPLETED,
				null, null, List.of());

		Evaluation evaluation = evaluate(PolicyFixtures.gitleaksOnly("p"),
				List.of(completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).bytes()), fixture));

		assertThat(codes(evaluation)).containsExactly("SCANNER_NOT_IN_POLICY:FIXTURE:null");
	}

	@Test
	void evaluationIsDeterministicRegardlessOfInputOrder() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(0, completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).finding("x").bytes()));
		jobs.set(1, completed(ScannerType.SEMGREP,
				findings(PolicyScanner.SEMGREP).incomplete("FILES_NOT_ANALYZED", "UNSUPPORTED_FILES_PRESENT").bytes()));

		Evaluation first = evaluate(jobs);
		List<JobEvidence> shuffled = new ArrayList<>(jobs);
		Collections.reverse(shuffled);
		Evaluation second = evaluate(shuffled);

		assertThat(second).isEqualTo(first);
		assertThat(PolicyEvaluationService.reasonsJson(second.reasons()))
			.isEqualTo(PolicyEvaluationService.reasonsJson(first.reasons()));
	}

	@Test
	void reasonsNeverCarryFindingContent() {
		List<JobEvidence> jobs = cleanJobs();
		jobs.set(0, completed(ScannerType.GITLEAKS, findings(PolicyScanner.GITLEAKS).finding("x").bytes()));

		String reasons = PolicyEvaluationService.reasonsJson(evaluate(jobs).reasons());

		assertThat(reasons).doesNotContain("src/file").doesNotContain("github-pat").doesNotContain("fingerprint");
		assertThat(reasons).matches("[\\x20-\\x7e]+");
	}

}

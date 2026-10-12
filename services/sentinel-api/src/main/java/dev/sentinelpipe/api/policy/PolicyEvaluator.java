package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import dev.sentinelpipe.api.policy.EvaluationInputs.Artifact;
import dev.sentinelpipe.api.policy.EvaluationInputs.EvidenceReference;
import dev.sentinelpipe.api.policy.EvaluationInputs.JobEvidence;
import dev.sentinelpipe.api.policy.EvaluationInputs.ScanContext;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import tools.jackson.databind.JsonNode;

/**
 * The deterministic policy engine (ADR-0013): a pure function of a validated policy, the
 * authoritative scan context and the evidence of record. It never reads the network, the
 * clock (the database clock is an input) or anything a worker or caller can choose.
 *
 * <p>
 * Per mandatory scanner, evidence passes these gates in order. A document that fails any
 * of the first five is <b>discarded</b>: it can neither pass nor fail the policy.
 * <ol>
 * <li>execution: the job COMPLETED (failed, cancelled or unfinished jobs have no
 * evidence);</li>
 * <li>presence: an accepted result of the current lease epoch referencing
 * {@code findings.json};</li>
 * <li>integrity: the stored result re-canonicalizes to its recorded digest, references the
 * artifact of record with the same digest, size and media type, and the artifact bytes
 * match the digest PostgreSQL computed at upload;</li>
 * <li>validity: strict JSON, an accepted {@code schema_version}, the {@code findings.v1}
 * schema;</li>
 * <li>binding and consistency: the document names this organization, project, scan, job,
 * commit and scanner, and does not contradict itself;</li>
 * <li>policy: evidence age, coverage, accepted limitations, required coverage metadata,
 * database age (Trivy), severity labels and blocking findings.</li>
 * </ol>
 * Only gate 6 can produce a violation, so FAIL is always established by valid evidence.
 * Severity labels are compared within each scanner's own scale; a label outside that scale
 * (or a missing one) is reported as {@link ReasonCode#UNSUPPORTED_SCANNER_SEVERITY}, never
 * guessed.
 */
public final class PolicyEvaluator {

	/** Recorded with every evaluation; change it whenever decision semantics change. */
	public static final String ENGINE_VERSION = "sentinelpipe-policy/1.0.0";

	public static final String EVIDENCE_NAME = "findings.json";

	public static final String EVIDENCE_MEDIA_TYPE = "application/json";

	/** The evidence artifact limit of ADR-0008. */
	public static final int MAX_EVIDENCE_BYTES = 1024 * 1024;

	/** findings.v1 schema versions this engine can interpret. */
	public static final Set<Integer> SUPPORTED_FINDINGS_VERSIONS = Set.of(1);

	/** Database timestamps further than this after the job's completion are implausible. */
	static final Duration DATABASE_FUTURE_TOLERANCE = Duration.ofHours(1);

	/** Snapshot skip reasons that make coverage incomplete (ADR-0010). */
	private static final List<String> INCOMPLETE_SKIPS = List.of("symlink", "special_file", "hardlink", "oversized",
			"unsupported_name");

	/** Limitations that explain {@code coverage.complete = false} (at least one must be present). */
	private static final Set<String> GAP_LIMITATIONS = Set.of("FILES_SKIPPED", "FILES_NOT_ANALYZED",
			"NO_SUPPORTED_FILES", "PARTIAL_DEPENDENCY_RESOLUTION", "UNRESOLVED_DEPENDENCY_VERSIONS",
			"DEPENDENCY_LOCKFILE_MISSING", "UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT", "BINARY_ARTIFACTS_NOT_ANALYZED",
			"VULNERABILITY_DB_STALE", "PYPI_NAME_MATCHING_UNVERIFIED", "DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED");

	/** Limitations that always mean {@code coverage.complete = false}, for every scanner. */
	private static final Set<String> GAP_IMPLYING_LIMITATIONS = Set.of("FILES_SKIPPED", "FILES_NOT_ANALYZED");

	/**
	 * Trivy limitations that make its coverage incomplete (the worker's {@code incomplete}
	 * list, ADR-0012). Semgrep's {@code NO_SUPPORTED_FILES} does not: Semgrep reports it with
	 * complete (empty) file coverage.
	 */
	private static final Set<String> TRIVY_GAP_IMPLYING_LIMITATIONS = Set.of("NO_SUPPORTED_FILES",
			"PARTIAL_DEPENDENCY_RESOLUTION", "UNRESOLVED_DEPENDENCY_VERSIONS", "DEPENDENCY_LOCKFILE_MISSING",
			"UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT", "BINARY_ARTIFACTS_NOT_ANALYZED", "VULNERABILITY_DB_STALE",
			"PYPI_NAME_MATCHING_UNVERIFIED", "DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED");

	private static final List<String> FILE_COVERAGE_FIELDS = List.of("files_supported", "files_analyzed",
			"files_not_analyzed", "files_unsupported", "not_analyzed_reasons");

	/** The result of an evaluation; {@code reasons} are sorted and distinct. */
	public record Evaluation(PolicyDecision decision, List<Reason> reasons, List<EvidenceReference> evidence) {

		public Evaluation {
			reasons = List.copyOf(reasons);
			evidence = List.copyOf(evidence);
		}

	}

	/**
	 * A finding the policy counted as blocking, identified as in its verified evidence. Only
	 * documents that passed gates 1 to 5 contribute; values are codes and digests only.
	 * @param scannerSeverity the scanner's own label, {@code null} for Gitleaks
	 */
	public record BlockingFinding(String fingerprint, String ruleId, String category, String scannerSeverity) {
	}

	/**
	 * An evaluation together with the blocking findings it counted, per scanner. The
	 * findings do not influence the decision beyond {@link Evaluation}; they let security
	 * exceptions (ADR-0015) name exactly which counted findings a violation consists of.
	 */
	public record Assessment(Evaluation evaluation, Map<ScannerType, List<BlockingFinding>> blockingFindings) {

		public Assessment {
			Map<ScannerType, List<BlockingFinding>> copy = new EnumMap<>(ScannerType.class);
			blockingFindings.forEach((scanner, findings) -> copy.put(scanner, List.copyOf(findings)));
			blockingFindings = Collections.unmodifiableMap(copy);
		}

	}

	public Evaluation evaluate(PolicyDefinition policy, ScanContext scan, List<JobEvidence> jobs) {
		return assess(policy, scan, jobs).evaluation();
	}

	/** {@link #evaluate}, also returning the blocking findings each scanner's count consists of. */
	public Assessment assess(PolicyDefinition policy, ScanContext scan, List<JobEvidence> jobs) {
		List<Reason> reasons = new ArrayList<>();
		Map<ScannerType, List<BlockingFinding>> blocking = new EnumMap<>(ScannerType.class);
		List<EvidenceReference> evidence = new ArrayList<>();
		Map<ScannerType, JobEvidence> byScanner = new EnumMap<>(ScannerType.class);
		jobs.forEach((job) -> byScanner.put(job.scannerType(), job));
		for (PolicyScanner scanner : policy.mandatoryScanners()) {
			if (!byScanner.containsKey(scanner.scannerType())) {
				reasons.add(Reason.of(ReasonCode.REQUIRED_SCANNER_NOT_PLANNED, scanner.scannerType()));
			}
		}
		jobs.stream()
			.sorted(Comparator.comparing(JobEvidence::scannerType))
			.forEach((job) -> evaluateJob(policy, scan, job, reasons, evidence, blocking));
		TreeSet<Reason> distinct = new TreeSet<>(Reason.ORDER);
		distinct.addAll(reasons);
		List<Reason> sorted = new ArrayList<>(distinct);
		evidence.sort(Comparator.comparing(EvidenceReference::scannerType));
		return new Assessment(new Evaluation(PolicyDecision.of(sorted), sorted, evidence), blocking);
	}

	private void evaluateJob(PolicyDefinition policy, ScanContext scan, JobEvidence job, List<Reason> reasons,
			List<EvidenceReference> evidence, Map<ScannerType, List<BlockingFinding>> blockingFindings) {
		ScannerType type = job.scannerType();
		Optional<PolicyScanner> governed = PolicyScanner.of(type).filter(policy.scanners()::containsKey);
		if (governed.isEmpty()) {
			reasons.add(Reason.of(ReasonCode.SCANNER_NOT_IN_POLICY, type));
			return;
		}
		PolicyScanner scanner = governed.get();
		PolicyDefinition.ScannerRules rules = policy.scanners().get(scanner);

		// Gate 1: execution.
		switch (job.status()) {
			case "COMPLETED" -> {
			}
			case "FAILED" -> {
				reasons.add(Reason.of(ReasonCode.SCANNER_EXECUTION_FAILED, type, safeCode(job.failureReason())));
				return;
			}
			case "CANCELLED" -> {
				reasons.add(Reason.of(ReasonCode.SCANNER_EXECUTION_CANCELLED, type));
				return;
			}
			default -> {
				reasons.add(Reason.of(ReasonCode.SCANNER_EXECUTION_UNFINISHED, type));
				return;
			}
		}

		// Gate 2: presence.
		if (job.result() == null || job.resultSha256() == null || job.completedAt() == null) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_MISSING, type, "RESULT"));
			return;
		}
		Optional<Artifact> found = job.artifacts().stream().filter((a) -> EVIDENCE_NAME.equals(a.name())).findFirst();
		if (found.isEmpty()) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_MISSING, type, "FINDINGS_ARTIFACT"));
			return;
		}
		Artifact artifact = found.get();

		// Gate 3: integrity of the result of record and of the artifact bytes.
		Optional<Reason> resultProblem = checkResult(scan, job, artifact);
		if (resultProblem.isPresent()) {
			reasons.add(resultProblem.get());
			return;
		}
		if (!EVIDENCE_MEDIA_TYPE.equals(artifact.mediaType())) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INVALID, type, "MEDIA_TYPE"));
			return;
		}
		byte[] content = artifact.content();
		if (content == null) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_PURGED, type));
			return;
		}
		if (content.length != artifact.sizeBytes() || !EvidenceVerifier.sha256(content).equals(artifact.sha256())) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INTEGRITY_FAILED, type, "ARTIFACT_DIGEST"));
			return;
		}
		evidence.add(new EvidenceReference(job.jobId(), type, job.leaseEpoch(), artifact.name(), artifact.sha256(),
				job.resultSha256()));

		// Gate 4: validity.
		if (content.length > MAX_EVIDENCE_BYTES) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INVALID, type, "SIZE"));
			return;
		}
		JsonNode document;
		try {
			document = CanonicalJson.parse(content);
		}
		catch (IllegalArgumentException ex) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INVALID, type, "JSON"));
			return;
		}
		if (!document.isObject()) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INVALID, type, "JSON"));
			return;
		}
		JsonNode version = document.get("schema_version");
		if (version != null && version.isIntegralNumber()) {
			BigInteger value = version.bigIntegerValue();
			boolean supported = value.bitLength() < 31 && SUPPORTED_FINDINGS_VERSIONS.contains(value.intValue())
					&& policy.findingsSchemaVersions().contains(value.intValue());
			if (!supported) {
				reasons.add(new Reason(ReasonCode.EVIDENCE_SCHEMA_UNSUPPORTED, type, null,
						(value.bitLength() < 63) ? value.longValue() : null, null));
				return;
			}
		}
		if (!RuntimeSchemas.validateFindings(document).isEmpty()) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INVALID, type, "SCHEMA"));
			return;
		}

		// Gate 5: binding and consistency.
		Optional<Reason> bindingProblem = checkBinding(scan, job, scanner, document);
		if (bindingProblem.isPresent()) {
			reasons.add(bindingProblem.get());
			return;
		}
		Optional<String> inconsistency = inconsistency(scanner, document);
		if (inconsistency.isPresent()) {
			reasons.add(Reason.of(ReasonCode.EVIDENCE_INCONSISTENT, type, inconsistency.get()));
			return;
		}

		// Gate 6: the policy.
		long age = secondsBetween(job.completedAt(), scan.asOf());
		if (age > policy.maxEvidenceAgeSeconds()) {
			reasons.add(Reason.measured(ReasonCode.EVIDENCE_STALE, type, age, policy.maxEvidenceAgeSeconds()));
		}
		JsonNode coverage = document.get("coverage");
		if (rules.requireCompleteCoverage() && !coverage.get("complete").booleanValue()) {
			reasons.add(Reason.of(ReasonCode.COVERAGE_INCOMPLETE, type));
		}
		for (JsonNode limitation : coverage.get("limitations").values()) {
			if (!rules.accepts(limitation.stringValue())) {
				reasons.add(Reason.of(ReasonCode.COVERAGE_LIMITATION_NOT_ACCEPTED, type, limitation.stringValue()));
			}
		}
		requiredMetadata(scanner, document)
			.forEach((missing) -> reasons.add(Reason.of(ReasonCode.COVERAGE_METADATA_MISSING, type, missing)));
		if (scanner == PolicyScanner.TRIVY && document.has("vulnerability_database")) {
			checkDatabase(rules, job, document.get("vulnerability_database"), reasons);
		}
		long blocking = 0;
		long unsupported = 0;
		List<BlockingFinding> counted = new ArrayList<>();
		for (JsonNode finding : document.get("findings").values()) {
			if (scanner.severities().isEmpty()) {
				// Gitleaks has no severity: every detected secret is blocking.
				blocking++;
				counted.add(blockingFinding(finding, null));
				continue;
			}
			JsonNode label = finding.get("scanner_severity");
			String severity = (label != null && label.isString()) ? label.stringValue() : null;
			if (severity == null || !scanner.severities().contains(severity)) {
				unsupported++;
			}
			else if (rules.blocks(severity)) {
				blocking++;
				counted.add(blockingFinding(finding, severity));
			}
		}
		blockingFindings.put(type, counted);
		if (unsupported > 0) {
			reasons.add(Reason.measured(ReasonCode.UNSUPPORTED_SCANNER_SEVERITY, type, unsupported, null));
		}
		if (blocking > rules.maxBlockingFindings()) {
			reasons.add(Reason.measured(ReasonCode.BLOCKING_FINDINGS_EXCEEDED, type, blocking,
					(long) rules.maxBlockingFindings()));
		}
	}

	/**
	 * The stored job-result.v1 document must be the accepted one (its canonical form hashes
	 * to the recorded digest), bound to this job, and reference exactly the artifact of
	 * record.
	 */
	private static Optional<Reason> checkResult(ScanContext scan, JobEvidence job, Artifact artifact) {
		ScannerType type = job.scannerType();
		JsonNode result;
		String canonical;
		try {
			result = CanonicalJson.parse(job.result());
			canonical = CanonicalJson.write(result);
		}
		catch (IllegalArgumentException ex) {
			return Optional.of(Reason.of(ReasonCode.EVIDENCE_INTEGRITY_FAILED, type, "RESULT_DOCUMENT"));
		}
		if (!EvidenceVerifier.sha256(canonical.getBytes(StandardCharsets.UTF_8)).equals(job.resultSha256())) {
			return Optional.of(Reason.of(ReasonCode.EVIDENCE_INTEGRITY_FAILED, type, "RESULT_DIGEST"));
		}
		boolean bound = text(result, "job_id").equals(job.jobId().toString())
				&& text(result, "scan_id").equals(scan.scanId().toString())
				&& text(result, "project_id").equals(scan.projectId().toString())
				&& text(result, "organization_id").equals(scan.organizationId().toString())
				&& text(result, "commit_sha").equals(scan.commitSha())
				&& text(result, "scanner_type").equals(type.name()) && text(result, "outcome").equals("COMPLETED")
				&& result.path("lease_epoch").isIntegralNumber()
				&& result.path("lease_epoch").longValue() == job.leaseEpoch();
		if (!bound) {
			return Optional.of(Reason.of(ReasonCode.EVIDENCE_BINDING_MISMATCH, type, "RESULT_CONTEXT"));
		}
		for (JsonNode reference : result.path("artifacts").values()) {
			if (text(reference, "name").equals(artifact.name())) {
				boolean same = text(reference, "sha256").equals(artifact.sha256())
						&& text(reference, "media_type").equals(artifact.mediaType())
						&& reference.path("size_bytes").isIntegralNumber()
						&& reference.path("size_bytes").longValue() == artifact.sizeBytes();
				return same ? Optional.empty()
						: Optional.of(Reason.of(ReasonCode.EVIDENCE_INTEGRITY_FAILED, type, "RESULT_ARTIFACT"));
			}
		}
		return Optional.of(Reason.of(ReasonCode.EVIDENCE_INTEGRITY_FAILED, type, "RESULT_ARTIFACT"));
	}

	private static Optional<Reason> checkBinding(ScanContext scan, JobEvidence job, PolicyScanner scanner,
			JsonNode document) {
		JsonNode context = document.get("context");
		boolean bound = text(context, "organization_id").equals(scan.organizationId().toString())
				&& text(context, "project_id").equals(scan.projectId().toString())
				&& text(context, "scan_id").equals(scan.scanId().toString())
				&& text(context, "job_id").equals(job.jobId().toString())
				&& text(context, "commit_sha").equals(scan.commitSha());
		if (!bound) {
			return Optional.of(Reason.of(ReasonCode.EVIDENCE_BINDING_MISMATCH, job.scannerType(), "FINDINGS_CONTEXT"));
		}
		if (!text(document.get("scanner"), "name").equals(scanner.evidenceName())) {
			return Optional.of(Reason.of(ReasonCode.EVIDENCE_BINDING_MISMATCH, job.scannerType(), "SCANNER"));
		}
		return Optional.empty();
	}

	/** The first self-contradiction of a schema-valid document, as a sanitized code. */
	private static Optional<String> inconsistency(PolicyScanner scanner, JsonNode document) {
		JsonNode findings = document.get("findings");
		if (document.get("finding_count").intValue() != findings.size()) {
			return Optional.of("FINDING_COUNT");
		}
		boolean detected = "FINDINGS_DETECTED".equals(text(document.get("execution"), "status"));
		if (detected != (findings.size() > 0)) {
			return Optional.of("EXECUTION_STATUS");
		}
		for (JsonNode finding : findings.values()) {
			if (!text(finding, "category").equals(scanner.category())
					|| !text(finding.get("scanner"), "name").equals(scanner.evidenceName())) {
				return Optional.of("FINDING_SCANNER");
			}
		}
		JsonNode coverage = document.get("coverage");
		Set<String> limitations = new TreeSet<>();
		coverage.get("limitations").values().forEach((value) -> limitations.add(value.stringValue()));
		if (!scanner.limitations().containsAll(limitations)) {
			return Optional.of("LIMITATIONS");
		}
		JsonNode input = document.get("input");
		if (input.get("files_scanned").intValue() == 0 && !limitations.contains("EMPTY_INPUT")) {
			return Optional.of("INPUT");
		}
		boolean complete = coverage.get("complete").booleanValue();
		// Every gap is named, and every named gap is a gap (worker contract, ADR-0010 to 0012):
		// a lax policy must never accept an incompleteness the evidence does not explain.
		boolean explained = limitations.stream().anyMatch(GAP_LIMITATIONS::contains);
		boolean implied = limitations.stream()
			.anyMatch((code) -> GAP_IMPLYING_LIMITATIONS.contains(code)
					|| (scanner == PolicyScanner.TRIVY && TRIVY_GAP_IMPLYING_LIMITATIONS.contains(code)));
		if ((!complete && !explained) || (complete && implied)) {
			return Optional.of("COVERAGE");
		}
		long incompleteSkips = INCOMPLETE_SKIPS.stream().mapToLong((key) -> input.get("skipped").get(key).longValue()).sum();
		if (complete && incompleteSkips > 0) {
			return Optional.of("COVERAGE");
		}
		if (coverage.has("files_supported") && coverage.has("files_analyzed") && coverage.has("files_not_analyzed")) {
			long supported = coverage.get("files_supported").longValue();
			long analyzed = coverage.get("files_analyzed").longValue();
			long notAnalyzed = coverage.get("files_not_analyzed").longValue();
			if (analyzed + notAnalyzed != supported || (complete && notAnalyzed > 0)) {
				return Optional.of("COVERAGE");
			}
		}
		JsonNode database = document.get("vulnerability_database");
		if (database != null) {
			if (scanner != PolicyScanner.TRIVY) {
				return Optional.of("VULNERABILITY_DATABASE");
			}
			boolean synthetic = "SYNTHETIC_FIXTURE".equals(text(database.get("source"), "kind"));
			boolean stale = "STALE".equals(text(database, "freshness"));
			if (synthetic != limitations.contains("SYNTHETIC_VULNERABILITY_DATABASE")
					|| stale != limitations.contains("VULNERABILITY_DB_STALE") || (stale && complete)) {
				return Optional.of("VULNERABILITY_DATABASE");
			}
		}
		return Optional.empty();
	}

	/** Coverage metadata a scanner must report so that its completeness can be judged. */
	private static List<String> requiredMetadata(PolicyScanner scanner, JsonNode document) {
		List<String> missing = new ArrayList<>();
		JsonNode coverage = document.get("coverage");
		if (scanner != PolicyScanner.GITLEAKS && !FILE_COVERAGE_FIELDS.stream().allMatch(coverage::has)) {
			missing.add("FILE_COVERAGE");
		}
		if (scanner == PolicyScanner.TRIVY) {
			if (!coverage.has("dependencies")) {
				missing.add("DEPENDENCY_COVERAGE");
			}
			if (!document.has("vulnerability_database")) {
				missing.add("VULNERABILITY_DATABASE");
			}
		}
		return missing;
	}

	/**
	 * Database age at the job's completion (database clock), and never less than the age the
	 * worker reported.
	 */
	private static void checkDatabase(PolicyDefinition.ScannerRules rules, JobEvidence job, JsonNode database,
			List<Reason> reasons) {
		Instant updatedAt;
		try {
			updatedAt = Instant.parse(text(database, "updated_at"));
		}
		catch (DateTimeParseException ex) {
			reasons.add(Reason.of(ReasonCode.VULNERABILITY_DATABASE_METADATA_INVALID, ScannerType.TRIVY));
			return;
		}
		if (updatedAt.isAfter(job.completedAt().plus(DATABASE_FUTURE_TOLERANCE))) {
			reasons.add(Reason.of(ReasonCode.VULNERABILITY_DATABASE_METADATA_INVALID, ScannerType.TRIVY));
			return;
		}
		long age = Math.max(secondsBetween(updatedAt, job.completedAt()), database.get("age_seconds").longValue());
		if (rules.maxDatabaseAgeSeconds() == null || age > rules.maxDatabaseAgeSeconds()) {
			reasons.add(Reason.measured(ReasonCode.VULNERABILITY_DATABASE_TOO_OLD, ScannerType.TRIVY, age,
					rules.maxDatabaseAgeSeconds()));
		}
	}

	private static BlockingFinding blockingFinding(JsonNode finding, String severity) {
		return new BlockingFinding(text(finding, "fingerprint"), text(finding, "rule_id"), text(finding, "category"),
				severity);
	}

	private static long secondsBetween(Instant from, Instant to) {
		return Math.max(0, Duration.between(from, to).getSeconds());
	}

	private static String text(JsonNode node, String field) {
		if (node == null) {
			return "";
		}
		JsonNode value = node.get(field);
		return (value != null && value.isString()) ? value.stringValue() : "";
	}

	private static String safeCode(String value) {
		return (value != null && value.matches("[A-Z][A-Z0-9_]{0,39}")) ? value : null;
	}

}

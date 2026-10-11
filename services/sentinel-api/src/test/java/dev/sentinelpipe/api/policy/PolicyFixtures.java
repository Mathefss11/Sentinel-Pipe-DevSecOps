package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Synthetic policy.v1 definitions and {@code findings.v1} evidence for policy engine tests.
 * Documents are schema-valid unless a test deliberately alters them; nothing here is real
 * scanner output.
 */
public final class PolicyFixtures {

	public static final List<String> GITLEAKS_INHERENT = List.of("ARCHIVES_NOT_SCANNED", "COMMIT_NOT_VERIFIED",
			"GIT_HISTORY_NOT_SCANNED", "RULESET_DEFAULT_ONLY");

	public static final List<String> SEMGREP_INHERENT = List.of("COMMIT_NOT_VERIFIED", "PARSE_COMPLETENESS_UNVERIFIED",
			"PATTERN_MATCHING_ONLY", "RULESET_MINIMAL");

	public static final List<String> TRIVY_INHERENT = List.of("ADVISORY_DATA_POINT_IN_TIME", "COMMIT_NOT_VERIFIED",
			"REACHABILITY_NOT_ANALYZED");

	private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

	private PolicyFixtures() {
	}

	/** Gitleaks only, no secret allowed, the scanner's inherent limitations accepted. */
	public static String gitleaksOnly(String name) {
		return """
				{"schema_version": 1, "name": "%s",
				 "evidence": {"findings_schema_versions": [1], "max_age_seconds": 86400},
				 "scanners": {"GITLEAKS": {"require_complete_coverage": true,
				   "accepted_limitations": ["ARCHIVES_NOT_SCANNED", "COMMIT_NOT_VERIFIED", "GIT_HISTORY_NOT_SCANNED",
				                            "RULESET_DEFAULT_ONLY"],
				   "max_blocking_findings": 0}}}
				""".formatted(name);
	}

	/**
	 * All three scanners, complete coverage required, only each scanner's inherent
	 * limitations (and the synthetic test database) accepted; Semgrep ERROR/WARNING and
	 * Trivy CRITICAL/HIGH are blocking; nothing blocking is allowed.
	 */
	public static String allScanners(String name) {
		return """
				{"schema_version": 1, "name": "%s",
				 "evidence": {"findings_schema_versions": [1], "max_age_seconds": 86400},
				 "scanners": {
				  "GITLEAKS": {"require_complete_coverage": true,
				   "accepted_limitations": ["ARCHIVES_NOT_SCANNED", "COMMIT_NOT_VERIFIED", "GIT_HISTORY_NOT_SCANNED",
				                            "RULESET_DEFAULT_ONLY"],
				   "max_blocking_findings": 0},
				  "SEMGREP": {"require_complete_coverage": true,
				   "accepted_limitations": ["COMMIT_NOT_VERIFIED", "PARSE_COMPLETENESS_UNVERIFIED", "PATTERN_MATCHING_ONLY",
				                            "RULESET_MINIMAL"],
				   "blocking_severities": ["ERROR", "WARNING"], "max_blocking_findings": 0},
				  "TRIVY": {"require_complete_coverage": true,
				   "accepted_limitations": ["ADVISORY_DATA_POINT_IN_TIME", "COMMIT_NOT_VERIFIED", "REACHABILITY_NOT_ANALYZED",
				                            "SYNTHETIC_VULNERABILITY_DATABASE"],
				   "blocking_severities": ["CRITICAL", "HIGH"], "max_blocking_findings": 0,
				   "max_database_age_seconds": 172800}}}
				""".formatted(name);
	}

	public static PolicyDefinition parse(String definition) {
		return PolicyDocuments.parse(definition).definition();
	}

	/** The authoritative context of one job, as a findings document must name it. */
	public record JobContext(UUID organizationId, UUID projectId, UUID scanId, UUID jobId, String commitSha) {
	}

	/** Builds a schema-valid findings.v1 document; every setter returns {@code this}. */
	public static final class Findings {

		private final PolicyScanner scanner;

		private final JobContext context;

		private boolean complete = true;

		private final TreeSet<String> limitations = new TreeSet<>();

		private int filesScanned = 2;

		private final Map<String, Integer> skipped = new LinkedHashMap<>();

		private final List<String> severities = new ArrayList<>();

		private boolean fileCoverage = true;

		private Instant databaseUpdatedAt;

		private long databaseAgeSeconds = 3600;

		private boolean synthetic = true;

		private Integer schemaVersion = 1;

		public Findings(PolicyScanner scanner, JobContext context) {
			this.scanner = scanner;
			this.context = context;
			for (String reason : List.of("symlink", "special_file", "hardlink", "oversized", "unsupported_name",
					"vcs_metadata", "suppression_file")) {
				this.skipped.put(reason, 0);
			}
			switch (scanner) {
				case GITLEAKS -> this.limitations.addAll(GITLEAKS_INHERENT);
				case SEMGREP -> this.limitations.addAll(SEMGREP_INHERENT);
				case TRIVY -> {
					this.limitations.addAll(TRIVY_INHERENT);
					this.limitations.add("SYNTHETIC_VULNERABILITY_DATABASE");
				}
			}
		}

		/** One finding per label (Gitleaks: the label is ignored, use any value). */
		public Findings finding(String severityLabel) {
			this.severities.add(severityLabel);
			return this;
		}

		public Findings incomplete(String... limitations) {
			this.complete = false;
			this.limitations.addAll(List.of(limitations));
			return this;
		}

		public Findings limitation(String limitation) {
			this.limitations.add(limitation);
			return this;
		}

		public Findings withoutFileCoverage() {
			this.fileCoverage = false;
			return this;
		}

		public Findings database(Instant updatedAt, long ageSeconds) {
			this.databaseUpdatedAt = updatedAt;
			this.databaseAgeSeconds = ageSeconds;
			return this;
		}

		public Findings upstreamDatabase() {
			this.synthetic = false;
			this.limitations.remove("SYNTHETIC_VULNERABILITY_DATABASE");
			return this;
		}

		public Findings schemaVersion(Integer version) {
			this.schemaVersion = version;
			return this;
		}

		public Findings emptyInput() {
			this.filesScanned = 0;
			this.limitations.add("EMPTY_INPUT");
			return this;
		}

		public ObjectNode node() {
			ObjectNode root = NODES.objectNode();
			root.put("schema_version", this.schemaVersion);
			ObjectNode scannerNode = root.putObject("scanner");
			scannerNode.put("name", this.scanner.evidenceName());
			scannerNode.put("version", version());
			scannerNode.put("image", "example.test/" + this.scanner.evidenceName() + "@sha256:" + "a".repeat(64));
			ObjectNode context = root.putObject("context");
			context.put("organization_id", this.context.organizationId().toString());
			context.put("project_id", this.context.projectId().toString());
			context.put("scan_id", this.context.scanId().toString());
			context.put("job_id", this.context.jobId().toString());
			context.put("commit_sha", this.context.commitSha());
			ObjectNode input = root.putObject("input");
			input.put("kind", "LOCAL_FIXTURE");
			input.put("commit_verified", false);
			input.put("content_sha256", "b".repeat(64));
			input.put("files_scanned", this.filesScanned);
			input.put("bytes_scanned", this.filesScanned * 10);
			input.put("paths_redacted", 0);
			ObjectNode skippedNode = input.putObject("skipped");
			this.skipped.forEach(skippedNode::put);
			ObjectNode coverage = root.putObject("coverage");
			coverage.put("complete", this.complete);
			ArrayNode limitationNodes = coverage.putArray("limitations");
			this.limitations.forEach(limitationNodes::add);
			if (this.scanner != PolicyScanner.GITLEAKS && this.fileCoverage) {
				int notAnalyzed = this.complete ? 0 : 1;
				coverage.put("files_supported", this.filesScanned);
				coverage.put("files_analyzed", this.filesScanned - notAnalyzed);
				coverage.put("files_not_analyzed", notAnalyzed);
				coverage.put("files_unsupported", 0);
				ObjectNode reasons = coverage.putObject("not_analyzed_reasons");
				reasons.put("scanner_skipped", notAnalyzed);
				reasons.put("parse_error", 0);
				reasons.put("resource_limit", 0);
				reasons.put("unverifiable_encoding", 0);
			}
			if (this.scanner == PolicyScanner.TRIVY) {
				ObjectNode dependencies = coverage.putObject("dependencies");
				for (String key : List.of("packages", "packages_unresolved", "packages_development",
						"manifests_partial", "manifests_lockfile_missing", "unsupported_dependency_files",
						"binary_artifacts")) {
					dependencies.put(key, key.equals("packages") ? 3 : 0);
				}
				Instant updated = (this.databaseUpdatedAt != null) ? this.databaseUpdatedAt
						: Instant.now().minusSeconds(this.databaseAgeSeconds);
				ObjectNode database = root.putObject("vulnerability_database");
				database.put("schema_version", 2);
				database.put("updated_at", updated.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString());
				database.put("next_update",
						updated.plusSeconds(86400).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString());
				database.put("age_seconds", Math.min(this.databaseAgeSeconds, 604800));
				boolean stale = this.limitations.contains("VULNERABILITY_DB_STALE");
				database.put("freshness", stale ? "STALE" : "FRESH");
				database.put("trivy_db_sha256", "c".repeat(64));
				database.put("metadata_sha256", "d".repeat(64));
				ObjectNode source = database.putObject("source");
				if (this.synthetic) {
					source.put("kind", "SYNTHETIC_FIXTURE");
					source.put("builder", "github.com/aquasecurity/trivy-db@v0.0.0-20261001090913-650c4091f951");
					source.put("advisories_sha256", "e".repeat(64));
				}
				else {
					source.put("kind", "UPSTREAM_OCI");
					source.put("repository", "ghcr.io/aquasecurity/trivy-db");
					source.put("manifest_digest", "sha256:" + "1".repeat(64));
					source.put("blob_digest", "sha256:" + "2".repeat(64));
				}
				ObjectNode image = database.putObject("image");
				image.put("config_digest", "sha256:" + "3".repeat(64));
				image.put("id", "sha256:" + "4".repeat(64));
			}
			ObjectNode execution = root.putObject("execution");
			execution.put("status", this.severities.isEmpty() ? "NO_FINDINGS" : "FINDINGS_DETECTED");
			execution.put("exit_code", this.severities.isEmpty() ? 0 : 41);
			execution.put("raw_report_sha256", "f".repeat(64));
			root.put("finding_count", this.severities.size());
			ArrayNode findings = root.putArray("findings");
			for (int i = 0; i < this.severities.size(); i++) {
				findings.add(finding(i, this.severities.get(i)));
			}
			return root;
		}

		public byte[] bytes() {
			return CanonicalJson.write(node()).getBytes(StandardCharsets.US_ASCII);
		}

		private String version() {
			return switch (this.scanner) {
				case GITLEAKS -> "8.30.1";
				case SEMGREP -> "1.179.0";
				case TRIVY -> "0.75.0";
			};
		}

		private ObjectNode finding(int index, String severity) {
			ObjectNode finding = NODES.objectNode();
			String fingerprint = EvidenceVerifier.sha256((this.context.jobId() + "/" + index).getBytes(StandardCharsets.UTF_8));
			finding.put("id", UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString());
			finding.put("fingerprint", fingerprint);
			ObjectNode scannerNode = finding.putObject("scanner");
			scannerNode.put("name", this.scanner.evidenceName());
			scannerNode.put("version", version());
			finding.put("category", this.scanner.category());
			finding.putNull("description");
			ObjectNode location = finding.putObject("location");
			location.put("path_redacted", false);
			if (this.scanner == PolicyScanner.TRIVY) {
				finding.put("rule_id", "GHSA-2f2f-3g3g-" + String.format("%04d", index));
				location.put("target", "DEPENDENCY_MANIFEST");
				location.put("path", "package-lock.json");
				location.putNull("start_line");
				location.putNull("end_line");
				ObjectNode pkg = finding.putObject("package");
				pkg.put("ecosystem", "npm");
				pkg.put("name", "sentinelpipe-fixture-" + index);
				pkg.put("installed_version", "1.0.0");
				pkg.putArray("fixed_versions").add("1.0.1");
				pkg.putNull("development");
				pkg.put("redacted", false);
				ObjectNode advisory = finding.putObject("advisory");
				advisory.putArray("aliases");
				advisory.put("data_source", "ghsa");
				advisory.put("status", "fixed");
			}
			else {
				finding.put("rule_id", this.scanner == PolicyScanner.GITLEAKS ? "github-pat" : "sentinelpipe.python.code-injection-eval");
				location.put("target", "FILE_CONTENT");
				location.put("path", "src/file" + index + ".py");
				location.put("start_line", 1);
				location.put("end_line", 1);
			}
			if (this.scanner == PolicyScanner.TRIVY) {
				location.putNull("start_column");
				location.putNull("end_column");
			}
			else {
				location.put("start_column", 1);
				location.put("end_column", 2);
			}
			if (this.scanner != PolicyScanner.GITLEAKS && severity != null) {
				finding.put("scanner_severity", severity);
			}
			finding.putNull("severity");
			finding.putNull("confidence");
			ObjectNode evidence = finding.putObject("evidence");
			evidence.put("redacted", true);
			evidence.putNull("excerpt");
			finding.putNull("remediation");
			finding.put("status", "OPEN");
			finding.put("occurrences", 1);
			return finding;
		}

	}

}

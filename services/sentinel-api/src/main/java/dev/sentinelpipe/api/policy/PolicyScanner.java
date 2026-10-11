package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.Optional;
import java.util.Set;

/**
 * Scanners a policy.v1 definition can govern, with the vocabulary of their
 * {@code findings.v1} evidence. Severity labels are each scanner's own scale, kept
 * verbatim: they are never mapped onto a shared scale (Semgrep's {@code ERROR} is not
 * Trivy's {@code HIGH}). Gitleaks reports no severity at all.
 */
public enum PolicyScanner {

	GITLEAKS(ScannerType.GITLEAKS, "gitleaks", "SECRET", Set.of(),
			Set.of("FILES_SKIPPED", "EMPTY_INPUT", "COMMIT_NOT_VERIFIED", "GIT_HISTORY_NOT_SCANNED",
					"ARCHIVES_NOT_SCANNED", "RULESET_DEFAULT_ONLY")),

	SEMGREP(ScannerType.SEMGREP, "semgrep", "CODE_PATTERN", Set.of("ERROR", "WARNING", "INFO"),
			Set.of("FILES_SKIPPED", "EMPTY_INPUT", "COMMIT_NOT_VERIFIED", "FILES_NOT_ANALYZED",
					"UNSUPPORTED_FILES_PRESENT", "NO_SUPPORTED_FILES", "RULESET_MINIMAL", "PATTERN_MATCHING_ONLY",
					"PARSE_COMPLETENESS_UNVERIFIED")),

	TRIVY(ScannerType.TRIVY, "trivy", "DEPENDENCY_VULNERABILITY", Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"),
			Set.of("FILES_SKIPPED", "EMPTY_INPUT", "COMMIT_NOT_VERIFIED", "FILES_NOT_ANALYZED", "NO_SUPPORTED_FILES",
					"ADVISORY_DATA_POINT_IN_TIME", "REACHABILITY_NOT_ANALYZED", "VULNERABILITY_DB_STALE",
					"SYNTHETIC_VULNERABILITY_DATABASE", "PARTIAL_DEPENDENCY_RESOLUTION", "UNRESOLVED_DEPENDENCY_VERSIONS",
					"DEPENDENCY_LOCKFILE_MISSING", "UNSUPPORTED_DEPENDENCY_FORMATS_PRESENT",
					"BINARY_ARTIFACTS_NOT_ANALYZED", "PACKAGE_VALUES_REDACTED", "PYPI_NAME_MATCHING_UNVERIFIED",
					"DEVELOPMENT_DEPENDENCIES_NOT_ANALYZED"));

	/**
	 * Limitations a policy can never accept: the scanner examined nothing, so its evidence
	 * cannot support PASS. Absence of findings is not proof of security.
	 */
	public static final Set<String> NEVER_ACCEPTABLE = Set.of("EMPTY_INPUT", "NO_SUPPORTED_FILES");

	private final ScannerType scannerType;

	private final String evidenceName;

	private final String category;

	private final Set<String> severities;

	private final Set<String> limitations;

	PolicyScanner(ScannerType scannerType, String evidenceName, String category, Set<String> severities,
			Set<String> limitations) {
		this.scannerType = scannerType;
		this.evidenceName = evidenceName;
		this.category = category;
		this.severities = severities;
		this.limitations = limitations;
	}

	public ScannerType scannerType() {
		return this.scannerType;
	}

	/** {@code scanner.name} in this scanner's {@code findings.v1} documents. */
	public String evidenceName() {
		return this.evidenceName;
	}

	/** The only finding category this scanner produces. */
	public String category() {
		return this.category;
	}

	/** The scanner's own severity labels; empty when it reports none (Gitleaks). */
	public Set<String> severities() {
		return this.severities;
	}

	/** Limitation codes this scanner's evidence can carry. */
	public Set<String> limitations() {
		return this.limitations;
	}

	public static Optional<PolicyScanner> of(ScannerType scannerType) {
		for (PolicyScanner scanner : values()) {
			if (scanner.scannerType == scannerType) {
				return Optional.of(scanner);
			}
		}
		return Optional.empty();
	}

}

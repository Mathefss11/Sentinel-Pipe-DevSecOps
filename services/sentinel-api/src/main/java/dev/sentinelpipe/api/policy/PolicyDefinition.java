package dev.sentinelpipe.api.policy;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * A validated policy.v1 definition ({@link PolicyDocuments}). Every scanner listed in
 * {@code scanners} is mandatory: its evidence must be present and valid for PASS.
 *
 * @param findingsSchemaVersions {@code findings.v1} schema versions accepted as evidence
 * @param maxEvidenceAgeSeconds maximum age of a job's evidence at evaluation, measured
 * from the job's completion (database clock)
 */
public record PolicyDefinition(String name, SortedSet<Integer> findingsSchemaVersions, long maxEvidenceAgeSeconds,
		Map<PolicyScanner, ScannerRules> scanners) {

	public PolicyDefinition {
		findingsSchemaVersions = Collections.unmodifiableSortedSet(new TreeSet<>(findingsSchemaVersions));
		scanners = Collections.unmodifiableMap(new EnumMap<>(scanners));
	}

	/**
	 * Requirements for one mandatory scanner.
	 *
	 * @param requireCompleteCoverage whether {@code coverage.complete = false} makes the
	 * evaluation INCOMPLETE
	 * @param acceptedLimitations limitation codes the policy explicitly accepts; any other
	 * limitation makes the evaluation INCOMPLETE
	 * @param blockingSeverities the scanner's own severity labels whose findings count
	 * against {@code maxBlockingFindings} (empty for Gitleaks, where every finding counts)
	 * @param maxBlockingFindings more blocking findings than this is a violation (FAIL)
	 * @param maxDatabaseAgeSeconds Trivy only: maximum vulnerability database age
	 */
	public record ScannerRules(boolean requireCompleteCoverage, SortedSet<String> acceptedLimitations,
			SortedSet<String> blockingSeverities, int maxBlockingFindings, Long maxDatabaseAgeSeconds) {

		public ScannerRules {
			acceptedLimitations = Collections.unmodifiableSortedSet(new TreeSet<>(acceptedLimitations));
			blockingSeverities = Collections.unmodifiableSortedSet(new TreeSet<>(blockingSeverities));
		}

		public boolean accepts(String limitation) {
			return this.acceptedLimitations.contains(limitation);
		}

		public boolean blocks(String severity) {
			return this.blockingSeverities.contains(severity);
		}

	}

	public Set<PolicyScanner> mandatoryScanners() {
		return this.scanners.keySet();
	}

}

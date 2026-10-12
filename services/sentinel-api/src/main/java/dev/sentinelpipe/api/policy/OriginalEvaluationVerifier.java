package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.policy.EvaluationInputs.EvidenceReference;
import dev.sentinelpipe.api.policy.EvaluationInputs.ScanContext;
import dev.sentinelpipe.api.policy.PolicyEvaluator.Assessment;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Re-runs a scan's ORIGINAL evaluation over its current evidence of record (ADR-0015).
 *
 * <p>
 * Security exceptions refer to findings of the original evaluation. Before an exception is
 * requested, approved or applied, the engine is run again with the pinned policy version,
 * as of the original decision time, over the evidence of record as it is stored now. The
 * original is <b>reproducible</b> only if the engine version, decision, canonical reasons
 * and evidence references are identical to the record. Anything else (purged, altered or
 * substituted evidence, an unusable stored policy, a different engine) means the findings
 * the record was based on can no longer be shown, so no exception can be based on them:
 * fail closed. The original record is only read, never changed.
 */
@Component
class OriginalEvaluationVerifier {

	/** The original evaluation and what the engine computes for it now. */
	record Verification(PolicyService.EvaluationRecord original, Assessment assessment, boolean reproducible) {

		/** The evidence reference the reproduced evaluation used for {@code scanner}, if any. */
		Optional<EvidenceReference> evidenceOf(String scanner) {
			return this.assessment.evaluation()
				.evidence()
				.stream()
				.filter((reference) -> reference.scannerType().name().equals(scanner))
				.findFirst();
		}

	}

	private final JdbcTemplate jdbc;

	private final PolicyService policies;

	private final PolicyEvaluationService evaluations;

	OriginalEvaluationVerifier(JdbcTemplate jdbc, PolicyService policies, PolicyEvaluationService evaluations) {
		this.jdbc = jdbc;
		this.policies = policies;
		this.evaluations = evaluations;
	}

	/**
	 * Runs in the caller's transaction, which should be a REPEATABLE READ snapshot. Empty if
	 * the scan has no original evaluation.
	 */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<Verification> verify(UUID scanId) {
		Optional<PolicyService.EvaluationRecord> found = this.policies.evaluation(scanId);
		if (found.isEmpty()) {
			return Optional.empty();
		}
		PolicyService.EvaluationRecord original = found.get();
		Map<String, Object> version = this.jdbc.queryForMap(
				"SELECT v.definition, v.definition_sha256, s.commit_sha FROM policy.policy_versions v, scans s"
						+ " WHERE v.id = ? AND s.id = ?",
				original.policyVersionId(), scanId);
		PolicyDocuments.ValidatedPolicy policy;
		try {
			policy = PolicyDocuments.parseStored((String) version.get("definition"),
					(String) version.get("definition_sha256"));
		}
		catch (IllegalArgumentException ex) {
			Assessment unusable = new Assessment(new PolicyEvaluator.Evaluation(PolicyDecision.INCOMPLETE,
					List.of(Reason.of(ReasonCode.POLICY_INVALID, null)), List.of()), Map.of());
			return Optional.of(new Verification(original, unusable, false));
		}
		ScanContext scan = new ScanContext(scanId, original.projectId(), original.organizationId(),
				(String) version.get("commit_sha"), original.evaluatedAsOf());
		Assessment assessment = this.evaluations.assess(policy.definition(), scan, this.evaluations.jobs(scanId));
		PolicyEvaluator.Evaluation evaluation = assessment.evaluation();
		boolean reproducible = PolicyEvaluator.ENGINE_VERSION.equals(original.engineVersion())
				&& evaluation.decision().name().equals(original.decision())
				&& PolicyEvaluationService.reasonsJson(evaluation.reasons()).equals(original.reasons())
				&& references(evaluation.evidence()).equals(recorded(original.evidence()));
		return Optional.of(new Verification(original, assessment, reproducible));
	}

	private static Set<String> references(List<EvidenceReference> evidence) {
		return evidence.stream()
			.map((e) -> String.join("|", e.jobId().toString(), e.scannerType().name(), Long.toString(e.leaseEpoch()),
					e.name(), e.sha256(), e.resultSha256()))
			.collect(Collectors.toSet());
	}

	private static Set<String> recorded(List<PolicyService.EvaluatedEvidence> evidence) {
		return evidence.stream()
			.map((e) -> String.join("|", e.jobId().toString(), e.scannerType(), Long.toString(e.leaseEpoch()), e.name(),
					e.sha256(), e.resultSha256()))
			.collect(Collectors.toSet());
	}

}

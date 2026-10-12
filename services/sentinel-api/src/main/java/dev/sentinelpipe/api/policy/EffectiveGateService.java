package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.policy.EvaluationInputs.EvidenceReference;
import dev.sentinelpipe.api.policy.PolicyEvaluator.BlockingFinding;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The effective security gate of a scan (ADR-0015): the original policy decision, with
 * active security exceptions applied, computed on every request and never persisted.
 *
 * <p>
 * The original decision is never changed. The effective decision is:
 * <ul>
 * <li>{@code PASS}: the original decision is PASS (no exception is involved);</li>
 * <li>{@code RISK_ACCEPTED}: the original decision is FAIL on complete evidence, the
 * original evaluation is reproducible from the current evidence of record, and every
 * violation is covered: after removing the findings of active, precisely bound exceptions
 * from the blocking count, no scanner exceeds its limit. It is deliberately <b>not</b>
 * PASS;</li>
 * <li>{@code FAIL}: at least one violation is not covered;</li>
 * <li>{@code INCOMPLETE}: anything else that cannot be shown: the scan is not completed,
 * has no original evaluation, its original decision is INCOMPLETE, the original evaluation
 * is not reproducible, or incomplete conditions remain after all violations are
 * covered.</li>
 * </ul>
 * Exceptions never cover an incomplete condition. Everything is read in one REPEATABLE
 * READ snapshot: an exception is active if it is approved, not revoked and unexpired at the
 * database time of that snapshot ({@code evaluatedAt}); {@code validUntil} is the earliest
 * expiry among the applied exceptions, after which the result must not be used.
 */
@Service
public class EffectiveGateService {

	/** Effective decisions; RISK_ACCEPTED is never PASS. */
	public enum EffectiveDecision {

		PASS, FAIL, INCOMPLETE, RISK_ACCEPTED

	}

	/** Why the effective decision is what it is. Codes, scanners and counts only. */
	public enum GateReasonCode {

		/** The scan has not completed; it has no final original decision yet. */
		SCAN_NOT_COMPLETED,

		/** The scan completed without a policy evaluation (no pinned policy). */
		ORIGINAL_EVALUATION_MISSING,

		/** The original decision is INCOMPLETE; exceptions never cover incomplete evidence. */
		ORIGINAL_INCOMPLETE,

		/** The original evaluation cannot be reproduced from the current evidence of record. */
		ORIGINAL_NOT_REPRODUCIBLE,

		/** A violation remains: {@code observed} blocking findings not excepted, over {@code limit}. */
		VIOLATION_NOT_EXCEPTED,

		/** A violation is covered: {@code observed} findings excepted, the rest within {@code limit}. */
		VIOLATION_EXCEPTED,

		/** All violations are covered, but the original evaluation has {@code observed} incomplete reasons. */
		INCOMPLETE_CONDITIONS_REMAIN

	}

	public record GateReason(GateReasonCode code, ScannerType scanner, Long observed, Long limit) {
	}

	/** An exception the effective decision relies on. */
	public record AppliedException(UUID id, ScannerType scannerType, String fingerprint, Instant expiresAt) {
	}

	/**
	 * @param originalDecision the scan's recorded security decision (unchanged)
	 * @param evaluationId the original evaluation, or {@code null}
	 * @param exceptionBased whether the decision relies on accepted risk
	 * @param validUntil for RISK_ACCEPTED, the earliest expiry of the applied exceptions
	 */
	public record EffectiveGate(UUID scanId, String executionStatus, String originalDecision, UUID evaluationId,
			EffectiveDecision effectiveDecision, boolean exceptionBased, List<GateReason> reasons,
			List<AppliedException> appliedExceptions, Instant evaluatedAt, Instant validUntil) {
	}

	private record Active(UUID id, UUID evaluationId, UUID policyVersionId, String policySha256, String engineVersion,
			UUID jobId, String scannerType, long leaseEpoch, String artifactSha256, String resultSha256,
			String fingerprint, String ruleId, String category, String scannerSeverity, Instant expiresAt) {
	}

	private record ScanState(String executionStatus, String securityDecision, Instant databaseNow) {
	}

	private final JdbcTemplate jdbc;

	private final OriginalEvaluationVerifier verifier;

	private final TransactionTemplate snapshot;

	EffectiveGateService(JdbcTemplate jdbc, OriginalEvaluationVerifier verifier,
			PlatformTransactionManager transactions) {
		this.jdbc = jdbc;
		this.verifier = verifier;
		this.snapshot = new TransactionTemplate(transactions);
		this.snapshot.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		this.snapshot.setReadOnly(true);
	}

	public EffectiveGate compute(UUID scanId) {
		return Objects.requireNonNull(this.snapshot.execute((status) -> computeInSnapshot(scanId)));
	}

	private EffectiveGate computeInSnapshot(UUID scanId) {
		ScanState state = this.jdbc
			.query("SELECT execution_status, security_decision, now() AS database_now FROM scans WHERE id = ?",
					(rs, row) -> new ScanState(rs.getString("execution_status"), rs.getString("security_decision"),
							rs.getObject("database_now", OffsetDateTime.class).toInstant()),
					scanId)
			.stream()
			.findFirst()
			.orElseThrow(() -> new ResourceNotFoundException("Scan", scanId));
		String executionStatus = state.executionStatus();
		String originalDecision = state.securityDecision();
		Instant now = state.databaseNow();
		if (!"COMPLETED".equals(executionStatus)) {
			return incomplete(scanId, executionStatus, originalDecision, null, now, GateReasonCode.SCAN_NOT_COMPLETED);
		}
		Optional<OriginalEvaluationVerifier.Verification> found = this.verifier.verify(scanId);
		if (found.isEmpty()) {
			return incomplete(scanId, executionStatus, originalDecision, null, now,
					GateReasonCode.ORIGINAL_EVALUATION_MISSING);
		}
		OriginalEvaluationVerifier.Verification verification = found.get();
		PolicyService.EvaluationRecord original = verification.original();
		switch (original.decision()) {
			case "PASS" -> {
				return new EffectiveGate(scanId, executionStatus, originalDecision, original.id(),
						EffectiveDecision.PASS, false, List.of(), List.of(), now, null);
			}
			case "FAIL" -> {
			}
			default -> {
				return incomplete(scanId, executionStatus, originalDecision, original.id(), now,
						GateReasonCode.ORIGINAL_INCOMPLETE);
			}
		}
		if (!verification.reproducible()) {
			return incomplete(scanId, executionStatus, originalDecision, original.id(), now,
					GateReasonCode.ORIGINAL_NOT_REPRODUCIBLE);
		}

		List<Active> active = activeExceptions(scanId, original);
		List<GateReason> reasons = new ArrayList<>();
		List<AppliedException> applied = new ArrayList<>();
		boolean uncovered = false;
		for (Reason violation : verification.assessment().evaluation().reasons()) {
			if (violation.effect() != ReasonEffect.VIOLATION) {
				continue;
			}
			ScannerType scanner = violation.scanner();
			if (violation.code() != ReasonCode.BLOCKING_FINDINGS_EXCEEDED || scanner == null
					|| violation.limit() == null) {
				// Only blocking-finding violations can be excepted.
				reasons.add(new GateReason(GateReasonCode.VIOLATION_NOT_EXCEPTED, scanner, violation.observed(),
						violation.limit()));
				uncovered = true;
				continue;
			}
			List<BlockingFinding> blocking = verification.assessment().blockingFindings().getOrDefault(scanner, List.of());
			Optional<EvidenceReference> evidence = verification.evidenceOf(scanner.name());
			Map<String, Active> covering = new LinkedHashMap<>();
			for (Active exception : active) {
				if (evidence.isPresent() && covers(exception, scanner, evidence.get(), blocking)) {
					covering.putIfAbsent(exception.fingerprint(), exception);
				}
			}
			long remaining = blocking.size() - covering.size();
			if (remaining > violation.limit()) {
				reasons.add(new GateReason(GateReasonCode.VIOLATION_NOT_EXCEPTED, scanner, remaining, violation.limit()));
				uncovered = true;
			}
			else {
				reasons.add(new GateReason(GateReasonCode.VIOLATION_EXCEPTED, scanner, (long) covering.size(),
						violation.limit()));
				covering.values()
					.forEach((e) -> applied.add(new AppliedException(e.id(), scanner, e.fingerprint(), e.expiresAt())));
			}
		}
		applied.sort(Comparator.comparing(AppliedException::scannerType).thenComparing(AppliedException::id));
		if (uncovered) {
			return new EffectiveGate(scanId, executionStatus, originalDecision, original.id(), EffectiveDecision.FAIL,
					false, reasons, applied, now, null);
		}
		if (original.incompleteCount() > 0) {
			reasons.add(new GateReason(GateReasonCode.INCOMPLETE_CONDITIONS_REMAIN, null,
					(long) original.incompleteCount(), null));
			return new EffectiveGate(scanId, executionStatus, originalDecision, original.id(),
					EffectiveDecision.INCOMPLETE, false, reasons, applied, now, null);
		}
		Instant validUntil = applied.stream().map(AppliedException::expiresAt).min(Comparator.naturalOrder()).orElse(null);
		return new EffectiveGate(scanId, executionStatus, originalDecision, original.id(),
				EffectiveDecision.RISK_ACCEPTED, true, reasons, applied, now, validUntil);
	}

	/**
	 * An exception covers a finding only if it is bound to exactly this evaluation's policy,
	 * engine and evidence, and its fingerprint, rule, category and severity name a blocking
	 * finding that occurs exactly once in that evidence.
	 */
	private static boolean covers(Active exception, ScannerType scanner, EvidenceReference evidence,
			List<BlockingFinding> blocking) {
		if (!exception.scannerType().equals(scanner.name()) || !exception.jobId().equals(evidence.jobId())
				|| exception.leaseEpoch() != evidence.leaseEpoch()
				|| !exception.artifactSha256().equals(evidence.sha256())
				|| !exception.resultSha256().equals(evidence.resultSha256())) {
			return false;
		}
		List<BlockingFinding> matches = blocking.stream()
			.filter((finding) -> finding.fingerprint().equals(exception.fingerprint()))
			.toList();
		return matches.size() == 1 && matches.get(0).ruleId().equals(exception.ruleId())
				&& matches.get(0).category().equals(exception.category())
				&& Objects.equals(matches.get(0).scannerSeverity(), exception.scannerSeverity());
	}

	private List<Active> activeExceptions(UUID scanId, PolicyService.EvaluationRecord original) {
		return this.jdbc.query("""
				SELECT id, evaluation_id, policy_version_id, policy_sha256, engine_version, job_id, scanner_type,
				       lease_epoch, artifact_sha256, result_sha256, finding_fingerprint, finding_rule_id,
				       finding_category, finding_scanner_severity, expires_at
				FROM policy.exception_status
				WHERE scan_id = ? AND status = 'ACTIVE' AND evaluation_id = ? AND policy_version_id = ?
				  AND policy_sha256 = ? AND engine_version = ?
				ORDER BY requested_at, id""",
				(rs, row) -> new Active(rs.getObject("id", UUID.class), rs.getObject("evaluation_id", UUID.class),
						rs.getObject("policy_version_id", UUID.class), rs.getString("policy_sha256"),
						rs.getString("engine_version"), rs.getObject("job_id", UUID.class), rs.getString("scanner_type"),
						rs.getLong("lease_epoch"), rs.getString("artifact_sha256"), rs.getString("result_sha256"),
						rs.getString("finding_fingerprint"), rs.getString("finding_rule_id"),
						rs.getString("finding_category"), rs.getString("finding_scanner_severity"),
						rs.getObject("expires_at", OffsetDateTime.class).toInstant()),
				scanId, original.id(), original.policyVersionId(), original.policySha256(), original.engineVersion());
	}

	private static EffectiveGate incomplete(UUID scanId, String executionStatus, String originalDecision,
			UUID evaluationId, Instant now, GateReasonCode code) {
		return new EffectiveGate(scanId, executionStatus, originalDecision, evaluationId, EffectiveDecision.INCOMPLETE,
				false, List.of(new GateReason(code, null, null, null)), List.of(), now, null);
	}

}

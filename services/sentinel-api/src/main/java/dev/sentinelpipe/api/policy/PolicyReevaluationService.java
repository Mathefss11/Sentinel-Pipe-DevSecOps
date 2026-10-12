package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.policy.EvaluationInputs.JobEvidence;
import dev.sentinelpipe.api.policy.EvaluationInputs.ScanContext;
import dev.sentinelpipe.api.policy.PolicyEvaluator.Evaluation;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Historical policy re-evaluation (ADR-0014): what decision would an explicitly chosen
 * policy version produce for the evidence of record a completed scan already has?
 *
 * <p>
 * Inputs are read like the original evaluation's ({@code policy.job_evidence}), in one
 * REPEATABLE READ snapshot together with the historical as-of instant (the original
 * decision time) and a database-computed fingerprint of those inputs. The same engine and
 * fail-closed handling as {@link PolicyEvaluationService} produce the decision. The record
 * is written by {@code policy.record_historical_evaluation}, which recomputes the
 * fingerprint under the scan row lock, re-checks the record like
 * {@code policy.record_evaluation}, and returns the existing record for a repeated
 * identity (scan, policy version, engine version, inputs).
 *
 * <p>
 * Nothing about the scan changes: not its execution state, decision, pinned policy, jobs,
 * original evaluation or the project's active policy, and no message is published. Callers
 * authorize the requester first. Evidence is never taken from the request.
 */
@Service
public class PolicyReevaluationService {

	/** Historical records per scan; enforced by the database. */
	public static final int MAX_PER_SCAN = 100;

	static final String SCAN_NOT_COMPLETED = "scan-not-completed";

	static final String POLICY_VERSION_UNUSABLE = "policy-version-unusable";

	static final String LIMIT_REACHED = "reevaluation-limit-reached";

	static final String INPUTS_CHANGED = "evaluation-inputs-changed";

	private static final Logger log = LoggerFactory.getLogger(PolicyReevaluationService.class);

	/** What {@link #reevaluate} did. */
	public enum Outcome {

		/** A new historical record was written. */
		RECORDED,

		/** The same re-evaluation was recorded before; nothing was written. */
		EXISTING

	}

	public record Result(Outcome outcome, UUID evaluationId) {
	}

	private record Inputs(ScanContext scan, String inputsSha256, UUID policyVersionId, String definition,
			String policySha256, List<JobEvidence> jobs) {
	}

	private final JdbcTemplate jdbc;

	private final PolicyEvaluationService evaluations;

	private final TransactionTemplate snapshot;

	private final TransactionTemplate writer;

	PolicyReevaluationService(JdbcTemplate jdbc, PolicyEvaluationService evaluations,
			PlatformTransactionManager transactions) {
		this.jdbc = jdbc;
		this.evaluations = evaluations;
		this.snapshot = new TransactionTemplate(transactions);
		this.snapshot.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		this.snapshot.setReadOnly(true);
		this.writer = new TransactionTemplate(transactions);
	}

	/**
	 * Re-evaluates a COMPLETED scan under a policy version of the scan's organization.
	 * @param actor audited server-side identity of the requester ({@code user:<uuid>})
	 * @throws ResourceNotFoundException if the scan does not exist, or the policy version
	 * does not exist or belongs to another organization (indistinguishable)
	 * @throws ConflictException if the scan is not COMPLETED, the stored policy version no
	 * longer validates, the per-scan limit is reached, or the evidence keeps changing
	 */
	public Result reevaluate(UUID scanId, UUID policyVersionId, String actor) {
		Objects.requireNonNull(scanId, "scanId");
		Objects.requireNonNull(policyVersionId, "policyVersionId");
		Objects.requireNonNull(actor, "actor");
		// One retry: evidence retention may purge content between reading and recording.
		for (int attempt = 1;; attempt++) {
			Inputs inputs = Objects.requireNonNull(this.snapshot.execute((status) -> read(scanId, policyVersionId)));
			Evaluation evaluation = evaluate(inputs);
			try {
				Result result = Objects.requireNonNull(this.writer.execute((status) -> record(inputs, evaluation, actor)));
				log.info("policy.reevaluated scan_id={} policy_version_id={} decision={} outcome={} evaluation_id={}",
						scanId, policyVersionId, evaluation.decision(), result.outcome(), result.evaluationId());
				return result;
			}
			catch (DataAccessException ex) {
				if (!rejectedAs(ex, "INPUTS_CHANGED")) {
					throw ex;
				}
				if (attempt >= 2) {
					throw new ConflictException(INPUTS_CHANGED,
							"The scan's evidence changed while it was being re-evaluated. Retry the request.");
				}
			}
		}
	}

	private Inputs read(UUID scanId, UUID policyVersionId) {
		List<Map<String, Object>> contexts = this.jdbc.queryForList("SELECT * FROM policy.historical_context(?)",
				scanId);
		if (contexts.isEmpty()) {
			throw new ResourceNotFoundException("Scan", scanId);
		}
		Map<String, Object> context = contexts.get(0);
		if (!"COMPLETED".equals(context.get("execution_status")) || context.get("evaluated_as_of") == null) {
			throw new ConflictException(SCAN_NOT_COMPLETED, "Only a COMPLETED scan can be re-evaluated.");
		}
		UUID organizationId = (UUID) context.get("organization_id");
		// A version of another organization is reported exactly like one that does not exist.
		List<Map<String, Object>> versions = this.jdbc.queryForList(
				"SELECT definition, definition_sha256 FROM policy.policy_versions WHERE id = ? AND organization_id = ?",
				policyVersionId, organizationId);
		if (versions.isEmpty()) {
			throw new ResourceNotFoundException("PolicyVersion", policyVersionId);
		}
		ScanContext scan = new ScanContext(scanId, (UUID) context.get("project_id"), organizationId,
				(String) context.get("commit_sha"), asOf(context.get("evaluated_as_of")));
		return new Inputs(scan, (String) context.get("inputs_sha256"), policyVersionId,
				(String) versions.get(0).get("definition"), (String) versions.get(0).get("definition_sha256"),
				this.evaluations.jobs(scanId));
	}

	/**
	 * The stored version must still validate against its schema and digest: unlike the
	 * gate (which records POLICY_INVALID), an unusable version requested explicitly is a
	 * request failure and nothing is recorded.
	 */
	private Evaluation evaluate(Inputs inputs) {
		PolicyDocuments.ValidatedPolicy policy;
		try {
			policy = PolicyDocuments.parseStored(inputs.definition(), inputs.policySha256());
		}
		catch (IllegalArgumentException ex) {
			log.error("policy.invalid_stored_policy scan_id={} policy_version_id={}", inputs.scan().scanId(),
					inputs.policyVersionId());
			throw new ConflictException(POLICY_VERSION_UNUSABLE,
					"The policy version does not validate against its schema and digest and cannot be evaluated.");
		}
		return this.evaluations.evaluate(policy.definition(), inputs.scan(), inputs.jobs());
	}

	private Result record(Inputs inputs, Evaluation evaluation, String actor) {
		Map<String, Object> row = this.jdbc.queryForMap(
				"SELECT * FROM policy.record_historical_evaluation(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				inputs.scan().scanId(), inputs.policyVersionId(), inputs.policySha256(),
				PolicyEvaluator.ENGINE_VERSION, evaluation.decision().name(),
				PolicyEvaluationService.reasonsJson(evaluation.reasons()),
				PolicyEvaluationService.evidenceJson(evaluation.evidence()),
				inputs.scan().asOf().atOffset(ZoneOffset.UTC), inputs.inputsSha256(), actor);
		String outcome = String.valueOf(row.get("outcome"));
		UUID id = (UUID) row.get("evaluation_id");
		return switch (outcome) {
			case "RECORDED" -> new Result(Outcome.RECORDED, id);
			case "EXISTING" -> new Result(Outcome.EXISTING, id);
			case "NOT_FOUND" -> throw new ResourceNotFoundException("Scan", inputs.scan().scanId());
			case "NOT_COMPLETED" -> throw new ConflictException(SCAN_NOT_COMPLETED,
					"Only a COMPLETED scan can be re-evaluated.");
			case "POLICY_VERSION_NOT_FOUND" -> throw new ResourceNotFoundException("PolicyVersion",
					inputs.policyVersionId());
			case "LIMIT_REACHED" -> throw new ConflictException(LIMIT_REACHED,
					"The scan has reached the maximum of " + MAX_PER_SCAN + " historical re-evaluations.");
			default -> throw new IllegalStateException(
					"Unexpected policy.record_historical_evaluation outcome: " + outcome);
		};
	}

	private static Instant asOf(Object value) {
		if (value instanceof OffsetDateTime time) {
			return time.toInstant();
		}
		if (value instanceof Timestamp timestamp) {
			return timestamp.toInstant();
		}
		throw new IllegalStateException("Unexpected as-of value");
	}

	private static boolean rejectedAs(DataAccessException ex, String code) {
		Throwable cause = ex.getMostSpecificCause();
		String message = (cause != null) ? cause.getMessage() : null;
		return message != null && message.contains("evaluation rejected: " + code);
	}

}

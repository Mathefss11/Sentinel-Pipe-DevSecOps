package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.policy.EvaluationInputs.Artifact;
import dev.sentinelpipe.api.policy.EvaluationInputs.EvidenceReference;
import dev.sentinelpipe.api.policy.EvaluationInputs.JobEvidence;
import dev.sentinelpipe.api.policy.EvaluationInputs.ScanContext;
import dev.sentinelpipe.api.policy.PolicyEvaluator.Evaluation;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Evaluates a policy-pinned scan and records the result (ADR-0013).
 *
 * <p>
 * Inputs are read through {@code policy.evaluation_context} and {@code policy.job_evidence}
 * in the caller's transaction, which already holds the scan row lock: once a scan is
 * EVALUATING every job is terminal, so no worker can change its evidence, and the lock
 * keeps concurrent evaluators and cancellation out until the record is written. The
 * evaluator is a pure function of those inputs. {@code policy.record_evaluation} then
 * re-checks the record against the database (decision precedence, evidence of record,
 * PASS backstops, pinned policy) and completes the scan atomically.
 *
 * <p>
 * Failures are fail-closed: a pinned policy that no longer validates is recorded as
 * INCOMPLETE ({@link ReasonCode#POLICY_INVALID}), and an unexpected engine error as
 * INCOMPLETE ({@link ReasonCode#EVALUATION_ERROR}). A record the database refuses leaves
 * the scan EVALUATING (decision PENDING, never mergeable) for the next pass.
 */
@Service
public class PolicyEvaluationService {

	/** What {@link #evaluate} did. */
	public enum Outcome {

		/** An evaluation was recorded and the scan completed with its decision. */
		RECORDED,

		/** The scan is unknown or no longer EVALUATING: nothing was done. */
		NOT_EVALUATING,

		/** The scan has no pinned policy; the caller records INCOMPLETE without one. */
		NO_POLICY

	}

	private static final Logger log = LoggerFactory.getLogger(PolicyEvaluationService.class);

	private final JdbcTemplate jdbc;

	private final PolicyEvaluator evaluator = new PolicyEvaluator();

	PolicyEvaluationService(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	private record Context(ScanContext scan, String executionStatus, UUID policyVersionId, String definition,
			String sha256) {
	}

	/** Runs in the caller's transaction, which must hold the scan row lock. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Outcome evaluate(UUID scanId) {
		List<Context> contexts = this.jdbc.query("SELECT * FROM policy.evaluation_context(?)",
				(rs, row) -> new Context(
						new ScanContext(rs.getObject("scan_id", UUID.class), rs.getObject("project_id", UUID.class),
								rs.getObject("organization_id", UUID.class), rs.getString("commit_sha"),
								rs.getObject("database_now", OffsetDateTime.class).toInstant()),
						rs.getString("execution_status"), rs.getObject("policy_version_id", UUID.class),
						rs.getString("policy_definition"), rs.getString("policy_sha256")),
				scanId);
		if (contexts.isEmpty() || !"EVALUATING".equals(contexts.get(0).executionStatus())) {
			return Outcome.NOT_EVALUATING;
		}
		Context context = contexts.get(0);
		if (context.policyVersionId() == null) {
			return Outcome.NO_POLICY;
		}
		Evaluation evaluation = evaluate(context, jobs(scanId));
		String outcome = this.jdbc.queryForObject("SELECT policy.record_evaluation(?, ?, ?, ?, ?, ?, ?, ?)",
				String.class, scanId, context.policyVersionId(), context.sha256(), PolicyEvaluator.ENGINE_VERSION,
				evaluation.decision().name(), reasonsJson(evaluation.reasons()), evidenceJson(evaluation.evidence()),
				context.scan().asOf().atOffset(ZoneOffset.UTC));
		if ("COMPLETED".equals(outcome)) {
			log.info("policy.evaluated scan_id={} policy_version_id={} decision={} reasons={}", scanId,
					context.policyVersionId(), evaluation.decision(), evaluation.reasons().size());
			return Outcome.RECORDED;
		}
		if ("NOT_EVALUATING".equals(outcome) || "NOT_FOUND".equals(outcome)) {
			return Outcome.NOT_EVALUATING;
		}
		throw new IllegalStateException("Unexpected policy.record_evaluation outcome: " + outcome);
	}

	private Evaluation evaluate(Context context, List<JobEvidence> jobs) {
		PolicyDocuments.ValidatedPolicy policy;
		try {
			policy = PolicyDocuments.parseStored(context.definition(), context.sha256());
		}
		catch (IllegalArgumentException ex) {
			log.error("policy.invalid_stored_policy scan_id={} policy_version_id={}", context.scan().scanId(),
					context.policyVersionId());
			return incomplete(ReasonCode.POLICY_INVALID);
		}
		return evaluate(policy.definition(), context.scan(), jobs);
	}

	/**
	 * Runs the engine on a validated policy. An unexpected engine error is INCOMPLETE
	 * ({@link ReasonCode#EVALUATION_ERROR}): fail closed. Shared with historical
	 * re-evaluation ({@link PolicyReevaluationService}), so both use one set of semantics.
	 */
	Evaluation evaluate(PolicyDefinition policy, ScanContext scan, List<JobEvidence> jobs) {
		try {
			return this.evaluator.evaluate(policy, scan, jobs);
		}
		catch (RuntimeException ex) {
			// Fail closed and record why; the exception never carries evidence content.
			log.error("policy.evaluation_error scan_id={} error_type={}", scan.scanId(),
					ex.getClass().getSimpleName());
			return incomplete(ReasonCode.EVALUATION_ERROR);
		}
	}

	private static Evaluation incomplete(ReasonCode code) {
		return new Evaluation(PolicyDecision.INCOMPLETE, List.of(Reason.of(code, null)), List.of());
	}

	/** Every job of the scan with its evidence of record, in the caller's transaction. */
	List<JobEvidence> jobs(UUID scanId) {
		Map<UUID, JobEvidence> jobs = new LinkedHashMap<>();
		Map<UUID, List<Artifact>> artifacts = new LinkedHashMap<>();
		this.jdbc.query("SELECT * FROM policy.job_evidence(?)", (rs) -> {
			UUID jobId = rs.getObject("job_id", UUID.class);
			if (!jobs.containsKey(jobId)) {
				OffsetDateTime completedAt = rs.getObject("job_completed_at", OffsetDateTime.class);
				jobs.put(jobId, new JobEvidence(jobId, ScannerType.valueOf(rs.getString("scanner_type")),
						stringOrThrow(rs.getString("job_status")), rs.getString("failure_reason"),
						longValue(rs.getObject("lease_epoch")), (completedAt != null) ? completedAt.toInstant() : null,
						rs.getString("result_sha256"), rs.getString("result"), List.of()));
			}
			List<Artifact> list = artifacts.computeIfAbsent(jobId, (id) -> new ArrayList<>());
			String name = rs.getString("artifact_name");
			if (name != null) {
				list.add(new Artifact(name, rs.getString("artifact_media_type"), rs.getString("artifact_sha256"),
						rs.getLong("artifact_size"), rs.getBytes("artifact_content")));
			}
		}, scanId);
		List<JobEvidence> result = new ArrayList<>();
		jobs.forEach((id, job) -> result.add(new JobEvidence(job.jobId(), job.scannerType(), job.status(),
				job.failureReason(), job.leaseEpoch(), job.completedAt(), job.resultSha256(), job.result(),
				artifacts.getOrDefault(id, List.of()))));
		return result;
	}

	static String reasonsJson(List<Reason> reasons) {
		ArrayNode array = JsonNodeFactory.instance.arrayNode();
		reasons.forEach((reason) -> array.add(reason.toJson()));
		return CanonicalJson.write(array);
	}

	static String evidenceJson(List<EvidenceReference> evidence) {
		ArrayNode array = JsonNodeFactory.instance.arrayNode();
		for (EvidenceReference reference : evidence) {
			ObjectNode node = array.addObject();
			node.put("job_id", reference.jobId().toString());
			node.put("lease_epoch", reference.leaseEpoch());
			node.put("name", reference.name());
			node.put("result_sha256", reference.resultSha256());
			node.put("scanner_type", reference.scannerType().name());
			node.put("sha256", reference.sha256());
		}
		return CanonicalJson.write(array);
	}

	private static String stringOrThrow(String value) {
		if (value == null) {
			throw new IllegalStateException("job without status");
		}
		return value;
	}

	private static long longValue(Object value) {
		return (value instanceof Number number) ? number.longValue() : 0L;
	}

}

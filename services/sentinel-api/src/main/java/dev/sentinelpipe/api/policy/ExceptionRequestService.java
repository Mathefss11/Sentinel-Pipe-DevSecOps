package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.DomainValidationException;
import dev.sentinelpipe.api.common.ForbiddenException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.policy.PolicyEvaluator.BlockingFinding;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Security exceptions with independent approval (ADR-0015): requests to accept one verified
 * blocking finding of one scan's original FAIL evaluation, and their append-only
 * transitions.
 *
 * <p>
 * Every operation is checked twice. The API first re-runs the original evaluation over the
 * current evidence of record ({@link OriginalEvaluationVerifier}) and checks the finding,
 * the state and the actor; {@code policy.request_exception} and
 * {@code policy.transition_exception} then derive the binding from stored records and
 * enforce the same rules under a row lock, with triggers and constraints as the backstop
 * for any writer. Identities are server-derived {@code user:<uuid>} references; callers
 * authorize the requester for the scan's organization first.
 *
 * <p>
 * Nothing here changes a scan, its decision, its evidence, its original evaluation or a
 * historical re-evaluation, and nothing is published or dispatched.
 */
@Service
public class ExceptionRequestService {

	/** Requests per scan; enforced by the database. */
	public static final int MAX_PER_SCAN = 200;

	static final String SCAN_NOT_EXCEPTIONABLE = "scan-not-exceptionable";

	static final String NOT_REPRODUCIBLE = "evaluation-not-reproducible";

	static final String FINDING_NOT_EXCEPTIONABLE = "finding-not-exceptionable";

	static final String REQUEST_EXISTS = "exception-request-exists";

	static final String LIMIT_REACHED = "exception-limit-reached";

	static final String INVALID_TRANSITION = "invalid-exception-transition";

	static final String EXPIRED = "exception-expired";

	static final String EXPIRES_TOO_SOON = "exception-expires-too-soon";

	static final String SELF_DECISION = "self-decision-forbidden";

	static final String NOT_REQUESTER = "not-requester";

	static final String INSUFFICIENT_ROLE = "insufficient-role";

	private static final Logger log = LoggerFactory.getLogger(ExceptionRequestService.class);

	/** Transitions a caller can request; REQUESTED is only the creation step. */
	public enum Action {

		APPROVE("APPROVED"), REJECT("REJECTED"), WITHDRAW("WITHDRAWN"), REVOKE("REVOKED");

		private final String targetState;

		Action(String targetState) {
			this.targetState = targetState;
		}

		public String targetState() {
			return this.targetState;
		}

	}

	/** One recorded transition. */
	public record Transition(int sequence, String fromState, String toState, String actor, String actorRole,
			String rationale, Instant occurredAt) {
	}

	/**
	 * A request with its binding, its last recorded {@code state} and its {@code status} at
	 * the database clock ({@code statusAsOf}): ACTIVE only for an unexpired approval.
	 */
	public record ExceptionRecord(UUID id, UUID scanId, UUID projectId, UUID organizationId, UUID evaluationId,
			UUID policyVersionId, String policySha256, String engineVersion, UUID jobId, String scannerType,
			long leaseEpoch, String artifactSha256, String resultSha256, String fingerprint, String ruleId,
			String category, String scannerSeverity, String justification, String requestedBy, Instant requestedAt,
			Instant expiresAt, String state, String status, Instant statusAsOf, List<Transition> transitions) {
	}

	private static final String SELECT_STATUS = """
			SELECT id, organization_id, project_id, scan_id, evaluation_id, policy_version_id, policy_sha256,
			       engine_version, job_id, scanner_type, lease_epoch, artifact_sha256, result_sha256,
			       finding_fingerprint, finding_rule_id, finding_category, finding_scanner_severity, justification,
			       requested_by, requested_at, expires_at, state, status, status_as_of
			FROM policy.exception_status""";

	private final JdbcTemplate jdbc;

	private final OriginalEvaluationVerifier verifier;

	private final TransactionTemplate snapshot;

	private final TransactionTemplate writer;

	private final TransactionTemplate reader;

	ExceptionRequestService(JdbcTemplate jdbc, OriginalEvaluationVerifier verifier,
			PlatformTransactionManager transactions) {
		this.jdbc = jdbc;
		this.verifier = verifier;
		this.snapshot = new TransactionTemplate(transactions);
		this.snapshot.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		this.snapshot.setReadOnly(true);
		this.writer = new TransactionTemplate(transactions);
		this.reader = new TransactionTemplate(transactions);
		this.reader.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		this.reader.setReadOnly(true);
	}

	/**
	 * Requests an exception for the blocking finding {@code fingerprint} of {@code scanner}
	 * in the scan's original FAIL evaluation.
	 * @param actor the requester's server-side identity ({@code user:<uuid>})
	 * @return the new request's id
	 * @throws ConflictException if the scan, the evaluation or the finding is not eligible,
	 * an open request or active exception exists for the finding, or the limit is reached
	 */
	public UUID request(UUID scanId, ScannerType scanner, String fingerprint, String justification, Instant expiresAt,
			String actor) {
		Objects.requireNonNull(scanId, "scanId");
		Objects.requireNonNull(scanner, "scanner");
		Objects.requireNonNull(actor, "actor");
		// The database counts characters as code points.
		if (justification.codePointCount(0, justification.length()) < 20) {
			throw new DomainValidationException("justification", "size must be between 20 and 2000");
		}
		this.snapshot.executeWithoutResult((status) -> requireTarget(scanId, scanner, fingerprint));
		Map<String, Object> row = Objects.requireNonNull(write("justification", () -> this.jdbc.queryForMap(
				"SELECT * FROM policy.request_exception(?, ?, ?, ?, ?, ?)", scanId, scanner.name(), fingerprint,
				justification, expiresAt.atOffset(ZoneOffset.UTC), actor)));
		String outcome = String.valueOf(row.get("outcome"));
		UUID id = (UUID) row.get("exception_id");
		log.info("policy.exception_requested scan_id={} scanner={} outcome={} exception_id={}", scanId, scanner, outcome,
				id);
		return switch (outcome) {
			case "CREATED" -> id;
			case "DUPLICATE" -> throw new ConflictException(REQUEST_EXISTS,
					"An open request or an active exception already exists for this finding: " + id + ".");
			case "NOT_FOUND" -> throw new ResourceNotFoundException("Scan", scanId);
			case "SCAN_NOT_ELIGIBLE" -> throw scanNotExceptionable();
			case "FINDING_NOT_ELIGIBLE" -> throw findingNotExceptionable();
			case "EVIDENCE_UNAVAILABLE" -> throw notReproducible();
			case "NOT_AUTHORIZED" -> throw insufficientRole();
			case "INVALID_EXPIRY" -> throw new DomainValidationException("expiresAt",
					"must be at least 1 hour and 1 minute and at most 90 days after the request");
			case "LIMIT_REACHED" -> throw new ConflictException(LIMIT_REACHED,
					"The scan has reached the maximum of " + MAX_PER_SCAN + " exception requests.");
			default -> throw new IllegalStateException("Unexpected policy.request_exception outcome: " + outcome);
		};
	}

	/**
	 * Moves the request {@code exceptionId} of scan {@code scanId} through {@code action}.
	 * Approval additionally requires that the original evaluation is still reproducible and
	 * that the finding is still one of its blocking findings.
	 * @param actor the actor's server-side identity ({@code user:<uuid>})
	 * @throws ResourceNotFoundException if the request does not exist or belongs to another
	 * scan
	 * @throws ForbiddenException if the actor is the requester of a decision, not the
	 * requester of a withdrawal, or lacks the role
	 * @throws ConflictException if the request is not in a state this action leaves, or it
	 * expired
	 */
	public void transition(UUID scanId, UUID exceptionId, Action action, String actor, String rationale) {
		Objects.requireNonNull(action, "action");
		Objects.requireNonNull(actor, "actor");
		ExceptionRecord current = find(scanId, exceptionId)
			.orElseThrow(() -> new ResourceNotFoundException("SecurityException", exceptionId));
		// Application-level checks; the database repeats them under the request's row lock.
		boolean ownRequest = current.requestedBy().equals(actor);
		if ((action == Action.APPROVE || action == Action.REJECT) && ownRequest) {
			throw selfDecision();
		}
		if (action == Action.WITHDRAW && !ownRequest) {
			throw notRequester();
		}
		if (action == Action.APPROVE) {
			this.snapshot.executeWithoutResult((status) -> requireTarget(scanId,
					ScannerType.valueOf(current.scannerType()), current.fingerprint()));
		}
		String outcome = write("rationale", () -> this.jdbc.queryForObject(
				"SELECT policy.transition_exception(?, ?, ?, ?)", String.class, exceptionId, action.targetState(), actor,
				rationale));
		log.info("policy.exception_transition scan_id={} exception_id={} action={} outcome={}", scanId, exceptionId,
				action, outcome);
		switch (String.valueOf(outcome)) {
			case "TRANSITIONED" -> {
			}
			case "NOT_FOUND" -> throw new ResourceNotFoundException("SecurityException", exceptionId);
			case "INVALID_STATE" -> throw new ConflictException(INVALID_TRANSITION,
					"The exception request is not in a state from which it can be "
							+ action.targetState().toLowerCase(Locale.ROOT) + ".");
			case "EXPIRED" -> throw new ConflictException(EXPIRED, "The exception request has expired.");
			case "EXPIRES_TOO_SOON" -> throw new ConflictException(EXPIRES_TOO_SOON,
					"The exception request expires in less than 5 minutes and can no longer be approved.");
			case "NOT_AUTHORIZED" -> throw insufficientRole();
			case "SELF_DECISION" -> throw selfDecision();
			case "NOT_REQUESTER" -> throw notRequester();
			case "EVIDENCE_UNAVAILABLE" -> throw notReproducible();
			default -> throw new IllegalStateException("Unexpected policy.transition_exception outcome: " + outcome);
		}
	}

	/**
	 * Runs a write function in its own transaction. Refusals the database can raise after the
	 * function's own checks passed are client conditions, not server errors: the expiry passing
	 * between the function's check and the insert (the CHECK uses the later database time), and
	 * text the database's character classes refuse although the API's pattern accepted it.
	 */
	private <T> T write(String textField, Supplier<T> call) {
		try {
			return this.writer.execute((status) -> call.get());
		}
		catch (DataAccessException ex) {
			Throwable cause = ex.getMostSpecificCause();
			String message = (cause != null && cause.getMessage() != null) ? cause.getMessage() : "";
			if (message.contains("ck_exception_transitions_before_expiry")) {
				throw new ConflictException(EXPIRED, "The exception request has expired.");
			}
			if (message.contains("ck_exception_transitions_approval_window")) {
				throw new ConflictException(EXPIRES_TOO_SOON,
						"The exception request expires in less than 5 minutes and can no longer be approved.");
			}
			if (message.contains("ck_exception_requests_lifetime")) {
				throw new DomainValidationException("expiresAt",
						"must be at least 1 hour and 1 minute and at most 90 days after the request");
			}
			if (message.contains("exception rejected: INVALID_ARGUMENTS")) {
				throw new DomainValidationException(textField, "contains characters that are not accepted");
			}
			throw ex;
		}
	}

	/** One request of the scan with its transitions; empty if it belongs to another scan. */
	public Optional<ExceptionRecord> find(UUID scanId, UUID exceptionId) {
		return Objects.requireNonNull(this.reader.execute((status) -> withTransitions(
				this.jdbc.query(SELECT_STATUS + " WHERE scan_id = ? AND id = ?", ExceptionRequestService::row, scanId,
						exceptionId))))
			.stream()
			.findFirst();
	}

	/** A page of the scan's requests, oldest first (request time, then id). */
	public Page<ExceptionRecord> list(UUID scanId, int page, int size) {
		return Objects.requireNonNull(this.reader.execute((status) -> {
			Long total = this.jdbc.queryForObject("SELECT count(*) FROM policy.exception_requests WHERE scan_id = ?",
					Long.class, scanId);
			List<ExceptionRecord> records = withTransitions(
					this.jdbc.query(SELECT_STATUS + " WHERE scan_id = ? ORDER BY requested_at, id LIMIT ? OFFSET ?",
							ExceptionRequestService::row, scanId, size, (long) page * size));
			return new PageImpl<>(records, PageRequest.of(page, size), (total != null) ? total : 0L);
		}));
	}

	/**
	 * The target must be a blocking finding, present exactly once, of a scanner with a
	 * violation in the scan's original FAIL evaluation, and that evaluation must be
	 * reproducible from the current evidence of record. Runs in a snapshot.
	 */
	private void requireTarget(UUID scanId, ScannerType scanner, String fingerprint) {
		List<Map<String, Object>> scans = this.jdbc
			.queryForList("SELECT execution_status, security_decision FROM scans WHERE id = ?", scanId);
		if (scans.isEmpty()) {
			throw new ResourceNotFoundException("Scan", scanId);
		}
		if (!"COMPLETED".equals(scans.get(0).get("execution_status"))
				|| !"FAIL".equals(scans.get(0).get("security_decision"))) {
			throw scanNotExceptionable();
		}
		OriginalEvaluationVerifier.Verification verification = this.verifier.verify(scanId)
			.orElseThrow(ExceptionRequestService::scanNotExceptionable);
		if (!"FAIL".equals(verification.original().decision())) {
			throw scanNotExceptionable();
		}
		if (!verification.reproducible()) {
			throw notReproducible();
		}
		boolean violated = verification.assessment()
			.evaluation()
			.reasons()
			.stream()
			.anyMatch((reason) -> reason.code() == ReasonCode.BLOCKING_FINDINGS_EXCEEDED && reason.scanner() == scanner);
		List<BlockingFinding> blocking = verification.assessment().blockingFindings().getOrDefault(scanner, List.of());
		if (!violated || blocking.stream().filter((finding) -> finding.fingerprint().equals(fingerprint)).count() != 1) {
			throw findingNotExceptionable();
		}
	}

	private List<ExceptionRecord> withTransitions(List<ExceptionRecord> records) {
		if (records.isEmpty()) {
			return records;
		}
		Map<UUID, List<Transition>> transitions = new HashMap<>();
		String placeholders = String.join(", ", Collections.nCopies(records.size(), "?"));
		this.jdbc.query("SELECT request_id, seq, from_state, to_state, actor, actor_role, rationale, occurred_at"
				+ " FROM policy.exception_transitions WHERE request_id IN (" + placeholders + ") ORDER BY request_id, seq",
				(RowCallbackHandler) (rs) -> transitions
					.computeIfAbsent(rs.getObject("request_id", UUID.class), (id) -> new ArrayList<>())
					.add(new Transition(rs.getInt("seq"), rs.getString("from_state"), rs.getString("to_state"),
							rs.getString("actor"), rs.getString("actor_role"), rs.getString("rationale"),
							instant(rs, "occurred_at"))),
				records.stream().map(ExceptionRecord::id).toArray());
		return records.stream()
			.map((r) -> new ExceptionRecord(r.id(), r.scanId(), r.projectId(), r.organizationId(), r.evaluationId(),
					r.policyVersionId(), r.policySha256(), r.engineVersion(), r.jobId(), r.scannerType(), r.leaseEpoch(),
					r.artifactSha256(), r.resultSha256(), r.fingerprint(), r.ruleId(), r.category(), r.scannerSeverity(),
					r.justification(), r.requestedBy(), r.requestedAt(), r.expiresAt(), r.state(), r.status(),
					r.statusAsOf(), List.copyOf(transitions.getOrDefault(r.id(), List.of()))))
			.toList();
	}

	private static ExceptionRecord row(ResultSet rs, int row) throws SQLException {
		return new ExceptionRecord(rs.getObject("id", UUID.class), rs.getObject("scan_id", UUID.class),
				rs.getObject("project_id", UUID.class), rs.getObject("organization_id", UUID.class),
				rs.getObject("evaluation_id", UUID.class), rs.getObject("policy_version_id", UUID.class),
				rs.getString("policy_sha256"), rs.getString("engine_version"), rs.getObject("job_id", UUID.class),
				rs.getString("scanner_type"), rs.getLong("lease_epoch"), rs.getString("artifact_sha256"),
				rs.getString("result_sha256"), rs.getString("finding_fingerprint"), rs.getString("finding_rule_id"),
				rs.getString("finding_category"), rs.getString("finding_scanner_severity"),
				rs.getString("justification"), rs.getString("requested_by"), instant(rs, "requested_at"),
				instant(rs, "expires_at"), rs.getString("state"), rs.getString("status"),
				instant(rs, "status_as_of"), List.of());
	}

	private static Instant instant(ResultSet rs, String column) throws SQLException {
		OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
		return (value != null) ? value.toInstant() : null;
	}

	private static ConflictException scanNotExceptionable() {
		return new ConflictException(SCAN_NOT_EXCEPTIONABLE,
				"Only a COMPLETED scan whose original policy decision is FAIL can have security exceptions.");
	}

	private static ConflictException notReproducible() {
		return new ConflictException(NOT_REPRODUCIBLE,
				"The scan's original evaluation cannot be reproduced from its current evidence of record.");
	}

	private static ConflictException findingNotExceptionable() {
		return new ConflictException(FINDING_NOT_EXCEPTIONABLE,
				"The finding is not a blocking finding of a policy violation in the scan's original evaluation.");
	}

	private static ForbiddenException insufficientRole() {
		return new ForbiddenException(INSUFFICIENT_ROLE, "Your organization role does not permit this operation.");
	}

	private static ForbiddenException selfDecision() {
		return new ForbiddenException(SELF_DECISION,
				"An exception must be approved or rejected by someone other than its requester.");
	}

	private static ForbiddenException notRequester() {
		return new ForbiddenException(NOT_REQUESTER, "Only the requester can withdraw an exception request.");
	}

}

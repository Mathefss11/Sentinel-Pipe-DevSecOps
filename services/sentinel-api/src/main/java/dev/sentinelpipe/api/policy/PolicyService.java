package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.common.ResourceNotFoundException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Policy versions, project activation, scan pinning and evaluation records (ADR-0013).
 *
 * <p>
 * Writes go through the {@code policy.*} database functions, which enforce immutability,
 * version numbering and tenant consistency; the API has no write access to the policy
 * tables. Callers authorize the requester for the owning organization first: an
 * identifier is never authorization.
 */
@Service
public class PolicyService {

	private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

	/** An immutable policy version; {@code definition} is the canonical policy.v1 text. */
	public record PolicyVersion(UUID id, UUID policyId, UUID organizationId, String name, int version,
			int schemaVersion, String definition, String definitionSha256, Instant createdAt) {
	}

	/** The policy version in force for a project. */
	public record ActivePolicy(UUID projectId, PolicyVersion policyVersion, Instant assignedAt) {
	}

	/** Evidence of record an evaluation relied on. */
	public record EvaluatedEvidence(UUID jobId, String scannerType, long leaseEpoch, String name, String sha256,
			String resultSha256) {
	}

	/** An immutable evaluation record; {@code reasons} is canonical JSON. */
	public record EvaluationRecord(UUID id, UUID scanId, UUID projectId, UUID organizationId, UUID policyVersionId,
			String policySha256, String engineVersion, String decision, int violationCount, int incompleteCount,
			String reasons, Instant evaluatedAsOf, Instant recordedAt, List<EvaluatedEvidence> evidence) {
	}

	private static final String VERSION_COLUMNS = """
			v.id, v.policy_id, v.organization_id, p.name, v.version, v.schema_version, v.definition,
			v.definition_sha256, v.created_at""";

	private final JdbcTemplate jdbc;

	PolicyService(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	/**
	 * Validates and stores a new version of the definition's policy in the organization.
	 * @param actor audited server-side identity of the requester
	 * @throws dev.sentinelpipe.api.common.InvalidDocumentException if the definition is not
	 * valid policy.v1
	 */
	@Transactional
	public PolicyVersion createVersion(UUID organizationId, String definition, String actor) {
		PolicyDocuments.ValidatedPolicy policy = PolicyDocuments.parse(definition);
		UUID id = this.jdbc.queryForObject(
				"SELECT policy_version_id FROM policy.create_policy_version(?, ?, ?, ?)", UUID.class, organizationId,
				policy.definition().name(), policy.canonical(), actor);
		PolicyVersion created = findVersion(id).orElseThrow();
		log.info("policy.version_created organization_id={} policy_version_id={} version={} sha256={}",
				organizationId, created.id(), created.version(), created.definitionSha256());
		return created;
	}

	@Transactional(readOnly = true)
	public Optional<PolicyVersion> findVersion(UUID policyVersionId) {
		return this.jdbc.query("SELECT " + VERSION_COLUMNS
				+ " FROM policy.policy_versions v JOIN policy.policies p ON p.id = v.policy_id WHERE v.id = ?",
				PolicyService::version, policyVersionId).stream().findFirst();
	}

	/**
	 * Activates a version for a project. A version of another organization is reported as
	 * not found, exactly like one that does not exist.
	 */
	@Transactional
	public ActivePolicy activate(UUID projectId, UUID policyVersionId, String actor) {
		String outcome = this.jdbc.queryForObject("SELECT policy.assign_project_policy(?, ?, ?)", String.class,
				projectId, policyVersionId, actor);
		switch (String.valueOf(outcome)) {
			case "ASSIGNED" -> log.info("policy.activated project_id={} policy_version_id={}", projectId,
					policyVersionId);
			case "UNCHANGED" -> {
			}
			case "PROJECT_NOT_FOUND" -> throw new ResourceNotFoundException("Project", projectId);
			case "POLICY_VERSION_NOT_FOUND" -> throw new ResourceNotFoundException("PolicyVersion", policyVersionId);
			default -> throw new IllegalStateException("Unexpected policy.assign_project_policy outcome: " + outcome);
		}
		return activePolicy(projectId).orElseThrow();
	}

	@Transactional(readOnly = true)
	public Optional<ActivePolicy> activePolicy(UUID projectId) {
		return this.jdbc.query("SELECT a.project_id, a.assigned_at, " + VERSION_COLUMNS + """
				 FROM policy.project_assignments a
				 JOIN policy.policy_versions v ON v.id = a.policy_version_id
				 JOIN policy.policies p ON p.id = v.policy_id
				WHERE a.project_id = ?
				ORDER BY a.id DESC LIMIT 1""",
				(rs, row) -> new ActivePolicy(rs.getObject("project_id", UUID.class), version(rs, row),
						instant(rs, "assigned_at")),
				projectId)
			.stream()
			.findFirst();
	}

	/**
	 * Pins the project's active policy version to a scan being created; must run in the
	 * scan's creating transaction. Empty when the project has no active policy.
	 */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<UUID> pinScan(UUID scanId) {
		return Optional.ofNullable(this.jdbc.queryForObject("SELECT policy.pin_scan_policy(?)", UUID.class, scanId));
	}

	@Transactional(readOnly = true)
	public Optional<EvaluationRecord> evaluation(UUID scanId) {
		List<EvaluatedEvidence> evidence = this.jdbc.query("""
				SELECT e.job_id, e.scanner_type, e.lease_epoch, e.name, e.sha256, e.result_sha256
				FROM policy.evaluation_evidence e JOIN policy.evaluations v ON v.id = e.evaluation_id
				WHERE v.scan_id = ? ORDER BY e.scanner_type, e.job_id""",
				(rs, row) -> new EvaluatedEvidence(rs.getObject("job_id", UUID.class), rs.getString("scanner_type"),
						rs.getLong("lease_epoch"), rs.getString("name"), rs.getString("sha256"),
						rs.getString("result_sha256")),
				scanId);
		return this.jdbc.query("SELECT * FROM policy.evaluations WHERE scan_id = ?",
				(rs, row) -> new EvaluationRecord(rs.getObject("id", UUID.class), rs.getObject("scan_id", UUID.class),
						rs.getObject("project_id", UUID.class), rs.getObject("organization_id", UUID.class),
						rs.getObject("policy_version_id", UUID.class), rs.getString("policy_sha256"),
						rs.getString("engine_version"), rs.getString("decision"), rs.getInt("violation_count"),
						rs.getInt("incomplete_count"), rs.getString("reasons"), instant(rs, "evaluated_as_of"),
						instant(rs, "recorded_at"), evidence),
				scanId)
			.stream()
			.findFirst();
	}

	private static PolicyVersion version(ResultSet rs, int row) throws SQLException {
		return new PolicyVersion(rs.getObject("id", UUID.class), rs.getObject("policy_id", UUID.class),
				rs.getObject("organization_id", UUID.class), rs.getString("name"), rs.getInt("version"),
				rs.getInt("schema_version"), rs.getString("definition"), rs.getString("definition_sha256"),
				instant(rs, "created_at"));
	}

	private static Instant instant(ResultSet rs, String column) throws SQLException {
		OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
		return (value != null) ? value.toInstant() : null;
	}

}

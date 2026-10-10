package dev.sentinelpipe.api.evidence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Evidence in PostgreSQL ({@code evidence} schema, Flyway V008), read through the
 * {@code SECURITY DEFINER} functions granted to the API; the API has no table access.
 * The database already refuses content that does not match its address; the content is
 * verified again here, so the guarantee does not depend on the storage backend.
 */
@Component
public class DatabaseEvidenceStore implements EvidenceStore {

	private static final Logger log = LoggerFactory.getLogger(DatabaseEvidenceStore.class);

	private final JdbcTemplate jdbc;

	DatabaseEvidenceStore(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public List<EvidenceArtifact> list(UUID jobId) {
		return this.jdbc.query("SELECT * FROM evidence.list_result_artifacts(?)",
				(rs, row) -> new EvidenceArtifact(rs.getLong("lease_epoch"), rs.getString("name"),
						rs.getString("media_type"), rs.getString("sha256"), rs.getLong("size_bytes"),
						rs.getTimestamp("stored_at").toInstant(), rs.getBoolean("purged")),
				jobId);
	}

	@Override
	public Optional<Evidence> read(UUID jobId, long leaseEpoch, String name) {
		List<Optional<Evidence>> rows = this.jdbc.query("SELECT * FROM evidence.read_result_artifact(?, ?, ?)",
				(rs, row) -> {
					byte[] content = rs.getBytes("content");
					if (content == null) {
						return Optional.<Evidence>empty();
					}
					String sha256 = rs.getString("sha256");
					try {
						EvidenceVerifier.verify(name, sha256, rs.getLong("size_bytes"), content);
					}
					catch (EvidenceIntegrityException ex) {
						log.error("evidence.integrity_violation job_id={} lease_epoch={} sha256={}", jobId, leaseEpoch,
								sha256);
						throw ex;
					}
					return Optional.of(new Evidence(name, rs.getString("media_type"), sha256, content));
				}, jobId, leaseEpoch, name);
		return rows.isEmpty() ? Optional.empty() : rows.get(0);
	}

}

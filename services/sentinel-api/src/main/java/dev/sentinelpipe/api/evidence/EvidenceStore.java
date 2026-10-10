package dev.sentinelpipe.api.evidence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Read access to the evidence of record of scan jobs (ADR-0008).
 *
 * <p>
 * Implementations must return only evidence referenced by an accepted result, and must
 * verify content against the recorded SHA-256 before returning it ({@link EvidenceVerifier}).
 * Callers authorize the requester for the job's organization first: a job id is not
 * authorization. The current implementation reads PostgreSQL ({@link DatabaseEvidenceStore});
 * an S3-compatible implementation can replace it without changing callers, since evidence
 * is addressed by (organization, SHA-256) and never by a worker-chosen path.
 */
public interface EvidenceStore {

	/** Artifacts of record of a job, metadata only, ordered by lease epoch and name. */
	List<EvidenceArtifact> list(UUID jobId);

	/**
	 * The verified content of one artifact of record, or empty if there is no such artifact
	 * or its content was purged by retention.
	 * @throws EvidenceIntegrityException if the stored bytes do not match the recorded digest
	 */
	Optional<Evidence> read(UUID jobId, long leaseEpoch, String name);

}

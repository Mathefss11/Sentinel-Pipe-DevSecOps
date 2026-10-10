package dev.sentinelpipe.api.evidence;

import java.time.Instant;

/**
 * Metadata of one artifact of record of a job: uploaded under a lease and referenced by
 * that lease's accepted {@code job-result.v1}. {@code sha256} and {@code sizeBytes} were
 * computed by PostgreSQL from the uploaded bytes, never taken from the worker.
 * {@code purged} means the content was removed by the retention policy; the digest
 * remains.
 */
public record EvidenceArtifact(long leaseEpoch, String name, String mediaType, String sha256, long sizeBytes,
		Instant storedAt, boolean purged) {
}

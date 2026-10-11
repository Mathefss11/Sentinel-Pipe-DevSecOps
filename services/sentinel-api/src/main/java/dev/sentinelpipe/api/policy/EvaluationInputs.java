package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * What the evaluator reads, all taken from the authoritative database rows in one
 * snapshot ({@code policy.evaluation_context} and {@code policy.job_evidence}). Nothing
 * here comes from a worker message or a request.
 */
public final class EvaluationInputs {

	private EvaluationInputs() {
	}

	/**
	 * The scan as recorded by the control plane.
	 * @param asOf the database clock when the inputs were read; all ages are measured
	 * against it
	 */
	public record ScanContext(UUID scanId, UUID projectId, UUID organizationId, String commitSha, Instant asOf) {

		public ScanContext {
			Objects.requireNonNull(scanId, "scanId");
			Objects.requireNonNull(projectId, "projectId");
			Objects.requireNonNull(organizationId, "organizationId");
			Objects.requireNonNull(commitSha, "commitSha");
			Objects.requireNonNull(asOf, "asOf");
		}

	}

	/**
	 * One artifact of record. {@code content} is {@code null} when purged by retention.
	 * {@code sha256} and {@code sizeBytes} were computed by PostgreSQL at upload.
	 */
	public record Artifact(String name, String mediaType, String sha256, long sizeBytes, byte[] content) {

		public Artifact {
			content = (content != null) ? content.clone() : null;
		}

		@Override
		public byte[] content() {
			return (this.content != null) ? this.content.clone() : null;
		}

		@Override
		public boolean equals(Object other) {
			return other instanceof Artifact artifact && this.name.equals(artifact.name)
					&& this.sha256.equals(artifact.sha256) && Arrays.equals(this.content, artifact.content);
		}

		@Override
		public int hashCode() {
			return this.sha256.hashCode();
		}

		@Override
		public String toString() {
			return "Artifact[name=" + this.name + ", sha256=" + this.sha256 + "]";
		}

	}

	/**
	 * A job of the scan with its evidence of record: the accepted COMPLETED result of its
	 * current lease epoch ({@code resultSha256}, {@code result}) and the artifacts that
	 * result references. Jobs that did not complete have neither.
	 */
	public record JobEvidence(UUID jobId, ScannerType scannerType, String status, String failureReason,
			long leaseEpoch, Instant completedAt, String resultSha256, String result, List<Artifact> artifacts) {

		public JobEvidence {
			Objects.requireNonNull(jobId, "jobId");
			Objects.requireNonNull(scannerType, "scannerType");
			Objects.requireNonNull(status, "status");
			artifacts = List.copyOf(artifacts);
		}

	}

	/** Evidence of record an evaluation relied on (one per job). */
	public record EvidenceReference(UUID jobId, ScannerType scannerType, long leaseEpoch, String name,
			String sha256, String resultSha256) {
	}

}

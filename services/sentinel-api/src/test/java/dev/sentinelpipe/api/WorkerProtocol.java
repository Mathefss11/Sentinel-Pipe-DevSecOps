package dev.sentinelpipe.api;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The worker side of the execution protocol (Flyway V007/V008), called exactly as the
 * Python worker does: through the {@code worker.*} functions, with a real worker login.
 * Results are canonical {@code job-result.v1} documents.
 */
public final class WorkerProtocol {

	/** Fixed worker-clock timestamps, so identical reports serialize to identical bytes. */
	public static final String STARTED_AT = "2026-10-10T12:00:00Z";

	public static final String FINISHED_AT = "2026-10-10T12:00:01.500000Z";

	/** A claimed lease with the authoritative context returned by {@code worker.claim_job}. */
	public record Lease(UUID jobId, UUID scanId, UUID projectId, UUID organizationId, String commitSha,
			String repositoryOwner, String repositoryName, String scannerType, int attempt, int maxAttempts,
			long epoch, String token, Instant expiresAt, int leaseDurationSeconds, Instant deadlineAt) {

		/** The same lease with another token (forgery and theft tests). */
		public Lease withToken(String otherToken) {
			return new Lease(this.jobId, this.scanId, this.projectId, this.organizationId, this.commitSha,
					this.repositoryOwner, this.repositoryName, this.scannerType, this.attempt, this.maxAttempts,
					this.epoch, otherToken, this.expiresAt, this.leaseDurationSeconds, this.deadlineAt);
		}

		/** The same lease with another epoch (fencing tests). */
		public Lease withEpoch(long otherEpoch) {
			return new Lease(this.jobId, this.scanId, this.projectId, this.organizationId, this.commitSha,
					this.repositoryOwner, this.repositoryName, this.scannerType, this.attempt, this.maxAttempts,
					otherEpoch, this.token, this.expiresAt, this.leaseDurationSeconds, this.deadlineAt);
		}

	}

	public record Heartbeat(String status, Instant leaseExpiresAt) {
	}

	/** Answer of {@code worker.put_evidence}; the digest and size are the database's. */
	public record Upload(String status, String sha256, Integer sizeBytes) {
	}

	/** An artifact reference in a job-result.v1 document. */
	public record Artifact(String name, String mediaType, String sha256, long sizeBytes) {

		public static Artifact of(Upload upload, String name, String mediaType) {
			return new Artifact(name, mediaType, upload.sha256(), upload.sizeBytes());
		}

	}

	private final JdbcTemplate jdbc;

	/** Context of the leases claimed through this instance, for reports by job id. */
	private final Map<UUID, Lease> claimed = new ConcurrentHashMap<>();

	public WorkerProtocol(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	/** The provisioned worker login. */
	public static WorkerProtocol asWorker(TestDatabaseAdmin admin) {
		return new WorkerProtocol(admin.connectAs(DatabaseRoles.WORKER_USER, DatabaseRoles.WORKER_PASSWORD));
	}

	public JdbcTemplate jdbc() {
		return this.jdbc;
	}

	public Optional<Lease> claim(UUID scanId, String... scannerTypes) {
		List<Lease> leases = this.jdbc.query("SELECT * FROM worker.claim_job(string_to_array(?, ','), ?::uuid)",
				(rs, row) -> new Lease(rs.getObject("job_id", UUID.class), rs.getObject("scan_id", UUID.class),
						rs.getObject("project_id", UUID.class), rs.getObject("organization_id", UUID.class),
						rs.getString("commit_sha"), rs.getString("repository_owner"), rs.getString("repository_name"),
						rs.getString("scanner_type"), rs.getInt("attempt"), rs.getInt("max_attempts"),
						rs.getLong("lease_epoch"), rs.getString("lease_token"),
						rs.getTimestamp("lease_expires_at").toInstant(), rs.getInt("lease_duration_seconds"),
						rs.getTimestamp("deadline_at").toInstant()),
				String.join(",", scannerTypes), (scanId != null) ? scanId.toString() : null);
		leases.forEach((lease) -> this.claimed.put(lease.jobId(), lease));
		return leases.stream().findFirst();
	}

	public Optional<Lease> claimFixture(UUID scanId) {
		return claim(scanId, "FIXTURE");
	}

	public Lease claimFixtureOrFail(UUID scanId) {
		return claimFixture(scanId).orElseThrow(() -> new AssertionError("no claimable FIXTURE job"));
	}

	public Heartbeat heartbeat(Lease lease) {
		return this.jdbc.queryForObject("SELECT * FROM worker.heartbeat_job(?, ?, ?)", (rs, row) -> {
			Timestamp expires = rs.getTimestamp("lease_expires_at");
			return new Heartbeat(rs.getString("status"), (expires != null) ? expires.toInstant() : null);
		}, lease.jobId(), lease.epoch(), lease.token());
	}

	// ---------------------------------------------------------------------------------
	// Evidence
	// ---------------------------------------------------------------------------------

	public Upload putEvidence(UUID jobId, long epoch, String token, String name, String mediaType, byte[] content) {
		return this.jdbc.queryForObject("SELECT * FROM worker.put_evidence(?, ?, ?, ?, ?, ?)",
				(rs, row) -> new Upload(rs.getString("status"), rs.getString("sha256"),
						(Integer) rs.getObject("size_bytes")),
				jobId, epoch, token, name, mediaType, content);
	}

	public Upload putEvidence(Lease lease, String name, String mediaType, byte[] content) {
		return putEvidence(lease.jobId(), lease.epoch(), lease.token(), name, mediaType, content);
	}

	// ---------------------------------------------------------------------------------
	// Results (job-result.v1)
	// ---------------------------------------------------------------------------------

	/** A mutable job-result.v1 document for the lease (keys sorted), for tests to alter. */
	public static Map<String, Object> resultDocument(Lease lease, String outcome, String failureReason,
			List<Artifact> artifacts) {
		Map<String, Object> document = new TreeMap<>();
		document.put("schema_version", 1);
		document.put("job_id", str(lease.jobId()));
		document.put("scan_id", str(lease.scanId()));
		document.put("project_id", str(lease.projectId()));
		document.put("organization_id", str(lease.organizationId()));
		document.put("commit_sha", lease.commitSha());
		document.put("scanner_type", lease.scannerType());
		document.put("attempt", lease.attempt());
		document.put("lease_epoch", lease.epoch());
		document.put("outcome", outcome);
		document.put("failure_reason", failureReason);
		document.put("started_at", STARTED_AT);
		document.put("finished_at", FINISHED_AT);
		List<Object> references = new ArrayList<>();
		artifacts.stream().sorted(java.util.Comparator.comparing(Artifact::name)).forEach((artifact) -> {
			Map<String, Object> reference = new TreeMap<>();
			reference.put("name", artifact.name());
			reference.put("media_type", artifact.mediaType());
			reference.put("sha256", artifact.sha256());
			reference.put("size_bytes", artifact.sizeBytes());
			references.add(reference);
		});
		document.put("artifacts", references);
		return document;
	}

	private static String str(Object value) {
		return (value != null) ? value.toString() : null;
	}

	/**
	 * Canonical JSON (job-result.v1): keys sorted by code point, no whitespace, integers,
	 * ASCII with minimal escaping.
	 */
	public static String canonical(Object value) {
		StringBuilder out = new StringBuilder();
		write(out, value);
		return out.toString();
	}

	private static void write(StringBuilder out, Object value) {
		if (value == null) {
			out.append("null");
		}
		else if (value instanceof Map<?, ?> map) {
			out.append('{');
			Iterator<? extends Map.Entry<?, ?>> entries = new TreeMap<>(map).entrySet().iterator();
			while (entries.hasNext()) {
				Map.Entry<?, ?> entry = entries.next();
				write(out, entry.getKey().toString());
				out.append(':');
				write(out, entry.getValue());
				if (entries.hasNext()) {
					out.append(',');
				}
			}
			out.append('}');
		}
		else if (value instanceof List<?> list) {
			out.append('[');
			for (int i = 0; i < list.size(); i++) {
				if (i > 0) {
					out.append(',');
				}
				write(out, list.get(i));
			}
			out.append(']');
		}
		else if (value instanceof Number || value instanceof Boolean) {
			out.append(value);
		}
		else {
			out.append('"');
			for (char c : value.toString().toCharArray()) {
				switch (c) {
					case '"' -> out.append("\\\"");
					case '\\' -> out.append("\\\\");
					default -> {
						if (c < 0x20 || c > 0x7e) {
							out.append(String.format("\\u%04x", (int) c));
						}
						else {
							out.append(c);
						}
					}
				}
			}
			out.append('"');
		}
	}

	/** Submits raw bytes as the result (malformed-input tests). */
	public String submitRaw(String token, String result) {
		return this.jdbc.queryForObject("SELECT worker.submit_result(?, ?)", String.class, token, result);
	}

	public String submit(String token, Map<String, Object> document) {
		return submitRaw(token, canonical(document));
	}

	public String submit(Lease lease, String outcome, String failureReason, List<Artifact> artifacts) {
		return submit(lease.token(), resultDocument(lease, outcome, failureReason, artifacts));
	}

	/**
	 * Reports for an arbitrary job, scan, epoch and token. The remaining context is taken
	 * from the lease this instance claimed for {@code jobId} (or a fictitious one).
	 */
	public String report(UUID jobId, UUID scanId, long epoch, String token, String outcome, String failureReason) {
		Lease context = this.claimed.getOrDefault(jobId, new Lease(jobId, scanId, UUID.randomUUID(), UUID.randomUUID(),
				"0".repeat(40), "x", "x", "FIXTURE", 1, 3, epoch, token, Instant.now(), 60, Instant.now()));
		Map<String, Object> document = resultDocument(context, outcome, failureReason, List.of());
		document.put("job_id", str(jobId));
		document.put("scan_id", str(scanId));
		document.put("lease_epoch", epoch);
		return submit(token, document);
	}

	public String report(Lease lease, String outcome, String failureReason) {
		return submit(lease, outcome, failureReason, List.of());
	}

	public String complete(Lease lease) {
		return report(lease, "COMPLETED", null);
	}

	public String fail(Lease lease, String failureReason) {
		return report(lease, "FAILED", failureReason);
	}

	/** Uploads one JSON artifact and reports COMPLETED referencing it. */
	public String completeWithEvidence(Lease lease, String name, byte[] content) {
		Upload upload = putEvidence(lease, name, "application/json", content);
		if (!upload.status().equals("STORED") && !upload.status().equals("DUPLICATE")) {
			throw new AssertionError("upload refused: " + upload.status());
		}
		return submit(lease, "COMPLETED", null, List.of(Artifact.of(upload, name, "application/json")));
	}

}

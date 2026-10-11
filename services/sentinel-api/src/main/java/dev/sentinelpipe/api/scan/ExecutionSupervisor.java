package dev.sentinelpipe.api.scan;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tags;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Drives the execution lifecycle forward from the control plane (ADR-0007). One pass:
 * <ol>
 * <li>{@code lifecycle.supervise}: fails RUNNING scans past their hard deadline, and
 * reclaims expired job leases (requeue while attempts remain, otherwise FAILED); a scan
 * whose jobs are all terminal moves to EVALUATING;</li>
 * <li>evaluates EVALUATING scans ({@link ScanLifecycleService#evaluate}): a scan pinned to
 * a policy version by the policy engine, with an evaluation record (ADR-0013); a scan
 * without a policy is INCOMPLETE with a recorded reason, never PASS;</li>
 * <li>purges evidence content past its retention ({@code evidence.purge_expired}); digests
 * and results remain;</li>
 * <li>refreshes low-cardinality gauges (job counts by state, oldest running job, refused
 * worker operations by sanitized reason). Values come from the database, so they are the
 * same on every instance.</li>
 * </ol>
 * Safe to run on several API instances at once: the database functions lock scan rows and
 * skip rows locked by another pass or a worker, and evaluation of a scan that is no longer
 * EVALUATING is a no-op.
 */
public class ExecutionSupervisor {

	static final String DEADLINES_EXCEEDED = "sentinel.execution.deadlines.exceeded";

	static final String LEASES_EXPIRED = "sentinel.execution.leases.expired";

	static final String SCANS_EVALUATED = "sentinel.execution.scans.evaluated";

	static final String EVIDENCE_PURGED = "sentinel.evidence.purged";

	static final String JOBS = "sentinel.execution.jobs";

	static final String EVALUATING_SCANS = "sentinel.execution.scans.evaluating";

	static final String OLDEST_RUNNING = "sentinel.execution.running.oldest";

	static final String RESULT_REJECTIONS = "sentinel.execution.rejections.results";

	static final String EVIDENCE_REJECTIONS = "sentinel.execution.rejections.evidence";

	/** Rejection reasons written by the V008 functions; anything else is reported as OTHER. */
	static final Set<String> REJECTION_DETAILS = Set.of("SCAN_MISMATCH", "STALE_EPOCH", "UNKNOWN_EPOCH",
			"NOT_LEASE_OWNER", "TOKEN_MISMATCH", "JOB_NOT_RUNNING", "LEASE_EXPIRED", "DEADLINE_EXCEEDED",
			"CONTEXT_MISMATCH", "MISSING_ARTIFACT", "ARTIFACT_MISMATCH", "CONFLICT", "QUOTA_EXCEEDED");

	private static final Logger log = LoggerFactory.getLogger(ExecutionSupervisor.class);

	/** What one pass changed. */
	public record Pass(int deadlinesExceeded, int leasesExpired, int scansEvaluated, int evidencePurged) {

		boolean changedAnything() {
			return this.deadlinesExceeded + this.leasesExpired + this.scansEvaluated + this.evidencePurged > 0;
		}

	}

	private final JdbcTemplate jdbc;

	private final ScanLifecycleService lifecycle;

	private final int batchSize;

	private final Counter deadlinesExceeded;

	private final Counter leasesExpired;

	private final Counter scansEvaluated;

	private final Counter evidencePurged;

	private final AtomicLong queuedJobs = new AtomicLong();

	private final AtomicLong runningJobs = new AtomicLong();

	private final AtomicLong retryPendingJobs = new AtomicLong();

	private final AtomicLong evaluatingScans = new AtomicLong();

	private final AtomicLong oldestRunningSeconds = new AtomicLong();

	private final MultiGauge resultRejections;

	private final MultiGauge evidenceRejections;

	public ExecutionSupervisor(JdbcTemplate jdbc, ScanLifecycleService lifecycle, ExecutionProperties properties,
			MeterRegistry registry) {
		this.jdbc = jdbc;
		this.lifecycle = lifecycle;
		this.batchSize = properties.getSupervisor().getBatchSize();
		this.deadlinesExceeded = Counter.builder(DEADLINES_EXCEEDED)
			.description("Scans failed because they exceeded their hard execution deadline")
			.register(registry);
		this.leasesExpired = Counter.builder(LEASES_EXPIRED)
			.description("Job leases reclaimed after the worker stopped renewing them")
			.register(registry);
		this.scansEvaluated = Counter.builder(SCANS_EVALUATED)
			.description("Scans whose security decision was recorded by the supervisor")
			.register(registry);
		this.evidencePurged = Counter.builder(EVIDENCE_PURGED)
			.description("Evidence objects whose content was removed by the retention policy")
			.register(registry);
		for (Map.Entry<String, AtomicLong> state : Map.of("queued", this.queuedJobs, "running", this.runningJobs,
				"retry_pending", this.retryPendingJobs).entrySet()) {
			Gauge.builder(JOBS, state.getValue(), AtomicLong::get)
				.description("Scan jobs by execution state (retry_pending: queued after a failed attempt)")
				.tag("status", state.getKey())
				.register(registry);
		}
		Gauge.builder(EVALUATING_SCANS, this.evaluatingScans, AtomicLong::get)
			.description("Scans waiting for their security decision")
			.register(registry);
		Gauge.builder(OLDEST_RUNNING, this.oldestRunningSeconds, AtomicLong::get)
			.description("Age of the oldest running job attempt")
			.baseUnit("seconds")
			.register(registry);
		this.resultRejections = MultiGauge.builder(RESULT_REJECTIONS)
			.description("Refused worker result submissions recorded in the database, by reason")
			.register(registry);
		this.evidenceRejections = MultiGauge.builder(EVIDENCE_REJECTIONS)
			.description("Refused worker evidence uploads recorded in the database, by reason")
			.register(registry);
	}

	public Pass runOnce() {
		// One statement, so one transaction: the function's changes commit atomically.
		Map<String, Object> supervised = this.jdbc.queryForMap(
				"SELECT deadlines_exceeded, leases_expired FROM lifecycle.supervise(?)", this.batchSize);
		int deadlines = ((Number) supervised.get("deadlines_exceeded")).intValue();
		int expired = ((Number) supervised.get("leases_expired")).intValue();

		List<UUID> evaluating = this.jdbc.queryForList(
				"SELECT id FROM scans WHERE execution_status = 'EVALUATING' ORDER BY updated_at, id LIMIT ?",
				UUID.class, this.batchSize);
		int evaluated = 0;
		for (UUID scanId : evaluating) {
			try {
				if (this.lifecycle.evaluate(scanId)) {
					evaluated++;
				}
			}
			catch (RuntimeException ex) {
				// One scan must not block the others; it stays EVALUATING and is retried.
				log.warn("execution.evaluation_failed scan_id={} error_type={}", scanId, ex.getClass().getSimpleName());
			}
		}

		Integer purgedCount = this.jdbc.queryForObject("SELECT evidence.purge_expired(?)", Integer.class,
				this.batchSize);
		int purged = (purgedCount != null) ? purgedCount : 0;

		this.deadlinesExceeded.increment(deadlines);
		this.leasesExpired.increment(expired);
		this.scansEvaluated.increment(evaluated);
		this.evidencePurged.increment(purged);
		refreshGauges();
		Pass pass = new Pass(deadlines, expired, evaluated, purged);
		if (pass.changedAnything()) {
			log.info("execution.supervised deadlines_exceeded={} leases_expired={} scans_evaluated={} evidence_purged={}",
					deadlines, expired, evaluated, purged);
		}
		return pass;
	}

	private void refreshGauges() {
		try {
			Map<String, Object> summary = this.jdbc.queryForMap("SELECT * FROM lifecycle.execution_summary()");
			this.queuedJobs.set(((Number) summary.get("queued_jobs")).longValue());
			this.runningJobs.set(((Number) summary.get("running_jobs")).longValue());
			this.retryPendingJobs.set(((Number) summary.get("retry_pending_jobs")).longValue());
			this.evaluatingScans.set(((Number) summary.get("evaluating_scans")).longValue());
			this.oldestRunningSeconds.set(((Number) summary.get("oldest_running_seconds")).longValue());
			Map<String, Long> results = new HashMap<>();
			Map<String, Long> evidence = new HashMap<>();
			this.jdbc.query("SELECT * FROM lifecycle.rejection_summary()", (rs) -> {
				String detail = rs.getString("detail");
				// Fixed label values only: a database value can never become a new series.
				String reason = REJECTION_DETAILS.contains(detail) ? detail : "OTHER";
				Map<String, Long> totals = "EVIDENCE".equals(rs.getString("operation")) ? evidence : results;
				totals.merge(reason, rs.getLong("occurrences"), Long::sum);
			});
			this.resultRejections.register(rows(results), true);
			this.evidenceRejections.register(rows(evidence), true);
		}
		catch (RuntimeException ex) {
			log.warn("execution.metrics_refresh_failed error_type={}", ex.getClass().getSimpleName());
		}
	}

	private static List<MultiGauge.Row<?>> rows(Map<String, Long> totals) {
		return totals.entrySet()
			.stream()
			.<MultiGauge.Row<?>>map((total) -> MultiGauge.Row.of(Tags.of("reason", total.getKey()), total.getValue()))
			.toList();
	}

}

package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.ConstraintViolations;
import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.common.Timestamps;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScanJobRepository;
import dev.sentinelpipe.api.scanjob.ScanJobStatus;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.BiConsumer;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Internal, trusted lifecycle operations for scans and their jobs.
 *
 * <p>
 * There is deliberately <b>no REST endpoint</b> for these operations. They will be driven
 * by trusted internal components (workers, policy evaluation) in later phases, behind
 * authenticated and integrity-checked channels.
 *
 * <p>
 * Every operation first takes a row lock on the scan, so operations on one scan and its
 * jobs are serialized across application instances. Entity versions provide an
 * additional optimistic check.
 */
@Service
public class ScanLifecycleService {

	static final String SCANNER_ALREADY_PLANNED = "scanner-already-planned";

	private final ScanRepository scans;

	private final ScanJobRepository scanJobs;

	private final Clock clock;

	ScanLifecycleService(ScanRepository scans, ScanJobRepository scanJobs, Clock clock) {
		this.scans = scans;
		this.scanJobs = scanJobs;
		this.clock = clock;
	}

	/** Adds a scanner job to a scan that has not started yet. */
	@Transactional
	public ScanJob planJob(UUID scanId, ScannerType scannerType) {
		Scan scan = lockScan(scanId);
		if (scan.getExecutionStatus() != ScanExecutionStatus.QUEUED) {
			throw new DomainRuleViolationException("Scanner jobs can only be planned while the scan is QUEUED");
		}
		ScanJob job = ScanJob.plan(scanId, scannerType, now());
		try {
			return this.scanJobs.saveAndFlush(job);
		}
		catch (DataIntegrityViolationException ex) {
			if (ConstraintViolations.isViolationOf(ex, "uq_scan_jobs_scan_scanner")) {
				throw new ConflictException(SCANNER_ALREADY_PLANNED, "This scanner is already planned for the scan.");
			}
			throw ex;
		}
	}

	@Transactional
	public Scan startScan(UUID scanId) {
		Scan scan = lockScan(scanId);
		scan.start(now());
		return scan;
	}

	/**
	 * Completes a running scan with a final security decision.
	 *
	 * <p>
	 * Fail-closed rules: every job must be terminal, and {@link SecurityDecision#PASS} is
	 * only accepted when at least one job exists and every job {@code COMPLETED}. A scan
	 * with failed, cancelled or missing jobs may be {@code FAIL} or {@code INCOMPLETE},
	 * never {@code PASS}.
	 */
	@Transactional
	public Scan completeScan(UUID scanId, SecurityDecision decision) {
		Scan scan = lockScan(scanId);
		List<ScanJob> jobs = this.scanJobs.findByScanIdOrderByScannerTypeAsc(scanId);
		if (jobs.stream().anyMatch((job) -> !job.getExecutionStatus().isTerminal())) {
			throw new DomainRuleViolationException("All scan jobs must be terminal before the scan completes");
		}
		boolean allJobsCompleted = !jobs.isEmpty()
				&& jobs.stream().allMatch((job) -> job.getExecutionStatus() == ScanJobStatus.COMPLETED);
		if (decision == SecurityDecision.PASS && !allJobsCompleted) {
			throw new DomainRuleViolationException(
					"PASS requires at least one scan job and every scan job to have COMPLETED");
		}
		scan.complete(decision, now());
		return scan;
	}

	/** Marks the scan FAILED (decision INCOMPLETE) and cancels its unfinished jobs. */
	@Transactional
	public Scan failScan(UUID scanId) {
		return terminate(scanId, Scan::fail);
	}

	/** Marks the scan CANCELLED (decision INCOMPLETE) and cancels its unfinished jobs. */
	@Transactional
	public Scan cancelScan(UUID scanId) {
		return terminate(scanId, Scan::cancel);
	}

	@Transactional
	public ScanJob startJob(UUID jobId) {
		return changeJob(jobId, true, ScanJob::start);
	}

	@Transactional
	public ScanJob completeJob(UUID jobId) {
		return changeJob(jobId, true, ScanJob::complete);
	}

	@Transactional
	public ScanJob retryJob(UUID jobId) {
		return changeJob(jobId, true, ScanJob::requeueForRetry);
	}

	@Transactional
	public ScanJob failJob(UUID jobId) {
		return changeJob(jobId, false, ScanJob::fail);
	}

	private Scan terminate(UUID scanId, BiConsumer<Scan, Instant> transition) {
		Scan scan = lockScan(scanId);
		Instant now = now();
		transition.accept(scan, now);
		for (ScanJob job : this.scanJobs.findByScanIdOrderByScannerTypeAsc(scanId)) {
			if (!job.getExecutionStatus().isTerminal()) {
				job.cancel(now);
			}
		}
		return scan;
	}

	private ScanJob changeJob(UUID jobId, boolean requireRunningScan, BiConsumer<ScanJob, Instant> transition) {
		UUID scanId = this.scanJobs.findScanIdById(jobId)
			.orElseThrow(() -> new ResourceNotFoundException("Scan job", jobId));
		Scan scan = lockScan(scanId);
		if (scan.getExecutionStatus().isTerminal()) {
			throw new DomainRuleViolationException("Jobs of a terminal scan cannot change");
		}
		if (requireRunningScan && scan.getExecutionStatus() != ScanExecutionStatus.RUNNING) {
			throw new DomainRuleViolationException("The scan must be RUNNING for this job transition");
		}
		ScanJob job = this.scanJobs.findById(jobId).orElseThrow(() -> new ResourceNotFoundException("Scan job", jobId));
		transition.accept(job, now());
		return job;
	}

	private Scan lockScan(UUID scanId) {
		return this.scans.findByIdForUpdate(scanId).orElseThrow(() -> new ResourceNotFoundException("Scan", scanId));
	}

	private Instant now() {
		return Timestamps.now(this.clock);
	}

}

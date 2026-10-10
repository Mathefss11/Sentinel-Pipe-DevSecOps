package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.scanjob.JobFailureReason;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScanJobStatus;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Scan representation. Lease owners, tokens and epochs are internal to the execution
 * protocol and deliberately not exposed.
 */
record ScanResponse(UUID id, UUID projectId, String commitSha, String branch, TriggerType triggerType,
		ScanExecutionStatus executionStatus, SecurityDecision securityDecision, DecisionReason decisionReason,
		Instant requestedAt, Instant startedAt, Instant deadlineAt, Instant completedAt, List<ScanJobResponse> jobs) {

	record ScanJobResponse(UUID id, UUID scanId, ScannerType scannerType, ScanJobStatus executionStatus,
			int attemptCount, JobFailureReason failureReason, Instant createdAt, Instant startedAt,
			Instant completedAt) {

		static ScanJobResponse from(ScanJob job) {
			return new ScanJobResponse(job.getId(), job.getScanId(), job.getScannerType(), job.getExecutionStatus(),
					job.getAttemptCount(), job.getFailureReason(), job.getCreatedAt(), job.getStartedAt(),
					job.getCompletedAt());
		}

	}

	static ScanResponse from(ScanDetails details) {
		Scan scan = details.scan();
		return new ScanResponse(scan.getId(), scan.getProjectId(), scan.getCommitSha(), scan.getBranch(),
				scan.getTriggerType(), scan.getExecutionStatus(), scan.getSecurityDecision(), scan.getDecisionReason(),
				scan.getRequestedAt(), scan.getStartedAt(), scan.getDeadlineAt(), scan.getCompletedAt(),
				details.jobs().stream().map(ScanJobResponse::from).toList());
	}

}

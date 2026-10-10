package dev.sentinelpipe.api.scanjob;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Planning and the documented transition matrix. The transitions themselves are performed
 * and enforced by the database execution protocol (V007) and tested against PostgreSQL in
 * {@code ExecutionProtocolIntegrationTests}, {@code ExecutionSupervisorIntegrationTests}
 * and {@code ScanLifecycleIntegrationTests}.
 */
class ScanJobTests {

	private static final Instant T0 = Instant.parse("2026-10-09T12:00:00Z");

	@Test
	void plannedJobIsQueuedWithoutAttempts() {
		ScanJob job = ScanJob.plan(UUID.randomUUID(), ScannerType.FIXTURE, T0);

		assertThat(job.getExecutionStatus()).isEqualTo(ScanJobStatus.QUEUED);
		assertThat(job.getAttemptCount()).isZero();
		assertThat(job.getStartedAt()).isNull();
		assertThat(job.getCompletedAt()).isNull();
		assertThat(job.getFailureReason()).isNull();
		assertThat(job.getCreatedAt()).isEqualTo(T0);
	}

	@Test
	void transitionMatrixIsExactlyAsDocumented() {
		Map<ScanJobStatus, Set<ScanJobStatus>> expected = Map.of(ScanJobStatus.QUEUED,
				EnumSet.of(ScanJobStatus.RUNNING, ScanJobStatus.FAILED, ScanJobStatus.CANCELLED), ScanJobStatus.RUNNING,
				EnumSet.of(ScanJobStatus.QUEUED, ScanJobStatus.COMPLETED, ScanJobStatus.FAILED,
						ScanJobStatus.CANCELLED),
				ScanJobStatus.COMPLETED, EnumSet.noneOf(ScanJobStatus.class), ScanJobStatus.FAILED,
				EnumSet.noneOf(ScanJobStatus.class), ScanJobStatus.CANCELLED, EnumSet.noneOf(ScanJobStatus.class));

		for (ScanJobStatus from : ScanJobStatus.values()) {
			for (ScanJobStatus to : ScanJobStatus.values()) {
				assertThat(from.canTransitionTo(to)).as("%s -> %s", from, to)
					.isEqualTo(expected.get(from).contains(to));
			}
		}
	}

	@Test
	void attemptsAreBoundedByThree() {
		// Mirrored by ck_scan_jobs_attempt_count and the claim/retry functions.
		assertThat(ScanJob.MAX_ATTEMPTS).isEqualTo(3);
	}

}

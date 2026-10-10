package dev.sentinelpipe.api.scanjob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.InvalidStateTransitionException;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ScanJobTests {

	private static final Instant T0 = Instant.parse("2026-10-09T12:00:00Z");

	private static ScanJob planned() {
		return ScanJob.plan(UUID.randomUUID(), ScannerType.SEMGREP, T0);
	}

	@Test
	void plannedJobIsQueuedWithoutAttempts() {
		ScanJob job = planned();

		assertThat(job.getExecutionStatus()).isEqualTo(ScanJobStatus.QUEUED);
		assertThat(job.getAttemptCount()).isZero();
		assertThat(job.getStartedAt()).isNull();
		assertThat(job.getCompletedAt()).isNull();
	}

	@Test
	void startCountsAttemptsAndCompleteRecordsTimestamps() {
		ScanJob job = planned();

		job.start(T0.plusSeconds(1));
		job.complete(T0.plusSeconds(2));

		assertThat(job.getExecutionStatus()).isEqualTo(ScanJobStatus.COMPLETED);
		assertThat(job.getAttemptCount()).isEqualTo(1);
		assertThat(job.getStartedAt()).isEqualTo(T0.plusSeconds(1));
		assertThat(job.getCompletedAt()).isEqualTo(T0.plusSeconds(2));
	}

	@Test
	void retriesAreBoundedByMaxAttempts() {
		ScanJob job = planned();
		Instant t = T0;
		for (int attempt = 1; attempt < ScanJob.MAX_ATTEMPTS; attempt++) {
			job.start(t = t.plusSeconds(1));
			job.requeueForRetry(t = t.plusSeconds(1));
			assertThat(job.getExecutionStatus()).isEqualTo(ScanJobStatus.QUEUED);
			assertThat(job.getStartedAt()).isNull();
		}
		job.start(t = t.plusSeconds(1));
		Instant last = t.plusSeconds(1);

		assertThat(job.getAttemptCount()).isEqualTo(ScanJob.MAX_ATTEMPTS);
		assertThatThrownBy(() -> job.requeueForRetry(last)).isInstanceOf(DomainRuleViolationException.class);
		assertThat(job.getExecutionStatus()).isEqualTo(ScanJobStatus.RUNNING);
		job.fail(last);
		assertThat(job.getExecutionStatus()).isEqualTo(ScanJobStatus.FAILED);
	}

	@Test
	void queuedJobCannotCompleteWithoutRunning() {
		ScanJob job = planned();

		assertThatThrownBy(() -> job.complete(T0.plusSeconds(1))).isInstanceOf(InvalidStateTransitionException.class);
	}

	@Test
	void queuedJobCannotBeRequeued() {
		ScanJob job = planned();

		assertThatThrownBy(() -> job.requeueForRetry(T0.plusSeconds(1)))
			.isInstanceOf(InvalidStateTransitionException.class);
	}

	@Test
	void terminalJobsAreImmutable() {
		ScanJob completed = planned();
		completed.start(T0.plusSeconds(1));
		completed.complete(T0.plusSeconds(2));
		ScanJob cancelled = planned();
		cancelled.cancel(T0.plusSeconds(1));
		Instant later = T0.plusSeconds(10);

		for (ScanJob job : new ScanJob[] { completed, cancelled }) {
			ScanJobStatus status = job.getExecutionStatus();
			assertThatThrownBy(() -> job.start(later)).isInstanceOf(InvalidStateTransitionException.class);
			assertThatThrownBy(() -> job.complete(later)).isInstanceOf(InvalidStateTransitionException.class);
			assertThatThrownBy(() -> job.fail(later)).isInstanceOf(InvalidStateTransitionException.class);
			assertThatThrownBy(() -> job.cancel(later)).isInstanceOf(InvalidStateTransitionException.class);
			assertThatThrownBy(() -> job.requeueForRetry(later)).isInstanceOf(InvalidStateTransitionException.class);
			assertThat(job.getExecutionStatus()).isEqualTo(status);
		}
	}

}

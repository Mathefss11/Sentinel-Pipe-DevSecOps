package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.common.DomainRuleViolationException;
import dev.sentinelpipe.api.common.DomainValidationException;
import dev.sentinelpipe.api.common.InvalidStateTransitionException;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class ScanTests {

	private static final Instant T0 = Instant.parse("2026-10-09T12:00:00Z");

	private static final Instant T1 = T0.plusSeconds(1);

	private static final Instant T2 = T0.plusSeconds(2);

	private static final String SHA = "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e";

	private static Scan queued() {
		return Scan.request(UUID.randomUUID(), SHA, "main", TriggerType.PUSH, null, null, T0);
	}

	private static Scan running() {
		Scan scan = queued();
		scan.start(T1);
		return scan;
	}

	@Test
	void newScanIsQueuedAndPending() {
		Scan scan = queued();

		assertThat(scan.getId()).isNotNull();
		assertThat(scan.getExecutionStatus()).isEqualTo(ScanExecutionStatus.QUEUED);
		assertThat(scan.getSecurityDecision()).isEqualTo(SecurityDecision.PENDING);
		assertThat(scan.getRequestedAt()).isEqualTo(T0);
		assertThat(scan.getStartedAt()).isNull();
		assertThat(scan.getCompletedAt()).isNull();
	}

	@Test
	void normalizesCommitShaToLowercase() {
		Scan scan = Scan.request(UUID.randomUUID(), SHA.toUpperCase(), "main", TriggerType.PUSH, null, null, T0);

		assertThat(scan.getCommitSha()).isEqualTo(SHA);
	}

	@Test
	void acceptsSha256CommitNames() {
		String sha256 = "a".repeat(64);
		assertThat(Scan.request(UUID.randomUUID(), sha256, "main", TriggerType.PUSH, null, null, T0).getCommitSha())
			.isEqualTo(sha256);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "4f2c8e1", "main", "HEAD", "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9", // 39
			"4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e0", // 41
			"zf2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e", " 4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e",
			"4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e\n" })
	void rejectsInvalidCommitShas(String sha) {
		assertThatThrownBy(() -> Scan.request(UUID.randomUUID(), sha, "main", TriggerType.PUSH, null, null, T0))
			.isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("commitSha");
	}

	@Test
	void successfulCompletionDoesNotImplyPass() {
		Scan scan = running();

		scan.complete(SecurityDecision.FAIL, T2);

		assertThat(scan.getExecutionStatus()).isEqualTo(ScanExecutionStatus.COMPLETED);
		assertThat(scan.getSecurityDecision()).isEqualTo(SecurityDecision.FAIL);
		assertThat(scan.getStartedAt()).isEqualTo(T1);
		assertThat(scan.getCompletedAt()).isEqualTo(T2);
	}

	@Test
	void completionRequiresAFinalDecision() {
		Scan scan = running();

		assertThatThrownBy(() -> scan.complete(SecurityDecision.PENDING, T2))
			.isInstanceOf(DomainRuleViolationException.class);
		assertThat(scan.getExecutionStatus()).isEqualTo(ScanExecutionStatus.RUNNING);
	}

	@Test
	void failureAndCancellationFailClosedAsIncomplete() {
		Scan failed = running();
		failed.fail(T2);
		Scan cancelled = queued();
		cancelled.cancel(T1);

		assertThat(failed.getExecutionStatus()).isEqualTo(ScanExecutionStatus.FAILED);
		assertThat(failed.getSecurityDecision()).isEqualTo(SecurityDecision.INCOMPLETE);
		assertThat(cancelled.getExecutionStatus()).isEqualTo(ScanExecutionStatus.CANCELLED);
		assertThat(cancelled.getSecurityDecision()).isEqualTo(SecurityDecision.INCOMPLETE);
		assertThat(cancelled.getCompletedAt()).isEqualTo(T1);
	}

	@Test
	void queuedScanCannotCompleteWithoutRunning() {
		Scan scan = queued();

		assertThatThrownBy(() -> scan.complete(SecurityDecision.PASS, T1))
			.isInstanceOf(InvalidStateTransitionException.class);
		assertThat(scan.getSecurityDecision()).isEqualTo(SecurityDecision.PENDING);
	}

	@ParameterizedTest
	@EnumSource(value = ScanExecutionStatus.class, names = { "COMPLETED", "FAILED", "CANCELLED" })
	void terminalScansAreImmutable(ScanExecutionStatus terminal) {
		Scan scan = running();
		switch (terminal) {
			case COMPLETED -> scan.complete(SecurityDecision.INCOMPLETE, T2);
			case FAILED -> scan.fail(T2);
			default -> scan.cancel(T2);
		}
		SecurityDecision decision = scan.getSecurityDecision();
		Instant later = T2.plusSeconds(1);

		for (Consumer<Scan> change : Set.<Consumer<Scan>>of((s) -> s.start(later),
				(s) -> s.complete(SecurityDecision.PASS, later), (s) -> s.fail(later), (s) -> s.cancel(later))) {
			assertThatThrownBy(() -> change.accept(scan)).isInstanceOf(InvalidStateTransitionException.class);
		}
		assertThat(scan.getExecutionStatus()).isEqualTo(terminal);
		assertThat(scan.getSecurityDecision()).isEqualTo(decision);
		assertThat(scan.getCompletedAt()).isEqualTo(T2);
	}

	@Test
	void transitionMatrixIsExactlyAsDocumented() {
		Map<ScanExecutionStatus, Set<ScanExecutionStatus>> expected = Map.of(ScanExecutionStatus.QUEUED,
				EnumSet.of(ScanExecutionStatus.RUNNING, ScanExecutionStatus.FAILED, ScanExecutionStatus.CANCELLED),
				ScanExecutionStatus.RUNNING,
				EnumSet.of(ScanExecutionStatus.COMPLETED, ScanExecutionStatus.FAILED, ScanExecutionStatus.CANCELLED),
				ScanExecutionStatus.COMPLETED, EnumSet.noneOf(ScanExecutionStatus.class), ScanExecutionStatus.FAILED,
				EnumSet.noneOf(ScanExecutionStatus.class), ScanExecutionStatus.CANCELLED,
				EnumSet.noneOf(ScanExecutionStatus.class));

		for (ScanExecutionStatus from : ScanExecutionStatus.values()) {
			for (ScanExecutionStatus to : ScanExecutionStatus.values()) {
				assertThat(from.canTransitionTo(to)).as("%s -> %s", from, to)
					.isEqualTo(expected.get(from).contains(to));
			}
		}
	}

	@Test
	void timestampsCannotMoveBackwards() {
		Scan scan = queued();

		assertThatThrownBy(() -> scan.start(T0.minusSeconds(1))).isInstanceOf(DomainRuleViolationException.class);
		assertThat(scan.getExecutionStatus()).isEqualTo(ScanExecutionStatus.QUEUED);
	}

	@Test
	void idempotencyKeyAndFingerprintAreSetTogether() {
		assertThatThrownBy(() -> Scan.request(UUID.randomUUID(), SHA, "main", TriggerType.PUSH, "key", null, T0))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void fingerprintCoversEveryRequestField() {
		String base = ScanRequestFingerprint.of(SHA, "main", TriggerType.PUSH);

		assertThat(base).hasSize(64).matches("[0-9a-f]{64}");
		assertThat(ScanRequestFingerprint.of(SHA, "main", TriggerType.PUSH)).isEqualTo(base);
		assertThat(ScanRequestFingerprint.of("b".repeat(40), "main", TriggerType.PUSH)).isNotEqualTo(base);
		assertThat(ScanRequestFingerprint.of(SHA, "develop", TriggerType.PUSH)).isNotEqualTo(base);
		assertThat(ScanRequestFingerprint.of(SHA, "main", TriggerType.MANUAL)).isNotEqualTo(base);
	}

}

package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.common.DomainValidationException;
import dev.sentinelpipe.api.scanjob.ScanJobStatus;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class ScanTests {

	private static final Instant T0 = Instant.parse("2026-10-09T12:00:00Z");

	private static final String SHA = "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e";

	private static Scan queued() {
		return Scan.request(UUID.randomUUID(), SHA, "main", TriggerType.PUSH, null, null, 60, 900, 90, T0);
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
		Scan scan = Scan.request(UUID.randomUUID(), SHA.toUpperCase(), "main", TriggerType.PUSH, null, null, 60, 900, 90, T0);

		assertThat(scan.getCommitSha()).isEqualTo(SHA);
	}

	@Test
	void acceptsSha256CommitNames() {
		String sha256 = "a".repeat(64);
		assertThat(Scan.request(UUID.randomUUID(), sha256, "main", TriggerType.PUSH, null, null, 60, 900, 90, T0).getCommitSha())
			.isEqualTo(sha256);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "4f2c8e1", "main", "HEAD", "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9", // 39
			"4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e0", // 41
			"zf2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e", " 4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e",
			"4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e\n" })
	void rejectsInvalidCommitShas(String sha) {
		assertThatThrownBy(() -> Scan.request(UUID.randomUUID(), sha, "main", TriggerType.PUSH, null, null, 60, 900, 90, T0))
			.isInstanceOf(DomainValidationException.class)
			.extracting("field")
			.isEqualTo("commitSha");
	}

	@Test
	void newScanCarriesItsExecutionLimitsButNoDeadlineUntilItStarts() {
		Scan scan = queued();

		assertThat(scan.getLeaseDurationSeconds()).isEqualTo(60);
		assertThat(scan.getExecutionTimeoutSeconds()).isEqualTo(900);
		assertThat(scan.getDeadlineAt()).isNull();
		assertThat(scan.getDecisionReason()).isNull();
	}

	@ParameterizedTest
	@CsvSource({ "14, 900", "601, 900", "60, 59", "60, 86401", "60, 60" })
	void rejectsExecutionLimitsOutsideTheDatabaseBounds(int lease, int timeout) {
		assertThatThrownBy(() -> Scan.request(UUID.randomUUID(), SHA, "main", TriggerType.PUSH, null, null, lease,
				timeout, 90, T0))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void transitionMatrixIsExactlyAsDocumented() {
		Map<ScanExecutionStatus, Set<ScanExecutionStatus>> expected = Map.of(ScanExecutionStatus.QUEUED,
				EnumSet.of(ScanExecutionStatus.RUNNING, ScanExecutionStatus.FAILED, ScanExecutionStatus.CANCELLED),
				ScanExecutionStatus.RUNNING,
				EnumSet.of(ScanExecutionStatus.EVALUATING, ScanExecutionStatus.FAILED, ScanExecutionStatus.CANCELLED),
				ScanExecutionStatus.EVALUATING,
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
	void terminalStatusesAreCompletedFailedAndCancelled() {
		assertThat(EnumSet.allOf(ScanExecutionStatus.class)).filteredOn(ScanExecutionStatus::isTerminal)
			.containsExactlyInAnyOrder(ScanExecutionStatus.COMPLETED, ScanExecutionStatus.FAILED,
					ScanExecutionStatus.CANCELLED);
	}

	@Test
	void withoutAPolicyEngineEveryEvaluationIsIncompleteWithAReason() {
		assertThat(ScanLifecycleService.reasonWithoutPolicyEngine(
				java.util.List.of(ScanJobStatus.COMPLETED, ScanJobStatus.COMPLETED)))
			.isEqualTo(DecisionReason.POLICY_EVALUATION_UNAVAILABLE);
		assertThat(ScanLifecycleService.reasonWithoutPolicyEngine(
				java.util.List.of(ScanJobStatus.COMPLETED, ScanJobStatus.FAILED)))
			.isEqualTo(DecisionReason.SCANNER_EXECUTION_INCOMPLETE);
		assertThat(ScanLifecycleService.reasonWithoutPolicyEngine(java.util.List.of(ScanJobStatus.CANCELLED)))
			.isEqualTo(DecisionReason.SCANNER_EXECUTION_INCOMPLETE);
		assertThat(ScanLifecycleService.reasonWithoutPolicyEngine(java.util.List.of()))
			.isEqualTo(DecisionReason.SCANNER_EXECUTION_INCOMPLETE);
	}

	@Test
	void idempotencyKeyAndFingerprintAreSetTogether() {
		assertThatThrownBy(() -> Scan.request(UUID.randomUUID(), SHA, "main", TriggerType.PUSH, "key", null, 60, 900, 90, T0))
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

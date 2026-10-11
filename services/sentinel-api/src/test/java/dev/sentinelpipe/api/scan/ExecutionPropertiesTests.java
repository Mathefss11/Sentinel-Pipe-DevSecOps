package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class ExecutionPropertiesTests {

	private static final String[] NO_PROFILES = {};

	@Test
	void defaultsAreTheApprovedLimits() {
		ExecutionProperties properties = new ExecutionProperties();

		assertThat(properties.getLeaseDuration()).isEqualTo(Duration.ofSeconds(60));
		assertThat(properties.getExecutionTimeout()).isEqualTo(Duration.ofMinutes(15));
		assertThat(properties.isFixtureEnabled()).isFalse();
		assertThat(properties.getPlannedScanners()).isEmpty();
		assertThat(properties.getSupervisor().isEnabled()).isTrue();
		assertThatCode(() -> properties.validate(NO_PROFILES)).doesNotThrowAnyException();
	}

	@ParameterizedTest
	@ValueSource(strings = { "prod", "production", "PROD", "Production" })
	void theFixtureIsRefusedUnderProductionProfiles(String profile) {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setFixtureEnabled(true);

		assertThatThrownBy(() -> properties.validate(new String[] { "local", profile }))
			.isInstanceOf(IllegalStateException.class)
			.hasMessageContaining("fixture-enabled");
		assertThatCode(() -> properties.validate(new String[] { "local" })).doesNotThrowAnyException();
	}

	@Test
	void onlyExecutableScannersCanBePlannedAutomatically() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setFixtureEnabled(true);
		properties.setPlannedScanners(List.of(ScannerType.CHECKOV));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("not executable");

		properties.setPlannedScanners(List.of(ScannerType.FIXTURE));
		assertThatCode(() -> properties.validate(NO_PROFILES)).doesNotThrowAnyException();

		properties.setPlannedScanners(List.of(ScannerType.FIXTURE, ScannerType.FIXTURE));
		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("duplicates");
	}

	@Test
	void gitleaksCanBePlannedAutomaticallyOutsideProduction() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(List.of(ScannerType.GITLEAKS));

		assertThatCode(() -> properties.validate(new String[] { "local" })).doesNotThrowAnyException();
		assertThat(properties.isPlannable(ScannerType.GITLEAKS)).isTrue();
	}

	@Test
	void semgrepCanBePlannedAutomaticallyOutsideProduction() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(List.of(ScannerType.GITLEAKS, ScannerType.SEMGREP));

		assertThatCode(() -> properties.validate(new String[] { "local" })).doesNotThrowAnyException();
		assertThat(properties.isPlannable(ScannerType.SEMGREP)).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "prod", "production", "PROD" })
	void gitleaksIsNotPlannedAutomaticallyUnderProductionProfiles(String profile) {
		// Workers scan only local synthetic repositories with Gitleaks in this version.
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(List.of(ScannerType.GITLEAKS));

		assertThatThrownBy(() -> properties.validate(new String[] { profile }))
			.isInstanceOf(IllegalStateException.class)
			.hasMessageContaining("GITLEAKS is not permitted with a production profile");
	}

	@Test
	void trivyCanBePlannedAutomaticallyOutsideProduction() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(List.of(ScannerType.GITLEAKS, ScannerType.SEMGREP, ScannerType.TRIVY));

		assertThatCode(() -> properties.validate(new String[] { "local" })).doesNotThrowAnyException();
		assertThat(properties.isPlannable(ScannerType.TRIVY)).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "prod", "production", "PROD" })
	void trivyIsNotPlannedAutomaticallyUnderProductionProfiles(String profile) {
		// Workers scan only local synthetic repositories with Trivy in this version.
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(List.of(ScannerType.TRIVY));

		assertThatThrownBy(() -> properties.validate(new String[] { profile }))
			.isInstanceOf(IllegalStateException.class)
			.hasMessageContaining("TRIVY is not permitted with a production profile");
	}

	@ParameterizedTest
	@ValueSource(strings = { "prod", "production", "PROD" })
	void semgrepIsNotPlannedAutomaticallyUnderProductionProfiles(String profile) {
		// Workers scan only local synthetic repositories with Semgrep in this version.
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(List.of(ScannerType.SEMGREP));

		assertThatThrownBy(() -> properties.validate(new String[] { profile }))
			.isInstanceOf(IllegalStateException.class)
			.hasMessageContaining("SEMGREP is not permitted with a production profile");
	}

	@Test
	void plannedFixtureRequiresTheFixtureToBeEnabled() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setPlannedScanners(new ArrayList<>(List.of(ScannerType.FIXTURE)));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("fixture-enabled=true");
		assertThat(properties.isPlannable(ScannerType.FIXTURE)).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "PT14S", "PT10M1S", "PT30.5S" })
	void rejectsUnsafeLeaseDurations(String lease) {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setLeaseDuration(Duration.parse(lease));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("lease-duration");
	}

	@ParameterizedTest
	@ValueSource(strings = { "PT59S", "PT24H1S", "PT1M0.5S" })
	void rejectsUnsafeExecutionTimeouts(String timeout) {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setExecutionTimeout(Duration.parse(timeout));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("execution-timeout");
	}

	@ParameterizedTest
	@ValueSource(strings = { "PT0S", "PT12H", "P3651D", "PT36H" })
	void evidenceRetentionIsWholeDaysWithinBounds(String retention) {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setEvidenceRetention(Duration.parse(retention));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("evidence-retention");
	}

	@Test
	void evidenceIsRetainedForNinetyDaysByDefault() {
		assertThat(new ExecutionProperties().evidenceRetentionDays()).isEqualTo(90);
	}

	@Test
	void theDeadlineMustLeaveRoomForAtLeastTwoLeases() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.setLeaseDuration(Duration.ofMinutes(10));
		properties.setExecutionTimeout(Duration.ofMinutes(15));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("twice the lease duration");
	}

	@Test
	void theSupervisorMustRunAtLeastOncePerLease() {
		ExecutionProperties properties = new ExecutionProperties();
		properties.getSupervisor().setInterval(Duration.ofSeconds(61));

		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("supervisor.interval");

		properties.getSupervisor().setInterval(Duration.ofSeconds(5));
		properties.getSupervisor().setBatchSize(0);
		assertThatThrownBy(() -> properties.validate(NO_PROFILES)).hasMessageContaining("batch-size");
	}

}

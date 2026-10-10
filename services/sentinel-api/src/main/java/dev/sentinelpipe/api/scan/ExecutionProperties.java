package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.scanjob.ScannerType;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Scan execution settings ({@code sentinel.execution.*}, ADR-0007).
 *
 * <p>
 * The lease duration and execution timeout are copied onto every new scan, so the
 * database lifecycle functions enforce the values that were in force when the scan was
 * requested. Workers renew leases every quarter of the lease duration (15 s by default).
 */
@ConfigurationProperties("sentinel.execution")
public class ExecutionProperties {

	/** Profiles under which the execution fixture is refused. */
	static final List<String> PRODUCTION_PROFILES = List.of("prod", "production");

	/**
	 * Scanners that can be executed by this version: the harmless fixture and Gitleaks
	 * (ADR-0010). Gitleaks workers scan only local synthetic repositories so far, so it is
	 * not plannable automatically under a production profile.
	 */
	static final Set<ScannerType> EXECUTABLE_SCANNERS = EnumSet.of(ScannerType.FIXTURE, ScannerType.GITLEAKS);

	/**
	 * Allows the harmless FIXTURE scanner type to be planned. For development, CI and
	 * tests; refused under a production profile.
	 */
	private boolean fixtureEnabled = false;

	/** Scanner jobs planned automatically for every new scan (default: none). */
	private List<ScannerType> plannedScanners = new ArrayList<>();

	/** Lifetime of a job lease; workers renew it with heartbeats. */
	private Duration leaseDuration = Duration.ofSeconds(60);

	/** Hard deadline for a scan's execution, measured from its first claimed job. */
	private Duration executionTimeout = Duration.ofMinutes(15);

	/**
	 * How long evidence content is kept after upload (whole days). Digests, sizes and
	 * results are kept after the content is purged.
	 */
	private Duration evidenceRetention = Duration.ofDays(90);

	private final Supervisor supervisor = new Supervisor();

	public static class Supervisor {

		/** Run the supervisor in this instance (safe on many instances). */
		private boolean enabled = true;

		/** Delay between supervisor passes. */
		private Duration interval = Duration.ofSeconds(5);

		/** Upper bound of scans or jobs handled per step of one pass. */
		private int batchSize = 100;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public Duration getInterval() {
			return this.interval;
		}

		public void setInterval(Duration interval) {
			this.interval = interval;
		}

		public int getBatchSize() {
			return this.batchSize;
		}

		public void setBatchSize(int batchSize) {
			this.batchSize = batchSize;
		}

	}

	public boolean isFixtureEnabled() {
		return this.fixtureEnabled;
	}

	public void setFixtureEnabled(boolean fixtureEnabled) {
		this.fixtureEnabled = fixtureEnabled;
	}

	public List<ScannerType> getPlannedScanners() {
		return this.plannedScanners;
	}

	public void setPlannedScanners(List<ScannerType> plannedScanners) {
		this.plannedScanners = plannedScanners;
	}

	public Duration getLeaseDuration() {
		return this.leaseDuration;
	}

	public void setLeaseDuration(Duration leaseDuration) {
		this.leaseDuration = leaseDuration;
	}

	public Duration getExecutionTimeout() {
		return this.executionTimeout;
	}

	public void setExecutionTimeout(Duration executionTimeout) {
		this.executionTimeout = executionTimeout;
	}

	public Duration getEvidenceRetention() {
		return this.evidenceRetention;
	}

	public void setEvidenceRetention(Duration evidenceRetention) {
		this.evidenceRetention = evidenceRetention;
	}

	public Supervisor getSupervisor() {
		return this.supervisor;
	}

	int leaseDurationSeconds() {
		return Math.toIntExact(this.leaseDuration.toSeconds());
	}

	int executionTimeoutSeconds() {
		return Math.toIntExact(this.executionTimeout.toSeconds());
	}

	int evidenceRetentionDays() {
		return Math.toIntExact(this.evidenceRetention.toDays());
	}

	/** Whether {@code scannerType} may be planned in this configuration. */
	boolean isPlannable(ScannerType scannerType) {
		return scannerType != ScannerType.FIXTURE || this.fixtureEnabled;
	}

	/** Fails startup on unsafe or unsupported values. */
	void validate(String[] activeProfiles) {
		if (this.leaseDuration == null || this.leaseDuration.toNanosPart() != 0
				|| this.leaseDuration.toSeconds() < Scan.MIN_LEASE_SECONDS
				|| this.leaseDuration.toSeconds() > Scan.MAX_LEASE_SECONDS) {
			throw new IllegalStateException("sentinel.execution.lease-duration must be whole seconds between 15s and 10m");
		}
		if (this.executionTimeout == null || this.executionTimeout.toNanosPart() != 0
				|| this.executionTimeout.toSeconds() < Scan.MIN_TIMEOUT_SECONDS
				|| this.executionTimeout.toSeconds() > Scan.MAX_TIMEOUT_SECONDS) {
			throw new IllegalStateException(
					"sentinel.execution.execution-timeout must be whole seconds between 1m and 24h");
		}
		if (this.executionTimeout.compareTo(this.leaseDuration.multipliedBy(2)) < 0) {
			throw new IllegalStateException(
					"sentinel.execution.execution-timeout must be at least twice the lease duration");
		}
		if (this.evidenceRetention == null || !this.evidenceRetention.equals(Duration.ofDays(this.evidenceRetention.toDays()))
				|| this.evidenceRetention.toDays() < Scan.MIN_RETENTION_DAYS
				|| this.evidenceRetention.toDays() > Scan.MAX_RETENTION_DAYS) {
			throw new IllegalStateException(
					"sentinel.execution.evidence-retention must be whole days between 1d and 3650d");
		}
		if (this.plannedScanners == null) {
			throw new IllegalStateException("sentinel.execution.planned-scanners must not be null");
		}
		for (ScannerType scanner : this.plannedScanners) {
			if (!EXECUTABLE_SCANNERS.contains(scanner)) {
				throw new IllegalStateException("sentinel.execution.planned-scanners: " + scanner
						+ " is not executable by this version (only FIXTURE and GITLEAKS are)");
			}
			if (!isPlannable(scanner)) {
				throw new IllegalStateException(
						"sentinel.execution.planned-scanners: FIXTURE requires sentinel.execution.fixture-enabled=true");
			}
		}
		if (this.plannedScanners.size() != this.plannedScanners.stream().distinct().count()) {
			throw new IllegalStateException("sentinel.execution.planned-scanners must not contain duplicates");
		}
		boolean production = Arrays.stream(activeProfiles)
			.map((profile) -> profile.toLowerCase(Locale.ROOT))
			.anyMatch(PRODUCTION_PROFILES::contains);
		if (this.fixtureEnabled && production) {
			throw new IllegalStateException(
					"sentinel.execution.fixture-enabled=true is not permitted with a production profile");
		}
		if (production && this.plannedScanners.contains(ScannerType.GITLEAKS)) {
			// Workers refuse Gitleaks in production: its only repository input is local fixtures.
			throw new IllegalStateException("sentinel.execution.planned-scanners: GITLEAKS is not permitted with a "
					+ "production profile (repository input is limited to local fixtures in this version)");
		}
		if (this.supervisor.interval == null || this.supervisor.interval.compareTo(Duration.ofSeconds(1)) < 0
				|| this.supervisor.interval.compareTo(this.leaseDuration) > 0) {
			throw new IllegalStateException(
					"sentinel.execution.supervisor.interval must be between 1s and the lease duration");
		}
		if (this.supervisor.batchSize < 1 || this.supervisor.batchSize > 1000) {
			throw new IllegalStateException("sentinel.execution.supervisor.batch-size must be between 1 and 1000");
		}
	}

}

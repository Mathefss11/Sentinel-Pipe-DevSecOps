package dev.sentinelpipe.api.scan;

import java.util.EnumSet;
import java.util.Set;

/**
 * Execution status of a scan, independent of its {@link SecurityDecision}.
 *
 * <pre>
 * QUEUED ──first claim──▶ RUNNING ──all jobs terminal──▶ EVALUATING ──decision──▶ COMPLETED
 *   │                       │                              │
 *   ├──fail─────────────────┴──fail / deadline─────────────┴──fail────▶ FAILED
 *   └──cancel───────────────┴──cancel──────────────────────┴──cancel──▶ CANCELLED
 * </pre>
 *
 * COMPLETED, FAILED and CANCELLED are terminal and cannot be changed. The transitions are
 * performed by the database lifecycle functions (Flyway V007, ADR-0007); this matrix
 * documents them. Planning happens synchronously when the scan is created, so there is no
 * separate PLANNING state yet.
 */
public enum ScanExecutionStatus {

	QUEUED, RUNNING, EVALUATING, COMPLETED, FAILED, CANCELLED;

	public boolean isTerminal() {
		return this == COMPLETED || this == FAILED || this == CANCELLED;
	}

	public boolean canTransitionTo(ScanExecutionStatus target) {
		return allowedTargets().contains(target);
	}

	private Set<ScanExecutionStatus> allowedTargets() {
		return switch (this) {
			case QUEUED -> EnumSet.of(RUNNING, FAILED, CANCELLED);
			case RUNNING -> EnumSet.of(EVALUATING, FAILED, CANCELLED);
			case EVALUATING -> EnumSet.of(COMPLETED, FAILED, CANCELLED);
			case COMPLETED, FAILED, CANCELLED -> EnumSet.noneOf(ScanExecutionStatus.class);
		};
	}

}

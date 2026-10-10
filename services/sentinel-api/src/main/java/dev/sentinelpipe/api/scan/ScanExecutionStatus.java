package dev.sentinelpipe.api.scan;

import java.util.EnumSet;
import java.util.Set;

/**
 * Execution status of a scan, independent of its {@link SecurityDecision}.
 *
 * <pre>
 * QUEUED ──start──▶ RUNNING ──complete──▶ COMPLETED
 *   │                 │
 *   ├──fail───────────┴──fail────▶ FAILED
 *   └──cancel─────────┴──cancel──▶ CANCELLED
 * </pre>
 *
 * COMPLETED, FAILED and CANCELLED are terminal and cannot be changed.
 */
public enum ScanExecutionStatus {

	QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED;

	public boolean isTerminal() {
		return this == COMPLETED || this == FAILED || this == CANCELLED;
	}

	public boolean canTransitionTo(ScanExecutionStatus target) {
		return allowedTargets().contains(target);
	}

	private Set<ScanExecutionStatus> allowedTargets() {
		return switch (this) {
			case QUEUED -> EnumSet.of(RUNNING, FAILED, CANCELLED);
			case RUNNING -> EnumSet.of(COMPLETED, FAILED, CANCELLED);
			case COMPLETED, FAILED, CANCELLED -> EnumSet.noneOf(ScanExecutionStatus.class);
		};
	}

}

package dev.sentinelpipe.api.scanjob;

import java.util.EnumSet;
import java.util.Set;

/**
 * Execution status of one scanner job.
 *
 * <pre>
 * QUEUED ──start──▶ RUNNING ──complete──▶ COMPLETED
 *   │  ▲              │
 *   │  └──retry───────┤ (bounded by {@link ScanJob#MAX_ATTEMPTS})
 *   │                 ├──fail──▶ FAILED
 *   ├──fail───────────┼─────────▶ FAILED
 *   └──cancel─────────┴─cancel─▶ CANCELLED
 * </pre>
 *
 * COMPLETED means the scanner ran to completion and produced its output. It says nothing
 * about whether vulnerabilities were found.
 */
public enum ScanJobStatus {

	QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED;

	public boolean isTerminal() {
		return this == COMPLETED || this == FAILED || this == CANCELLED;
	}

	public boolean canTransitionTo(ScanJobStatus target) {
		return allowedTargets().contains(target);
	}

	private Set<ScanJobStatus> allowedTargets() {
		return switch (this) {
			case QUEUED -> EnumSet.of(RUNNING, FAILED, CANCELLED);
			case RUNNING -> EnumSet.of(QUEUED, COMPLETED, FAILED, CANCELLED);
			case COMPLETED, FAILED, CANCELLED -> EnumSet.noneOf(ScanJobStatus.class);
		};
	}

}

package dev.sentinelpipe.api.scan;

/**
 * Why a scan reached its security decision. Recorded with every final decision so that
 * an {@link SecurityDecision#INCOMPLETE} result is explained rather than silent.
 */
public enum DecisionReason {

	/**
	 * A policy evaluation produced the decision; its evaluation record explains it
	 * (ADR-0013). The only reason for PASS or FAIL, and the reason of every decision of a
	 * COMPLETED scan pinned to a policy, including INCOMPLETE (a pinned scan cancelled or
	 * failed during execution keeps its own reason).
	 */
	POLICY_EVALUATED,

	/** Every job completed, but the scan has no policy to evaluate it against: INCOMPLETE. */
	POLICY_EVALUATION_UNAVAILABLE,

	/**
	 * A scan without a policy had a job fail or be cancelled, so evidence is missing:
	 * INCOMPLETE.
	 */
	SCANNER_EXECUTION_INCOMPLETE,

	/** The scan exceeded its hard execution deadline. */
	EXECUTION_DEADLINE_EXCEEDED,

	/** The scan was marked failed by a trusted internal component. */
	EXECUTION_FAILED,

	/** An authorized user cancelled the scan. */
	CANCELLED_BY_USER

}

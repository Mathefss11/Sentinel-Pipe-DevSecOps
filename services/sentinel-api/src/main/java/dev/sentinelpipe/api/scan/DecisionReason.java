package dev.sentinelpipe.api.scan;

/**
 * Why a scan reached its security decision. Recorded with every final decision so that
 * an {@link SecurityDecision#INCOMPLETE} result is explained rather than silent.
 */
public enum DecisionReason {

	/** A policy evaluation produced the decision (the only reason for PASS or FAIL). */
	POLICY_EVALUATED,

	/** Every job completed, but no policy evaluation is available yet: INCOMPLETE. */
	POLICY_EVALUATION_UNAVAILABLE,

	/** At least one job failed or was cancelled, so evidence is missing: INCOMPLETE. */
	SCANNER_EXECUTION_INCOMPLETE,

	/** The scan exceeded its hard execution deadline. */
	EXECUTION_DEADLINE_EXCEEDED,

	/** The scan was marked failed by a trusted internal component. */
	EXECUTION_FAILED,

	/** An authorized user cancelled the scan. */
	CANCELLED_BY_USER

}

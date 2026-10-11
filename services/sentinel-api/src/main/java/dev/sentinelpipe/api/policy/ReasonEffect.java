package dev.sentinelpipe.api.policy;

/** How a reason affects the decision (precedence: VIOLATION, then INCOMPLETE). */
public enum ReasonEffect {

	/** Valid evidence violates the policy: FAIL. */
	VIOLATION,

	/** The policy cannot be shown to be satisfied: INCOMPLETE unless there is a violation. */
	INCOMPLETE

}

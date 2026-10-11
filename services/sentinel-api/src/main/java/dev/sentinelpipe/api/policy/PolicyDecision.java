package dev.sentinelpipe.api.policy;

import java.util.Collection;

/**
 * Outcome of a policy evaluation. Precedence is fixed (ADR-0013): any violation is FAIL,
 * even when other evidence is incomplete (a confirmed violation is never hidden by missing
 * evidence elsewhere); otherwise any incomplete reason is INCOMPLETE; only an evaluation
 * without reasons is PASS. FAIL and INCOMPLETE both block a merge.
 */
public enum PolicyDecision {

	PASS, FAIL, INCOMPLETE;

	public static PolicyDecision of(Collection<Reason> reasons) {
		if (reasons.stream().anyMatch((reason) -> reason.effect() == ReasonEffect.VIOLATION)) {
			return FAIL;
		}
		return reasons.isEmpty() ? PASS : INCOMPLETE;
	}

}

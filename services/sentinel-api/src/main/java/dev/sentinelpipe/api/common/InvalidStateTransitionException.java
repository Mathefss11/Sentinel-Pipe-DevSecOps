package dev.sentinelpipe.api.common;

/** A lifecycle transition that the state machine does not allow. */
public class InvalidStateTransitionException extends DomainRuleViolationException {

	public InvalidStateTransitionException(String aggregate, Enum<?> from, Enum<?> to) {
		super(aggregate + " cannot transition from " + from + " to " + to);
	}

}

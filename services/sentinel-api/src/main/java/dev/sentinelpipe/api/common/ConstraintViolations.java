package dev.sentinelpipe.api.common;

import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Identifies which database constraint caused a {@link DataIntegrityViolationException}.
 * The database constraints are the authoritative guard against concurrent duplicates;
 * services translate known violations into domain conflicts.
 */
public final class ConstraintViolations {

	private ConstraintViolations() {
	}

	public static boolean isViolationOf(DataIntegrityViolationException exception, String constraintName) {
		for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
			if (cause instanceof ConstraintViolationException violation
					&& constraintName.equalsIgnoreCase(violation.getConstraintName())) {
				return true;
			}
		}
		return false;
	}

}

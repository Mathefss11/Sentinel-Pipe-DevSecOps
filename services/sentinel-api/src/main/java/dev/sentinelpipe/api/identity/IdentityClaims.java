package dev.sentinelpipe.api.identity;

import dev.sentinelpipe.api.common.DomainValidationException;
import java.util.regex.Pattern;

/** Validation of the issuer and subject values that identify a user. */
public final class IdentityClaims {

	/** Non-blank and free of control characters. */
	public static final String SUBJECT_REGEX = "^(?=.*\\S)[^\\p{Cntrl}]+$";

	private static final Pattern VALID = Pattern.compile(SUBJECT_REGEX);

	private IdentityClaims() {
	}

	public static boolean isValidSubject(String subject) {
		return subject != null && subject.length() <= UserIdentity.SUBJECT_MAX_LENGTH
				&& VALID.matcher(subject).matches();
	}

	public static boolean isValidIssuer(String issuer) {
		return issuer != null && issuer.length() <= UserIdentity.ISSUER_MAX_LENGTH && VALID.matcher(issuer).matches();
	}

	static String requireSubject(String subject) {
		if (!isValidSubject(subject)) {
			throw new DomainValidationException("subject",
					"must be 1-" + UserIdentity.SUBJECT_MAX_LENGTH + " characters without control characters");
		}
		return subject;
	}

	static String requireIssuer(String issuer) {
		if (!isValidIssuer(issuer)) {
			throw new DomainValidationException("issuer",
					"must be 1-" + UserIdentity.ISSUER_MAX_LENGTH + " characters without control characters");
		}
		return issuer;
	}

}

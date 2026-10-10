package dev.sentinelpipe.api.common;

import java.util.regex.Pattern;

/** Normalization and validation of human-readable display names. */
public final class DisplayNames {

	public static final int MAX_LENGTH = 100;

	/** Rejects control characters, including line breaks, to keep names safe for logs and reports. */
	public static final String NO_CONTROL_CHARACTERS_REGEX = "^[^\\p{Cntrl}]*$";

	private static final Pattern NO_CONTROL_CHARACTERS = Pattern.compile(NO_CONTROL_CHARACTERS_REGEX);

	private DisplayNames() {
	}

	/** Returns the stripped name or throws {@link DomainValidationException}. */
	public static String normalize(String field, String value) {
		if (value == null || value.isBlank()) {
			throw new DomainValidationException(field, "must not be blank");
		}
		String stripped = value.strip();
		if (stripped.length() > MAX_LENGTH) {
			throw new DomainValidationException(field, "must be at most " + MAX_LENGTH + " characters");
		}
		if (!NO_CONTROL_CHARACTERS.matcher(stripped).matches()) {
			throw new DomainValidationException(field, "must not contain control characters");
		}
		return stripped;
	}

}

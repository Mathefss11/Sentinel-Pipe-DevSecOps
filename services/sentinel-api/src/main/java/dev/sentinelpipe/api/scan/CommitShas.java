package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.DomainValidationException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validation of full Git commit object names: 40 hexadecimal characters (SHA-1) or 64
 * (SHA-256). Abbreviated SHAs, branch names and other revision expressions are rejected
 * because they are ambiguous or mutable. Values are normalized to lowercase.
 */
final class CommitShas {

	static final String INPUT_REGEX = "^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$";

	private static final Pattern NORMALIZED = Pattern.compile("^[0-9a-f]{40}([0-9a-f]{24})?$");

	private CommitShas() {
	}

	static String normalize(String commitSha) {
		String normalized = (commitSha != null) ? commitSha.toLowerCase(Locale.ROOT) : null;
		if (normalized == null || !NORMALIZED.matcher(normalized).matches()) {
			throw new DomainValidationException("commitSha",
					"must be a full 40-character (SHA-1) or 64-character (SHA-256) hexadecimal commit SHA");
		}
		return normalized;
	}

}

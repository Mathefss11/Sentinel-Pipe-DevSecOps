package dev.sentinelpipe.api.common;

import java.util.regex.Pattern;

/**
 * Validates short Git branch names (for example {@code main} or {@code feature/login}).
 *
 * <p>
 * This is a deliberately conservative subset of {@code git check-ref-format}: only ASCII
 * letters, digits, {@code .}, {@code _}, {@code -} and {@code /} are accepted. Full ref
 * names ({@code refs/heads/...}), revision syntax ({@code @{}, {@code ~}, {@code ^},
 * {@code :}), wildcards, whitespace and control characters are rejected. Branch names are
 * case-sensitive and are not normalized.
 */
public final class GitBranchNames {

	public static final int MAX_LENGTH = 255;

	private static final Pattern ALLOWED_CHARACTERS = Pattern.compile("^[A-Za-z0-9._/-]+$");

	private GitBranchNames() {
	}

	public static boolean isValid(String name) {
		if (name == null || name.isEmpty() || name.length() > MAX_LENGTH) {
			return false;
		}
		if (!ALLOWED_CHARACTERS.matcher(name).matches()) {
			return false;
		}
		if (name.startsWith("-") || name.startsWith("refs/") || name.equals("HEAD")) {
			return false;
		}
		if (name.contains("..") || name.contains("//") || name.endsWith(".")) {
			return false;
		}
		for (String component : name.split("/", -1)) {
			if (component.isEmpty() || component.startsWith(".") || component.endsWith(".lock")) {
				return false;
			}
		}
		return true;
	}

	/** Returns the name unchanged or throws {@link DomainValidationException}. */
	public static String require(String field, String name) {
		if (!isValid(name)) {
			throw new DomainValidationException(field, "must be a valid Git branch name");
		}
		return name;
	}

}

package dev.sentinelpipe.api.project;

import dev.sentinelpipe.api.common.DomainValidationException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Normalization and validation of GitHub repository identity.
 *
 * <p>
 * A repository is identified only by its owner and name; URLs are never accepted, so a
 * client cannot point SentinelPipe at an arbitrary host or path. GitHub treats owner and
 * repository names case-insensitively, so both are stored in lowercase, which also makes
 * duplicate detection case-insensitive.
 */
final class GitHubRepositoryNames {

	static final int OWNER_MAX_LENGTH = 39;

	static final int NAME_MAX_LENGTH = 100;

	/** Request-level patterns (case-insensitive input); stored values are lowercase. */
	static final String OWNER_INPUT_REGEX = "^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$";

	static final String NAME_INPUT_REGEX = "^[A-Za-z0-9._-]+$";

	private static final Pattern OWNER = Pattern.compile("^[a-z0-9]+(-[a-z0-9]+)*$");

	private static final Pattern NAME = Pattern.compile("^[a-z0-9._-]+$");

	private GitHubRepositoryNames() {
	}

	static String normalizeOwner(String owner) {
		String normalized = (owner != null) ? owner.toLowerCase(Locale.ROOT) : null;
		if (normalized == null || normalized.length() > OWNER_MAX_LENGTH || !OWNER.matcher(normalized).matches()) {
			throw new DomainValidationException("repositoryOwner",
					"must be a GitHub user or organization name: 1-39 letters, digits or single hyphens, "
							+ "not starting or ending with a hyphen");
		}
		return normalized;
	}

	static String normalizeName(String name) {
		String normalized = (name != null) ? name.toLowerCase(Locale.ROOT) : null;
		if (normalized == null || normalized.length() > NAME_MAX_LENGTH || !NAME.matcher(normalized).matches()
				|| normalized.equals(".") || normalized.equals("..") || normalized.endsWith(".git")) {
			throw new DomainValidationException("repositoryName",
					"must be a GitHub repository name: 1-100 letters, digits, '.', '_' or '-', "
							+ "not '.', '..' and without a '.git' suffix");
		}
		return normalized;
	}

}

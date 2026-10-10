package dev.sentinelpipe.api.scan;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 fingerprint of a normalized scan request. Used only to detect reuse of an
 * {@code Idempotency-Key} with a different payload; it is not a security credential.
 * The version prefix allows the canonical form to evolve without ambiguity.
 */
final class ScanRequestFingerprint {

	private static final String CANONICAL_FORM_VERSION = "scan-request.v1";

	private ScanRequestFingerprint() {
	}

	/** All arguments must already be validated and normalized. */
	static String of(String commitSha, String branch, TriggerType triggerType) {
		String canonical = String.join("\n", CANONICAL_FORM_VERSION, commitSha, branch, triggerType.name());
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return HexFormat.of().formatHex(digest.digest(canonical.getBytes(StandardCharsets.UTF_8)));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is required by every Java platform", ex);
		}
	}

}

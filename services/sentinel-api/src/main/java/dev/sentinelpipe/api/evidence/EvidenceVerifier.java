package dev.sentinelpipe.api.evidence;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Recomputes SHA-256 digests of evidence bytes independently of the storage backend. */
public final class EvidenceVerifier {

	private EvidenceVerifier() {
	}

	public static String sha256(byte[] content) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 unavailable", ex);
		}
	}

	/**
	 * @throws EvidenceIntegrityException if {@code content} does not have the recorded size
	 * and digest
	 */
	public static void verify(String name, String recordedSha256, long recordedSize, byte[] content) {
		// Digests are not secrets, so a constant-time comparison is not needed.
		if (content.length != recordedSize || !sha256(content).equals(recordedSha256)) {
			throw new EvidenceIntegrityException("Evidence '" + name + "' does not match its recorded digest");
		}
	}

}

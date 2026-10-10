package dev.sentinelpipe.api.evidence;

/**
 * Stored evidence does not match the digest or size recorded at upload: it was altered
 * or corrupted after it was verified. The message names the artifact, never its content.
 */
public class EvidenceIntegrityException extends RuntimeException {

	public EvidenceIntegrityException(String message) {
		super(message);
	}

}

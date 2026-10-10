package dev.sentinelpipe.api.evidence;

import java.util.Arrays;

/**
 * Verified evidence content: the bytes matched the recorded SHA-256 and size when read.
 * {@link #toString()} never includes the content.
 */
public record Evidence(String name, String mediaType, String sha256, byte[] content) {

	public Evidence {
		content = content.clone();
	}

	@Override
	public byte[] content() {
		return this.content.clone();
	}

	@Override
	public boolean equals(Object other) {
		return other instanceof Evidence evidence && this.name.equals(evidence.name)
				&& this.mediaType.equals(evidence.mediaType) && this.sha256.equals(evidence.sha256)
				&& Arrays.equals(this.content, evidence.content);
	}

	@Override
	public int hashCode() {
		return this.sha256.hashCode();
	}

	@Override
	public String toString() {
		return "Evidence[name=" + this.name + ", mediaType=" + this.mediaType + ", sha256=" + this.sha256 + ", size="
				+ this.content.length + "]";
	}

}

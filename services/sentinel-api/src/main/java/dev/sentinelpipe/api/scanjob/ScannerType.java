package dev.sentinelpipe.api.scanjob;

/**
 * Scanners on the SentinelPipe roadmap. These are identifiers only; no scanner is
 * integrated or executed by this version.
 */
public enum ScannerType {

	/** Static application security testing. */
	SEMGREP,

	/** Secrets detection. */
	GITLEAKS,

	/** Dependency and container vulnerability scanning. */
	TRIVY,

	/** Infrastructure-as-code scanning. */
	CHECKOV,

	/** Software bill of materials generation. */
	SYFT,

	/** Dynamic application security testing. */
	ZAP

}

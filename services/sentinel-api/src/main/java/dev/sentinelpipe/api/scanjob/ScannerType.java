package dev.sentinelpipe.api.scanjob;

/**
 * Scanners on the SentinelPipe roadmap. {@link #GITLEAKS} is executed by workers (ADR-0010,
 * local synthetic repositories only); the other real scanners are identifiers only.
 * {@link #FIXTURE} is a harmless execution fixture used to exercise the execution
 * lifecycle and isolation.
 */
public enum ScannerType {

	/** Static application security testing. */
	SEMGREP,

	/** Secrets detection (Gitleaks 8.30.1 in an isolated sandbox, ADR-0010). */
	GITLEAKS,

	/** Dependency and container vulnerability scanning. */
	TRIVY,

	/** Infrastructure-as-code scanning. */
	CHECKOV,

	/** Software bill of materials generation. */
	SYFT,

	/** Dynamic application security testing. */
	ZAP,

	/**
	 * Harmless execution fixture: runs no scanner and inspects no repository content. It
	 * validates leases, heartbeats, cancellation and (later) sandbox limits. Plannable only
	 * when {@code sentinel.execution.fixture-enabled=true}, which production profiles refuse.
	 */
	FIXTURE

}

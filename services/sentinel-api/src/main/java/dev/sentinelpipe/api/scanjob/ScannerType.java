package dev.sentinelpipe.api.scanjob;

/**
 * Scanners on the SentinelPipe roadmap. The real scanners are identifiers only; none is
 * integrated or executed by this version. {@link #FIXTURE} is a harmless execution
 * fixture used to exercise the execution lifecycle and isolation.
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
	ZAP,

	/**
	 * Harmless execution fixture: runs no scanner and inspects no repository content. It
	 * validates leases, heartbeats, cancellation and (later) sandbox limits. Plannable only
	 * when {@code sentinel.execution.fixture-enabled=true}, which production profiles refuse.
	 */
	FIXTURE

}

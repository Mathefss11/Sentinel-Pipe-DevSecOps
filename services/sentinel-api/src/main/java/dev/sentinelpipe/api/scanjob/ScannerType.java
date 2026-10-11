package dev.sentinelpipe.api.scanjob;

/**
 * Scanners on the SentinelPipe roadmap. {@link #GITLEAKS} (ADR-0010) and {@link #SEMGREP}
 * (ADR-0011) are executed by workers, on local synthetic repositories only; the other real
 * scanners are identifiers only.
 * {@link #FIXTURE} is a harmless execution fixture used to exercise the execution
 * lifecycle and isolation.
 */
public enum ScannerType {

	/** Static application security testing (Semgrep 1.179.0, bundled ruleset, ADR-0011). */
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

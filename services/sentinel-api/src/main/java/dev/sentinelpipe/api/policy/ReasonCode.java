package dev.sentinelpipe.api.policy;

/**
 * Structured reasons of a policy evaluation. Each code has a fixed effect: a
 * {@link ReasonEffect#VIOLATION} means valid evidence breaks a policy rule; an
 * {@link ReasonEffect#INCOMPLETE} means the policy cannot be shown to be satisfied.
 * Codes are part of the evaluation record and the API: add, never rename.
 */
public enum ReasonCode {

	// --- Violations: established by valid evidence -----------------------------------

	/** More blocking findings than the policy allows ({@code observed} > {@code limit}). */
	BLOCKING_FINDINGS_EXCEEDED(ReasonEffect.VIOLATION),

	// --- Policy ----------------------------------------------------------------------

	/** The pinned policy no longer validates or does not match its digest. */
	POLICY_INVALID(ReasonEffect.INCOMPLETE),

	// --- Execution -------------------------------------------------------------------

	/** The policy requires a scanner the scan did not plan. */
	REQUIRED_SCANNER_NOT_PLANNED(ReasonEffect.INCOMPLETE),

	/** The scan ran a scanner the policy does not govern; its evidence cannot be judged. */
	SCANNER_NOT_IN_POLICY(ReasonEffect.INCOMPLETE),

	/** The scanner job failed ({@code subject}: the failure reason). */
	SCANNER_EXECUTION_FAILED(ReasonEffect.INCOMPLETE),

	/** The scanner job was cancelled. */
	SCANNER_EXECUTION_CANCELLED(ReasonEffect.INCOMPLETE),

	/** The scanner job did not reach a terminal state. */
	SCANNER_EXECUTION_UNFINISHED(ReasonEffect.INCOMPLETE),

	// --- Evidence --------------------------------------------------------------------

	/** A completed job has no accepted result or no {@code findings.json} of record. */
	EVIDENCE_MISSING(ReasonEffect.INCOMPLETE),

	/** The evidence content was purged by retention and cannot be re-verified. */
	EVIDENCE_PURGED(ReasonEffect.INCOMPLETE),

	/**
	 * Stored bytes or the stored result do not match their recorded digests, or the result
	 * does not reference the artifact of record ({@code subject} says which).
	 */
	EVIDENCE_INTEGRITY_FAILED(ReasonEffect.INCOMPLETE),

	/** The evidence names another tenant, project, scan, job, commit or scanner. */
	EVIDENCE_BINDING_MISMATCH(ReasonEffect.INCOMPLETE),

	/** The evidence is not valid {@code findings.v1}. */
	EVIDENCE_INVALID(ReasonEffect.INCOMPLETE),

	/** The evidence schema version is not accepted by the policy or the engine. */
	EVIDENCE_SCHEMA_UNSUPPORTED(ReasonEffect.INCOMPLETE),

	/** The evidence contradicts itself ({@code subject} says where); it is discarded. */
	EVIDENCE_INCONSISTENT(ReasonEffect.INCOMPLETE),

	/** The evidence is older than the policy allows. */
	EVIDENCE_STALE(ReasonEffect.INCOMPLETE),

	// --- Coverage --------------------------------------------------------------------

	/** The scanner reports incomplete coverage and the policy requires complete coverage. */
	COVERAGE_INCOMPLETE(ReasonEffect.INCOMPLETE),

	/** The evidence carries a limitation ({@code subject}) the policy does not accept. */
	COVERAGE_LIMITATION_NOT_ACCEPTED(ReasonEffect.INCOMPLETE),

	/** Coverage metadata the scanner must report is absent ({@code subject}: which). */
	COVERAGE_METADATA_MISSING(ReasonEffect.INCOMPLETE),

	/**
	 * Findings without a severity label of the scanner's own scale ({@code observed}:
	 * how many). They are neither counted as blocking nor ignored.
	 */
	UNSUPPORTED_SCANNER_SEVERITY(ReasonEffect.INCOMPLETE),

	// --- Vulnerability database (Trivy) ----------------------------------------------

	/** The vulnerability database is older than the policy allows. */
	VULNERABILITY_DATABASE_TOO_OLD(ReasonEffect.INCOMPLETE),

	/** The database timestamps are implausible (dated after the scan). */
	VULNERABILITY_DATABASE_METADATA_INVALID(ReasonEffect.INCOMPLETE),

	// --- Engine ----------------------------------------------------------------------

	/** The engine failed unexpectedly; nothing was concluded. */
	EVALUATION_ERROR(ReasonEffect.INCOMPLETE);

	private final ReasonEffect effect;

	ReasonCode(ReasonEffect effect) {
		this.effect = effect;
	}

	public ReasonEffect effect() {
		return this.effect;
	}

}

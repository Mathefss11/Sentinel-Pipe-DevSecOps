package dev.sentinelpipe.api.scan;

/**
 * Security gate outcome of a scan, independent of its {@link ScanExecutionStatus}. A
 * {@code COMPLETED} scan may carry {@code FAIL} or {@code INCOMPLETE}; successful
 * execution never implies {@code PASS}.
 */
public enum SecurityDecision {

	/** No decision yet; the scan has not reached a terminal execution status. */
	PENDING,

	/** All required controls completed and policy permits the change. */
	PASS,

	/** Valid evidence violates one or more blocking policies. */
	FAIL,

	/**
	 * Required evidence, scanner execution, policy evaluation or integrity verification is
	 * missing or invalid. Must never approve a merge.
	 */
	INCOMPLETE;

	public boolean isFinal() {
		return this != PENDING;
	}

}

package dev.sentinelpipe.api.scanjob;

/**
 * Why a job attempt failed. Set on a FAILED job, and on a requeued job for its last
 * failed attempt. Whether a failure is retried is decided by the control plane, not by the
 * reporting worker (Flyway V007, {@code worker.report_job}).
 */
public enum JobFailureReason {

	/** The worker stopped renewing its lease (crash, hang or partition). Retried. */
	LEASE_EXPIRED,

	/** The scanner failed to run. Retried. */
	SCANNER_ERROR,

	/** The isolated execution environment failed. Retried. */
	SANDBOX_ERROR,

	/** The worker shut down and released the job. Retried. */
	WORKER_SHUTDOWN,

	/** The evidence could not be stored or verified. Retried. */
	EVIDENCE_UNAVAILABLE,

	/** The execution exceeded its per-attempt time limit. Final. */
	EXECUTION_TIMEOUT,

	/** The execution exceeded a resource limit (memory, processes, output). Final. */
	RESOURCE_LIMIT_EXCEEDED,

	/** The worker cannot execute this scanner type. Final. */
	UNSUPPORTED_SCANNER,

	/** The scan exceeded its hard execution deadline. Final. */
	EXECUTION_DEADLINE_EXCEEDED

}

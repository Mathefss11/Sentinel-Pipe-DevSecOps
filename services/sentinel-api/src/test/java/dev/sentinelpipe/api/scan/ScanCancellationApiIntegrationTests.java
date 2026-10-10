package dev.sentinelpipe.api.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestDatabaseAdmin;
import dev.sentinelpipe.api.TestJwts;
import dev.sentinelpipe.api.WorkerProtocol;
import dev.sentinelpipe.api.WorkerProtocol.Lease;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.ResultActions;

/**
 * {@code POST /api/v1/projects/{projectId}/scans/{scanId}/cancel}: MEMBER and above,
 * tenant-checked, idempotent, audited with the caller's server-side identity.
 */
class ScanCancellationApiIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanLifecycleService lifecycle;

	@Autowired
	private TestDatabaseAdmin admin;

	private UUID organizationId;

	private UUID projectId;

	private UUID scanId;

	@BeforeEach
	void scanWithAFixtureJob() throws Exception {
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "app");
		this.scanId = UUID.fromString(json(requestScan(this.projectId, randomSha(), null)).get("id").asString());
		this.lifecycle.planJob(this.scanId, ScannerType.FIXTURE);
	}

	private ResultActions cancel(UUID projectId, UUID scanId, String subject) throws Exception {
		return this.mockMvc.perform(post("/api/v1/projects/{p}/scans/{s}/cancel", projectId, scanId)
			.header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(subject)));
	}

	private String member(String role) throws Exception {
		String subject = uniqueSubject(role.toLowerCase());
		grant(this.organizationId, subject, role);
		return subject;
	}

	private String scanStatus() {
		return this.jdbcTemplate.queryForObject("SELECT execution_status FROM scans WHERE id = ?", String.class,
				this.scanId);
	}

	@Test
	void aMemberCancelsAScanAndTheDecisionIsIncomplete() throws Exception {
		String member = member("MEMBER");

		cancel(this.projectId, this.scanId, member).andExpect(status().isOk())
			.andExpect(jsonPath("$.id").value(this.scanId.toString()))
			.andExpect(jsonPath("$.executionStatus").value("CANCELLED"))
			.andExpect(jsonPath("$.securityDecision").value("INCOMPLETE"))
			.andExpect(jsonPath("$.decisionReason").value("CANCELLED_BY_USER"))
			.andExpect(jsonPath("$.jobs[0].executionStatus").value("CANCELLED"));

		// Audited with the caller's server-side identity, not a request value.
		UUID identityId = this.jdbcTemplate.queryForObject("SELECT id FROM user_identities WHERE subject = ?",
				UUID.class, member);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT actor FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = 'SCAN_CANCELLED'",
				String.class, this.scanId))
			.isEqualTo("user:" + identityId);
	}

	@Test
	void cancellationIsIdempotent() throws Exception {
		String member = member("MEMBER");
		cancel(this.projectId, this.scanId, member).andExpect(status().isOk());

		cancel(this.projectId, this.scanId, member).andExpect(status().isOk())
			.andExpect(jsonPath("$.executionStatus").value("CANCELLED"));

		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM lifecycle.execution_events WHERE scan_id = ? AND event_type = 'SCAN_CANCELLED'",
				Integer.class, this.scanId))
			.isEqualTo(1);
	}

	@Test
	void aRunningWorkerIsToldToStopAndCannotReport() throws Exception {
		WorkerProtocol worker = WorkerProtocol.asWorker(this.admin);
		Lease lease = worker.claimFixtureOrFail(this.scanId);

		cancel(this.projectId, this.scanId, member("ADMIN")).andExpect(status().isOk());

		assertThat(worker.heartbeat(lease).status()).isEqualTo("CANCELLED");
		assertThat(worker.complete(lease)).isEqualTo("REJECTED_JOB_NOT_RUNNING");
	}

	@Test
	void viewersCannotCancel() throws Exception {
		cancel(this.projectId, this.scanId, member("VIEWER")).andExpect(status().isForbidden());

		assertThat(scanStatus()).isEqualTo("QUEUED");
	}

	@Test
	void outsidersCannotCancelOrLearnThatTheScanExists() throws Exception {
		cancel(this.projectId, this.scanId, uniqueSubject("outsider")).andExpect(status().isNotFound());

		assertThat(scanStatus()).isEqualTo("QUEUED");
	}

	@Test
	void aMemberOfAnotherOrganizationCannotCancelThroughItsOwnProject() throws Exception {
		// The attacker owns an organization and project, and knows the victim's scan id.
		String attacker = uniqueSubject("attacker");
		UUID attackerOrganization = createOrganization();
		UUID attackerProject = createProject(attackerOrganization, "own");
		grant(attackerOrganization, attacker, "OWNER");

		cancel(attackerProject, this.scanId, attacker).andExpect(status().isNotFound());

		assertThat(scanStatus()).isEqualTo("QUEUED");
	}

	@Test
	void aScanIsOnlyCancellableThroughItsOwnProject() throws Exception {
		UUID otherProject = createProject(this.organizationId, "other");

		cancel(otherProject, this.scanId, TestJwts.PLATFORM_ADMIN).andExpect(status().isNotFound());
		cancel(this.projectId, UUID.randomUUID(), TestJwts.PLATFORM_ADMIN).andExpect(status().isNotFound());

		assertThat(scanStatus()).isEqualTo("QUEUED");
	}

	@Test
	void finishedScansCannotBeCancelled() throws Exception {
		WorkerProtocol worker = WorkerProtocol.asWorker(this.admin);
		worker.complete(worker.claimFixtureOrFail(this.scanId));
		this.lifecycle.evaluate(this.scanId);

		cancel(this.projectId, this.scanId, TestJwts.PLATFORM_ADMIN).andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("scan-not-cancellable"));

		assertThat(scanStatus()).isEqualTo("COMPLETED");
	}

}

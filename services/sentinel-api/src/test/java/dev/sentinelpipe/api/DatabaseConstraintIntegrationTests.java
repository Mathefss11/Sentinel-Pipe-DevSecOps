package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Verifies that the database itself rejects inconsistent domain state, independently of
 * the application code (defense in depth against defects and manual writes).
 */
class DatabaseConstraintIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final Timestamp NOW = Timestamp.from(Instant.parse("2026-10-09T12:00:00Z"));

	private static final Timestamp LATER = Timestamp.from(Instant.parse("2026-10-09T12:05:00Z"));

	private static final String SHA = "4f2c8e1d9b7a6c5e3f1a2b4c6d8e0f1a3b5c7d9e";

	private UUID insertOrganization() {
		UUID id = UUID.randomUUID();
		this.jdbcTemplate.update(
				"INSERT INTO organizations (id, name, slug, version, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)",
				id, "Org", uniqueSlug("db"), NOW, NOW);
		return id;
	}

	private UUID insertProject(UUID organizationId, String owner, String name) {
		UUID id = UUID.randomUUID();
		this.jdbcTemplate.update("""
				INSERT INTO projects (id, organization_id, name, repository_provider, repository_owner,
				    repository_name, default_branch, enabled, version, created_at, updated_at)
				VALUES (?, ?, 'P', 'GITHUB', ?, ?, 'main', true, 0, ?, ?)
				""", id, organizationId, owner, name, NOW, NOW);
		return id;
	}

	private UUID insertProject() {
		return insertProject(insertOrganization(), "acme", "repo");
	}

	private UUID insertScan(UUID projectId, String sha, String status, String decision, Timestamp startedAt,
			Timestamp completedAt, String key, String fingerprint) {
		UUID id = UUID.randomUUID();
		this.jdbcTemplate.update("""
				INSERT INTO scans (id, project_id, commit_sha, branch, trigger_type, execution_status,
				    security_decision, idempotency_key, request_fingerprint, version, requested_at,
				    started_at, completed_at, updated_at)
				VALUES (?, ?, ?, 'main', 'PUSH', ?, ?, ?, ?, 0, ?, ?, ?, ?)
				""", id, projectId, sha, status, decision, key, fingerprint, NOW, startedAt, completedAt, LATER);
		return id;
	}

	private UUID insertQueuedScan(UUID projectId) {
		return insertScan(projectId, SHA, "QUEUED", "PENDING", null, null, null, null);
	}

	private void insertJob(UUID scanId, String scanner, String status, int attempts, Timestamp startedAt,
			Timestamp completedAt) {
		this.jdbcTemplate.update("""
				INSERT INTO scan_jobs (id, scan_id, scanner_type, execution_status, attempt_count, version,
				    created_at, started_at, completed_at, updated_at)
				VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
				""", UUID.randomUUID(), scanId, scanner, status, attempts, NOW, startedAt, completedAt, LATER);
	}

	@Test
	void organizationSlugMustBeUniqueAndWellFormed() {
		String slug = uniqueSlug("dup");
		this.jdbcTemplate.update(
				"INSERT INTO organizations (id, name, slug, version, created_at, updated_at) VALUES (?, 'A', ?, 0, ?, ?)",
				UUID.randomUUID(), slug, NOW, NOW);

		assertThatThrownBy(() -> this.jdbcTemplate.update(
				"INSERT INTO organizations (id, name, slug, version, created_at, updated_at) VALUES (?, 'B', ?, 0, ?, ?)",
				UUID.randomUUID(), slug, NOW, NOW))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_organizations_slug");
		assertThatThrownBy(() -> this.jdbcTemplate.update(
				"INSERT INTO organizations (id, name, slug, version, created_at, updated_at) VALUES (?, 'C', 'Bad Slug', 0, ?, ?)",
				UUID.randomUUID(), NOW, NOW))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_organizations_slug_format");
	}

	@Test
	void projectRequiresExistingOrganization() {
		assertThatThrownBy(() -> insertProject(UUID.randomUUID(), "acme", "repo"))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("fk_projects_organization");
	}

	@Test
	void repositoryIdentityIsUniquePerOrganizationAndStoredNormalized() {
		UUID organizationId = insertOrganization();
		insertProject(organizationId, "acme", "repo");

		assertThatThrownBy(() -> insertProject(organizationId, "acme", "repo"))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_projects_organization_repository");
		assertThatThrownBy(() -> insertProject(organizationId, "Acme", "other"))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_projects_repository_owner_format");
		assertThatThrownBy(() -> insertProject(organizationId, "acme", "repo.git"))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_projects_repository_name_format");
	}

	@Test
	void organizationsWithProjectsCannotBeDeleted() {
		UUID organizationId = insertOrganization();
		insertProject(organizationId, "acme", "repo");

		assertThatThrownBy(() -> this.jdbcTemplate.update("DELETE FROM organizations WHERE id = ?", organizationId))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("fk_projects_organization");
	}

	@Test
	void commitShaMustBeAFullLowercaseObjectName() {
		UUID projectId = insertProject();

		assertThatThrownBy(() -> insertScan(projectId, "abc123", "QUEUED", "PENDING", null, null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_scans_commit_sha_format");
		assertThatThrownBy(() -> insertScan(projectId, SHA.toUpperCase(), "QUEUED", "PENDING", null, null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_scans_commit_sha_format");
	}

	@Test
	void unknownStatusesAndDecisionsAreRejected() {
		UUID projectId = insertProject();

		assertThatThrownBy(() -> insertScan(projectId, SHA, "DONE", "PENDING", null, null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_scans_execution_status");
		assertThatThrownBy(() -> insertScan(projectId, SHA, "QUEUED", "OK", null, null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("ck_scans_security_decision");
	}

	@Test
	void securityDecisionMustBeConsistentWithExecutionStatus() {
		UUID projectId = insertProject();

		// A queued or running scan cannot already have a verdict.
		assertThatThrownBy(() -> insertScan(projectId, SHA, "QUEUED", "PASS", null, null, null, null))
			.hasMessageContaining("ck_scans_status_decision");
		// A completed scan must have a final decision.
		assertThatThrownBy(() -> insertScan(projectId, SHA, "COMPLETED", "PENDING", NOW, LATER, null, null))
			.hasMessageContaining("ck_scans_status_decision");
		// Fail closed: failed or cancelled scans can never pass or fail.
		assertThatThrownBy(() -> insertScan(projectId, SHA, "FAILED", "PASS", NOW, LATER, null, null))
			.hasMessageContaining("ck_scans_status_decision");
		assertThatThrownBy(() -> insertScan(projectId, SHA, "CANCELLED", "FAIL", null, LATER, null, null))
			.hasMessageContaining("ck_scans_status_decision");

		assertThatCode(() -> insertScan(projectId, SHA, "COMPLETED", "FAIL", NOW, LATER, null, null))
			.doesNotThrowAnyException();
		assertThatCode(() -> insertScan(projectId, SHA, "CANCELLED", "INCOMPLETE", null, LATER, null, null))
			.doesNotThrowAnyException();
	}

	@Test
	void timestampsMustMatchExecutionStatus() {
		UUID projectId = insertProject();

		assertThatThrownBy(() -> insertScan(projectId, SHA, "QUEUED", "PENDING", NOW, null, null, null))
			.hasMessageContaining("ck_scans_status_timestamps");
		assertThatThrownBy(() -> insertScan(projectId, SHA, "RUNNING", "PENDING", null, null, null, null))
			.hasMessageContaining("ck_scans_status_timestamps");
		assertThatThrownBy(() -> insertScan(projectId, SHA, "COMPLETED", "PASS", NOW, null, null, null))
			.hasMessageContaining("ck_scans_status_timestamps");
		assertThatThrownBy(() -> insertScan(projectId, SHA, "COMPLETED", "PASS", LATER, NOW, null, null))
			.hasMessageContaining("ck_scans_timestamp_order");
	}

	@Test
	void idempotencyKeysAreUniquePerProjectAndRequireAFingerprint() {
		UUID projectId = insertProject();
		String fingerprint = "a".repeat(64);
		insertScan(projectId, SHA, "QUEUED", "PENDING", null, null, "key", fingerprint);

		assertThatThrownBy(() -> insertScan(projectId, SHA, "QUEUED", "PENDING", null, null, "key", fingerprint))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_scans_project_idempotency_key");
		assertThatCode(() -> insertScan(insertProject(), SHA, "QUEUED", "PENDING", null, null, "key", fingerprint))
			.doesNotThrowAnyException();
		assertThatThrownBy(() -> insertScan(projectId, SHA, "QUEUED", "PENDING", null, null, "other", null))
			.hasMessageContaining("ck_scans_idempotency_pair");
	}

	private UUID insertIdentity(String subject) {
		UUID id = UUID.randomUUID();
		this.jdbcTemplate.update(
				"INSERT INTO user_identities (id, issuer, subject, version, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)",
				id, TestJwts.ISSUER, subject, NOW, NOW);
		return id;
	}

	private void insertMembership(UUID organizationId, UUID identityId, String role, UUID grantedBy) {
		this.jdbcTemplate.update("""
				INSERT INTO organization_memberships (id, organization_id, user_identity_id, role, granted_by,
				    version, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, 0, ?, ?)
				""", UUID.randomUUID(), organizationId, identityId, role, grantedBy, NOW, NOW);
	}

	@Test
	void identitiesAreUniquePerIssuerAndSubject() {
		String subject = uniqueSubject("db");
		insertIdentity(subject);

		assertThatThrownBy(() -> insertIdentity(subject)).isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_user_identities_issuer_subject");
		assertThatThrownBy(() -> insertIdentity("   ")).hasMessageContaining("ck_user_identities_subject_format");
		assertThatThrownBy(() -> insertIdentity("line\nbreak")).hasMessageContaining("ck_user_identities_subject_format");
	}

	@Test
	void membershipsAreUniqueTypedAndNeverSelfGranted() {
		UUID organizationId = insertOrganization();
		UUID owner = insertIdentity(uniqueSubject("owner"));
		UUID user = insertIdentity(uniqueSubject("user"));
		insertMembership(organizationId, owner, "OWNER", null);
		insertMembership(organizationId, user, "MEMBER", owner);

		assertThatThrownBy(() -> insertMembership(organizationId, user, "ADMIN", owner))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_organization_memberships_organization_user");
		assertThatThrownBy(() -> insertMembership(insertOrganization(), user, "SUPERUSER", owner))
			.hasMessageContaining("ck_organization_memberships_role");
		assertThatThrownBy(() -> insertMembership(insertOrganization(), user, "OWNER", user))
			.hasMessageContaining("ck_organization_memberships_not_self_granted");
		assertThatThrownBy(() -> insertMembership(UUID.randomUUID(), user, "VIEWER", owner))
			.hasMessageContaining("fk_organization_memberships_organization");
		assertThatThrownBy(() -> insertMembership(organizationId, UUID.randomUUID(), "VIEWER", owner))
			.hasMessageContaining("fk_organization_memberships_user_identity");
		assertThatThrownBy(() -> this.jdbcTemplate.update("DELETE FROM user_identities WHERE id = ?", user))
			.hasMessageContaining("fk_organization_memberships_user_identity");
	}

	@Test
	void scanJobsAreUniquePerScannerAndBounded() {
		UUID scanId = insertQueuedScan(insertProject());
		insertJob(scanId, "SEMGREP", "QUEUED", 0, null, null);

		assertThatThrownBy(() -> insertJob(scanId, "SEMGREP", "QUEUED", 0, null, null))
			.isInstanceOf(DataIntegrityViolationException.class)
			.hasMessageContaining("uq_scan_jobs_scan_scanner");
		assertThatThrownBy(() -> insertJob(scanId, "NMAP", "QUEUED", 0, null, null))
			.hasMessageContaining("ck_scan_jobs_scanner_type");
		assertThatThrownBy(() -> insertJob(scanId, "TRIVY", "RUNNING", 4, NOW, null))
			.hasMessageContaining("ck_scan_jobs_attempt_count");
		assertThatThrownBy(() -> insertJob(scanId, "TRIVY", "RUNNING", 0, NOW, null))
			.hasMessageContaining("ck_scan_jobs_status_timestamps");
		assertThatThrownBy(() -> insertJob(UUID.randomUUID(), "TRIVY", "QUEUED", 0, null, null))
			.hasMessageContaining("fk_scan_jobs_scan");
	}

}

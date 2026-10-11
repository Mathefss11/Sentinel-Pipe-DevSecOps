package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import dev.sentinelpipe.api.contract.ContractSchemas;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;

/**
 * Policy versions and activation through the API (ADR-0013), against real PostgreSQL:
 * role permissions, tenant isolation, immutability and versioning under concurrency.
 */
class PolicyApiIntegrationTests extends AbstractDomainApiIntegrationTest {

	private UUID organizationId;

	private UUID projectId;

	@BeforeEach
	void organizationWithProject() throws Exception {
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "policy-repo");
	}

	private MvcResult createPolicy(UUID organizationId, String definition, String bearer) throws Exception {
		return this.mockMvc
			.perform(post("/api/v1/organizations/{id}/policies", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content(definition)
				.header(HttpHeaders.AUTHORIZATION, bearer))
			.andReturn();
	}

	private UUID createPolicy(UUID organizationId, String definition) throws Exception {
		MvcResult result = createPolicy(organizationId, definition, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
		return UUID.fromString(json(result).get("id").asString());
	}

	private MvcResult activate(UUID projectId, UUID versionId, String bearer) throws Exception {
		return this.mockMvc
			.perform(put("/api/v1/projects/{id}/policy", projectId).contentType(MediaType.APPLICATION_JSON)
				.content("{\"policyVersionId\": \"%s\"}".formatted(versionId))
				.header(HttpHeaders.AUTHORIZATION, bearer))
			.andReturn();
	}

	private MvcResult getAs(String path, String bearer, Object... variables) throws Exception {
		return this.mockMvc.perform(get(path, variables).header(HttpHeaders.AUTHORIZATION, bearer)).andReturn();
	}

	@Test
	void anAdminCreatesVersionsThatAreCanonicalNumberedAndContractValid() throws Exception {
		String admin = uniqueSubject("admin");
		grant(this.organizationId, admin, "ADMIN");

		MvcResult first = createPolicy(this.organizationId, PolicyFixtures.allScanners("baseline"), TestJwts.bearer(admin));
		MvcResult second = createPolicy(this.organizationId, PolicyFixtures.allScanners("baseline"), TestJwts.bearer(admin));

		assertThat(first.getResponse().getStatus()).isEqualTo(201);
		JsonNode created = json(first);
		ContractSchemas.assertValid("policy-version.schema.json", created);
		assertThat(first.getResponse().getHeader(HttpHeaders.LOCATION))
			.isEqualTo("/api/v1/policy-versions/" + created.get("id").asString());
		assertThat(created.get("version").asInt()).isEqualTo(1);
		assertThat(json(second).get("version").asInt()).isEqualTo(2);
		assertThat(json(second).get("policyId")).isEqualTo(created.get("policyId"));
		PolicyDocuments.ValidatedPolicy expected = PolicyDocuments.parse(PolicyFixtures.allScanners("baseline"));
		assertThat(created.get("definitionSha256").asString()).isEqualTo(expected.sha256());
		assertThat(this.jdbcTemplate.queryForObject("SELECT definition FROM policy.policy_versions WHERE id = ?",
				String.class, UUID.fromString(created.get("id").asString())))
			.isEqualTo(expected.canonical());
		// Any member can read it.
		String viewer = uniqueSubject("viewer");
		grant(this.organizationId, viewer, "VIEWER");
		MvcResult read = getAs("/api/v1/policy-versions/{id}", TestJwts.bearer(viewer), created.get("id").asString());
		assertThat(read.getResponse().getStatus()).isEqualTo(200);
		assertThat(json(read)).isEqualTo(created);
	}

	@Test
	void membersAndViewersCannotCreateAndOutsidersCannotSeePolicies() throws Exception {
		String member = uniqueSubject("member");
		String viewer = uniqueSubject("viewer");
		grant(this.organizationId, member, "MEMBER");
		grant(this.organizationId, viewer, "VIEWER");
		UUID versionId = createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("secrets"));
		String outsider = TestJwts.bearer(uniqueSubject("outsider"));

		assertThat(createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("m"), TestJwts.bearer(member))
			.getResponse()
			.getStatus()).isEqualTo(403);
		assertThat(createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("v"), TestJwts.bearer(viewer))
			.getResponse()
			.getStatus()).isEqualTo(403);
		assertThat(createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("o"), outsider).getResponse()
			.getStatus()).isEqualTo(404);
		assertThat(getAs("/api/v1/policy-versions/{id}", outsider, versionId).getResponse().getStatus())
			.isEqualTo(404);
		assertThat(getAs("/api/v1/policy-versions/{id}", outsider, UUID.randomUUID()).getResponse().getStatus())
			.as("an unknown id looks exactly like another tenant's")
			.isEqualTo(404);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.policies WHERE organization_id = ? AND name IN ('m', 'v', 'o')",
				Integer.class, this.organizationId))
			.isZero();
	}

	@Test
	void invalidDefinitionsAreRejectedWithoutEchoingTheirContent() throws Exception {
		String marker = "SENTINEL_POLICY_PROBE_" + "Z".repeat(16);
		String invalid = PolicyFixtures.gitleaksOnly("secrets")
			.replace("\"schema_version\": 1,", "\"schema_version\": 1, \"" + marker + "\": \"" + marker + "\",");
		String duplicate = PolicyFixtures.gitleaksOnly("secrets")
			.replace("\"max_blocking_findings\": 0", "\"max_blocking_findings\": 0, \"max_blocking_findings\": 5");

		MvcResult unknownField = createPolicy(this.organizationId, invalid, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));
		MvcResult duplicated = createPolicy(this.organizationId, duplicate, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));

		assertThat(unknownField.getResponse().getStatus()).isEqualTo(400);
		assertThat(duplicated.getResponse().getStatus()).isEqualTo(400);
		ContractSchemas.assertValid("problem-details.schema.json", json(unknownField));
		assertThat(json(unknownField).get("type").asString()).isEqualTo("urn:sentinelpipe:problem:validation-error");
		assertThat(unknownField.getResponse().getContentAsString()).doesNotContain(marker);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.policies WHERE organization_id = ?", Integer.class, this.organizationId))
			.isZero();
	}

	@Test
	void oversizedOrNonUtf8BodiesAreRefusedWithoutBeingStored() throws Exception {
		String oversized = PolicyFixtures.gitleaksOnly("secrets") + " ".repeat(4 * PolicyDocuments.MAX_BYTES);
		byte[] latin1 = PolicyFixtures.gitleaksOnly("secréts").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

		MvcResult tooLarge = createPolicy(this.organizationId, oversized, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));
		MvcResult notUtf8 = this.mockMvc
			.perform(post("/api/v1/organizations/{id}/policies", this.organizationId)
				.contentType(MediaType.APPLICATION_JSON)
				.content(latin1))
			.andReturn();

		assertThat(tooLarge.getResponse().getStatus()).isEqualTo(400);
		assertThat(json(tooLarge).at("/errors/0/message").asString()).contains("16384");
		assertThat(notUtf8.getResponse().getStatus()).isEqualTo(400);
		assertThat(json(notUtf8).at("/errors/0/message").asString()).isEqualTo("must be UTF-8");
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.policies WHERE organization_id = ?", Integer.class, this.organizationId))
			.isZero();
	}

	@Test
	void onlyAnOwnerActivatesAndTheActivationIsReadableAndIdempotent() throws Exception {
		UUID versionId = createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("secrets"));
		String admin = uniqueSubject("admin");
		String viewer = uniqueSubject("viewer");
		grant(this.organizationId, admin, "ADMIN");
		grant(this.organizationId, viewer, "VIEWER");

		assertThat(activate(this.projectId, versionId, TestJwts.bearer(admin)).getResponse().getStatus())
			.as("drafting and activation are separate duties")
			.isEqualTo(403);
		assertThat(getAs("/api/v1/projects/{id}/policy", TestJwts.bearer(viewer), this.projectId).getResponse()
			.getStatus()).isEqualTo(404);

		MvcResult activated = activate(this.projectId, versionId, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));
		MvcResult again = activate(this.projectId, versionId, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));

		assertThat(activated.getResponse().getStatus()).isEqualTo(200);
		ContractSchemas.assertValid("project-policy.schema.json", json(activated));
		assertThat(json(activated).get("policyVersionId").asString()).isEqualTo(versionId.toString());
		assertThat(json(again)).isEqualTo(json(activated));
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.project_assignments WHERE project_id = ?", Integer.class, this.projectId))
			.as("re-activating the active version records nothing")
			.isEqualTo(1);
		MvcResult read = getAs("/api/v1/projects/{id}/policy", TestJwts.bearer(viewer), this.projectId);
		assertThat(read.getResponse().getStatus()).isEqualTo(200);
		assertThat(json(read)).isEqualTo(json(activated));
	}

	@Test
	void aPolicyVersionOfAnotherTenantCanNeverBeActivated() throws Exception {
		UUID otherOrganization = createOrganization();
		UUID foreignVersion = createPolicy(otherOrganization, PolicyFixtures.gitleaksOnly("foreign"));

		MvcResult attempt = activate(this.projectId, foreignVersion, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));

		// The platform admin owns both organizations, and still cannot cross them.
		assertThat(attempt.getResponse().getStatus()).isEqualTo(404);
		assertThat(json(attempt).get("detail").asString()).isEqualTo("PolicyVersion was not found.");
		assertThat(activate(this.projectId, UUID.randomUUID(), TestJwts.bearer(TestJwts.PLATFORM_ADMIN)).getResponse()
			.getStatus()).isEqualTo(404);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM policy.project_assignments WHERE project_id = ?", Integer.class, this.projectId))
			.isZero();
		// The database refuses it independently of the API: the composite keys require one tenant.
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.project_assignments (project_id, organization_id, policy_version_id, assigned_by)
				VALUES (?, ?, ?, 'test')""", this.projectId, this.organizationId, foreignVersion))
			.hasMessageContaining("fk_project_assignments_version");
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.project_assignments (project_id, organization_id, policy_version_id, assigned_by)
				VALUES (?, ?, ?, 'test')""", this.projectId, otherOrganization, foreignVersion))
			.hasMessageContaining("fk_project_assignments_project");
	}

	@Test
	void policyRecordsAreImmutableEvenForTheDatabaseOwnerThroughOrdinaryStatements() throws Exception {
		UUID versionId = createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("secrets"));
		activate(this.projectId, versionId, TestJwts.bearer(TestJwts.PLATFORM_ADMIN));

		for (String sql : List.of(
				"UPDATE policy.policy_versions SET created_by = 'tampered' WHERE id = '" + versionId + "'",
				"DELETE FROM policy.policy_versions WHERE id = '" + versionId + "'",
				"UPDATE policy.project_assignments SET assigned_by = 'tampered' WHERE project_id = '" + this.projectId
						+ "'",
				"DELETE FROM policy.project_assignments WHERE project_id = '" + this.projectId + "'",
				"TRUNCATE policy.project_assignments CASCADE")) {
			assertThatThrownBy(() -> this.jdbcTemplate.execute(sql)).as(sql)
				.hasMessageContaining("policy records are immutable");
		}
		// The digest is bound to the stored text by a CHECK.
		assertThatThrownBy(() -> this.jdbcTemplate.update("""
				INSERT INTO policy.policy_versions (policy_id, organization_id, version, schema_version, definition,
				    definition_sha256, created_by)
				SELECT policy_id, organization_id, 99, 1, definition || ' ', definition_sha256, 'tampered'
				FROM policy.policy_versions WHERE id = ?""", versionId))
			.hasMessageContaining("ck_policy_versions_integrity");
	}

	@Test
	void concurrentVersionCreationNumbersVersionsWithoutGapsOrDuplicates() throws Exception {
		int writers = 8;
		ExecutorService pool = Executors.newFixedThreadPool(writers);
		try {
			List<Callable<Integer>> tasks = new ArrayList<>();
			for (int i = 0; i < writers; i++) {
				tasks.add(() -> createPolicy(this.organizationId, PolicyFixtures.gitleaksOnly("raced"),
						TestJwts.bearer(TestJwts.PLATFORM_ADMIN))
					.getResponse()
					.getStatus());
			}
			for (Future<Integer> status : pool.invokeAll(tasks)) {
				assertThat(status.get()).isEqualTo(201);
			}
		}
		finally {
			pool.shutdownNow();
		}

		assertThat(this.jdbcTemplate.queryForList("""
				SELECT v.version FROM policy.policy_versions v JOIN policy.policies p ON p.id = v.policy_id
				WHERE p.organization_id = ? AND p.name = 'raced' ORDER BY v.version""", Integer.class,
				this.organizationId))
			.containsExactly(1, 2, 3, 4, 5, 6, 7, 8);
	}

}

package dev.sentinelpipe.api.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Cross-tenant access (IDOR): an OWNER of organization A, holding valid UUIDs of
 * organization B's resources, must not read, enumerate or modify anything in B. Responses
 * must be indistinguishable from requests for resources that do not exist.
 */
class TenantIsolationIntegrationTests extends AbstractDomainApiIntegrationTest {

	private String ownerOfA;

	private UUID orgB;

	private UUID projectB;

	private UUID scanB;

	private UUID membershipB;

	@BeforeEach
	void twoTenants() throws Exception {
		this.ownerOfA = uniqueSubject("owner-a");
		UUID orgA = createOrganization();
		grant(orgA, this.ownerOfA, "OWNER");

		this.orgB = createOrganization();
		this.projectB = createProject(this.orgB, "secret-repo");
		this.scanB = UUID.fromString(json(requestScan(this.projectB, randomSha(), "b-key")).get("id").asString());
		this.membershipB = grant(this.orgB, uniqueSubject("b-member"), "MEMBER");
	}

	private MockHttpServletRequestBuilder asOwnerOfA(MockHttpServletRequestBuilder request) {
		return request.header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(this.ownerOfA));
	}

	@Test
	void readsOfAnotherTenantsResourcesLookLikeMissingResources() throws Exception {
		String[] paths = { "/api/v1/organizations/" + this.orgB, "/api/v1/organizations/" + this.orgB + "/projects",
				"/api/v1/organizations/" + this.orgB + "/members",
				"/api/v1/organizations/" + this.orgB + "/members/" + this.membershipB,
				"/api/v1/projects/" + this.projectB, "/api/v1/projects/" + this.projectB + "/scans",
				"/api/v1/scans/" + this.scanB };
		for (String path : paths) {
			String foreign = this.mockMvc.perform(asOwnerOfA(get(path)))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:not-found"))
				.andReturn()
				.getResponse()
				.getContentAsString();
			assertThat(foreign).doesNotContain("secret-repo");
		}
	}

	@Test
	void notFoundResponsesForForeignAndNonexistentResourcesAreIdentical() throws Exception {
		UUID missing = UUID.randomUUID();
		String foreign = json(this.mockMvc.perform(asOwnerOfA(get("/api/v1/projects/{id}", this.projectB))).andReturn())
			.get("detail")
			.asString();
		String nonexistent = json(this.mockMvc.perform(asOwnerOfA(get("/api/v1/projects/{id}", missing))).andReturn())
			.get("detail")
			.asString();

		assertThat(foreign).isEqualTo(nonexistent);
	}

	@Test
	void writesToAnotherTenantAreRejectedAndHaveNoEffect() throws Exception {
		this.mockMvc
			.perform(asOwnerOfA(post("/api/v1/organizations/{id}/projects", this.orgB))
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "x", "repositoryProvider": "GITHUB", "repositoryOwner": "evil",
						 "repositoryName": "implant", "defaultBranch": "main"}
						"""))
			.andExpect(status().isNotFound());
		this.mockMvc
			.perform(asOwnerOfA(post("/api/v1/projects/{id}/scans", this.projectB)).header("Idempotency-Key", "b-key")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"commitSha": "%s", "branch": "main", "triggerType": "PUSH"}
						""".formatted(randomSha())))
			.andExpect(status().isNotFound());
		this.mockMvc
			.perform(asOwnerOfA(post("/api/v1/organizations/{id}/members", this.orgB))
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"subject\": \"%s\", \"role\": \"OWNER\"}".formatted(this.ownerOfA)))
			.andExpect(status().isNotFound());
		this.mockMvc
			.perform(asOwnerOfA(put("/api/v1/organizations/{o}/members/{m}", this.orgB, this.membershipB))
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"role\": \"VIEWER\"}"))
			.andExpect(status().isNotFound());
		this.mockMvc
			.perform(asOwnerOfA(delete("/api/v1/organizations/{o}/members/{m}", this.orgB, this.membershipB)))
			.andExpect(status().isNotFound());

		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM projects WHERE organization_id = ?",
				Integer.class, this.orgB))
			.isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM scans WHERE project_id = ?", Integer.class,
				this.projectB))
			.isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT role FROM organization_memberships WHERE id = ?", String.class, this.membershipB))
			.isEqualTo("MEMBER");
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM organization_memberships WHERE organization_id = ?", Integer.class, this.orgB))
			.isEqualTo(2);
	}

	@Test
	void membershipIdsOfAnotherOrganizationCannotBeAddressedThroughOwnOrganization() throws Exception {
		UUID orgA = createOrganization();
		// The platform admin owns A and B; it addresses B's membership through A's path.
		this.mockMvc.perform(get("/api/v1/organizations/{o}/members/{m}", orgA, this.membershipB))
			.andExpect(status().isNotFound());
		this.mockMvc
			.perform(put("/api/v1/organizations/{o}/members/{m}", orgA, this.membershipB)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"role\": \"VIEWER\"}"))
			.andExpect(status().isNotFound());
		this.mockMvc.perform(delete("/api/v1/organizations/{o}/members/{m}", orgA, this.membershipB))
			.andExpect(status().isNotFound());

		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT role FROM organization_memberships WHERE id = ?", String.class, this.membershipB))
			.isEqualTo("MEMBER");
	}

	@Test
	void listingsNeverIncludeOtherTenantsData() throws Exception {
		this.mockMvc
			.perform(get("/api/v1/me").header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(this.ownerOfA)))
			.andExpect(jsonPath("$.memberships.length()").value(1))
			.andExpect(jsonPath("$.memberships[0].role").value("OWNER"));
	}

}

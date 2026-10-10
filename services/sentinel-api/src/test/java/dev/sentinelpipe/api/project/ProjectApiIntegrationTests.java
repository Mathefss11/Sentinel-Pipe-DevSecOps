package dev.sentinelpipe.api.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

class ProjectApiIntegrationTests extends AbstractDomainApiIntegrationTest {

	private ResultActions register(UUID organizationId, String owner, String name) throws Exception {
		return this.mockMvc.perform(post("/api/v1/organizations/{id}/projects", organizationId)
			.contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"name": "Payments", "repositoryProvider": "GITHUB", "repositoryOwner": "%s",
					 "repositoryName": "%s", "defaultBranch": "main"}
					""".formatted(owner, name)));
	}

	@Test
	void registersProjectWithNormalizedRepositoryIdentity() throws Exception {
		UUID organizationId = createOrganization();

		MvcResult result = register(organizationId, "Acme-Corp", "Payments-Service").andExpect(status().isCreated())
			.andExpect(jsonPath("$.organizationId").value(organizationId.toString()))
			.andExpect(jsonPath("$.repositoryProvider").value("GITHUB"))
			.andExpect(jsonPath("$.repositoryOwner").value("acme-corp"))
			.andExpect(jsonPath("$.repositoryName").value("payments-service"))
			.andExpect(jsonPath("$.defaultBranch").value("main"))
			.andExpect(jsonPath("$.enabled").value(true))
			.andReturn();
		String id = json(result).get("id").asString();

		assertThat(result.getResponse().getHeader("Location")).isEqualTo("/api/v1/projects/" + id);
		this.mockMvc.perform(get("/api/v1/projects/{id}", id))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.repositoryOwner").value("acme-corp"));
	}

	@Test
	void rejectsDuplicateRepositoryWithinOrganizationCaseInsensitively() throws Exception {
		UUID organizationId = createOrganization();
		register(organizationId, "acme", "payments").andExpect(status().isCreated());

		register(organizationId, "ACME", "Payments").andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("repository-already-registered"));
	}

	@Test
	void sameRepositoryMayBeRegisteredByDifferentOrganizations() throws Exception {
		register(createOrganization(), "acme", "shared").andExpect(status().isCreated());
		register(createOrganization(), "acme", "shared").andExpect(status().isCreated());
	}

	@ParameterizedTest
	@CsvSource(delimiter = '|', textBlock = """
			-acme                      | repo        | repositoryOwner
			acme_corp                  | repo        | repositoryOwner
			https://github.com/acme    | repo        | repositoryOwner
			acme                       | ..          | repositoryName
			acme                       | repo.git    | repositoryName
			acme                       | ../../etc   | repositoryName
			acme                       | a/b         | repositoryName
			acme                       | https:x     | repositoryName
			""")
	void rejectsInvalidRepositoryIdentifiers(String owner, String name, String field) throws Exception {
		register(createOrganization(), owner, name).andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:validation-error"))
			.andExpect(jsonPath("$.errors[0].field").value(field));
	}

	@Test
	void rejectsUnsupportedProvidersAndRepositoryUrls() throws Exception {
		UUID organizationId = createOrganization();
		this.mockMvc
			.perform(post("/api/v1/organizations/{id}/projects", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "x", "repositoryProvider": "GITLAB", "repositoryOwner": "acme",
						 "repositoryName": "repo", "defaultBranch": "main"}
						"""))
			.andExpect(status().isBadRequest());
		this.mockMvc
			.perform(post("/api/v1/organizations/{id}/projects", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "x", "repositoryProvider": "GITHUB", "repositoryUrl": "https://evil.example/repo.git",
						 "repositoryOwner": "acme", "repositoryName": "repo", "defaultBranch": "main"}
						"""))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:malformed-request"));
	}

	@Test
	void rejectsInvalidDefaultBranch() throws Exception {
		this.mockMvc
			.perform(post("/api/v1/organizations/{id}/projects", createOrganization())
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "x", "repositoryProvider": "GITHUB", "repositoryOwner": "acme",
						 "repositoryName": "repo", "defaultBranch": "main;rm -rf /"}
						"""))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[0].field").value("defaultBranch"));
	}

	@Test
	void registrationInUnknownOrganizationIsNotFound() throws Exception {
		register(UUID.randomUUID(), "acme", "repo").andExpect(status().isNotFound());
	}

	@Test
	void listsProjectsWithPaginationInCreationOrder() throws Exception {
		UUID organizationId = createOrganization();
		for (int i = 0; i < 5; i++) {
			register(organizationId, "acme", "repo-" + i).andExpect(status().isCreated());
		}

		this.mockMvc.perform(get("/api/v1/organizations/{id}/projects", organizationId).param("size", "2"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.items.length()").value(2))
			.andExpect(jsonPath("$.items[0].repositoryName").value("repo-0"))
			.andExpect(jsonPath("$.items[1].repositoryName").value("repo-1"))
			.andExpect(jsonPath("$.page.number").value(0))
			.andExpect(jsonPath("$.page.size").value(2))
			.andExpect(jsonPath("$.page.totalElements").value(5))
			.andExpect(jsonPath("$.page.totalPages").value(3));
		this.mockMvc
			.perform(get("/api/v1/organizations/{id}/projects", organizationId).param("page", "2").param("size", "2"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.items.length()").value(1))
			.andExpect(jsonPath("$.items[0].repositoryName").value("repo-4"));
		this.mockMvc.perform(get("/api/v1/organizations/{id}/projects", organizationId))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.page.size").value(20))
			.andExpect(jsonPath("$.items.length()").value(5));
	}

	@Test
	void listingOnlyReturnsProjectsOfTheRequestedOrganization() throws Exception {
		UUID first = createOrganization();
		UUID second = createOrganization();
		register(first, "acme", "mine").andExpect(status().isCreated());
		register(second, "acme", "theirs").andExpect(status().isCreated());

		this.mockMvc.perform(get("/api/v1/organizations/{id}/projects", first))
			.andExpect(jsonPath("$.page.totalElements").value(1))
			.andExpect(jsonPath("$.items[0].repositoryName").value("mine"));
	}

	@ParameterizedTest
	@CsvSource({ "page,-1", "page,10001", "size,0", "size,101", "size,abc" })
	void rejectsInvalidPaginationParameters(String parameter, String value) throws Exception {
		this.mockMvc.perform(get("/api/v1/organizations/{id}/projects", createOrganization()).param(parameter, value))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:validation-error"))
			.andExpect(jsonPath("$.errors[0].field").value(parameter));
	}

	@Test
	void unknownProjectAndOrganizationAreNotFound() throws Exception {
		this.mockMvc.perform(get("/api/v1/projects/{id}", UUID.randomUUID())).andExpect(status().isNotFound());
		this.mockMvc.perform(get("/api/v1/organizations/{id}/projects", UUID.randomUUID()))
			.andExpect(status().isNotFound());
	}

}

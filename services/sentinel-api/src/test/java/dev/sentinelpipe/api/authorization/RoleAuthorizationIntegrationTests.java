package dev.sentinelpipe.api.authorization;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** The authorization matrix enforced end to end, per role. */
class RoleAuthorizationIntegrationTests extends AbstractDomainApiIntegrationTest {

	private UUID organizationId;

	private UUID projectId;

	private UUID scanId;

	@BeforeEach
	void organizationWithData() throws Exception {
		this.organizationId = createOrganization();
		this.projectId = createProject(this.organizationId, "app");
		this.scanId = UUID.fromString(json(requestScan(this.projectId, randomSha(), null)).get("id").asString());
	}

	private String memberWithRole(String role) throws Exception {
		String subject = uniqueSubject(role.toLowerCase());
		grant(this.organizationId, subject, role);
		return subject;
	}

	private void perform(String subject, MockHttpServletRequestBuilder request, ResultMatcher expected)
			throws Exception {
		this.mockMvc.perform(request.header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(subject)))
			.andExpect(expected);
	}

	private static ResultMatcher allowedOrDenied(boolean allowed, ResultMatcher success) {
		return allowed ? success : status().isForbidden();
	}

	@ParameterizedTest(name = "{0}")
	@CsvSource({
			// role,  view, requestScan, registerProject, viewMembers
			"OWNER,   true, true,        true,            true",
			"ADMIN,   true, true,        true,            true",
			"MEMBER,  true, true,        false,           false",
			"VIEWER,  true, false,       false,           false" })
	void rolePermissionsMatchTheMatrix(String role, boolean view, boolean requestScan, boolean registerProject,
			boolean viewMembers) throws Exception {
		String subject = memberWithRole(role);

		perform(subject, get("/api/v1/organizations/{id}", this.organizationId), allowedOrDenied(view, status().isOk()));
		perform(subject, get("/api/v1/organizations/{id}/projects", this.organizationId),
				allowedOrDenied(view, status().isOk()));
		perform(subject, get("/api/v1/projects/{id}", this.projectId), allowedOrDenied(view, status().isOk()));
		perform(subject, get("/api/v1/projects/{id}/scans", this.projectId), allowedOrDenied(view, status().isOk()));
		perform(subject, get("/api/v1/scans/{id}", this.scanId), allowedOrDenied(view, status().isOk()));

		perform(subject,
				post("/api/v1/projects/{id}/scans", this.projectId).contentType(MediaType.APPLICATION_JSON)
					.content("""
							{"commitSha": "%s", "branch": "main", "triggerType": "MANUAL"}
							""".formatted(randomSha())),
				allowedOrDenied(requestScan, status().isAccepted()));
		perform(subject,
				post("/api/v1/organizations/{id}/projects", this.organizationId).contentType(MediaType.APPLICATION_JSON)
					.content("""
							{"name": "n", "repositoryProvider": "GITHUB", "repositoryOwner": "acme",
							 "repositoryName": "%s", "defaultBranch": "main"}
							""".formatted("r-" + UUID.randomUUID().toString().substring(0, 8))),
				allowedOrDenied(registerProject, status().isCreated()));
		perform(subject, get("/api/v1/organizations/{id}/members", this.organizationId),
				allowedOrDenied(viewMembers, status().isOk()));
	}

	@ParameterizedTest
	@CsvSource({ "OWNER", "ADMIN", "MEMBER", "VIEWER" })
	void onlyPlatformAdministratorsCanCreateOrganizations(String role) throws Exception {
		String subject = memberWithRole(role);

		perform(subject,
				post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
					.content("{\"name\": \"x\", \"slug\": \"%s\"}".formatted(uniqueSlug("deny"))),
				status().isForbidden());
		perform(subject, get("/api/v1/me"), jsonPath("$.platformAdmin").value(false));
	}

	@ParameterizedTest
	@CsvSource({ "MEMBER", "VIEWER" })
	void insufficientRoleIsReportedAsForbiddenWithACode(String role) throws Exception {
		String subject = memberWithRole(role);

		perform(subject, get("/api/v1/organizations/{id}/members", this.organizationId),
				jsonPath("$.code").value("insufficient-role"));
	}

}

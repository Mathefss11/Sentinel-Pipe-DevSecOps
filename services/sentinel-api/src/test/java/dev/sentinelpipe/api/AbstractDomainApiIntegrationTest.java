package dev.sentinelpipe.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Integration tests with the development domain API enabled, as in the {@code local}
 * profile, against real PostgreSQL and RabbitMQ containers. All subclasses share one
 * application context. Tests isolate their data by creating uniquely named
 * organizations instead of cleaning the database.
 */
@SpringBootTest(properties = { "sentinel.domain-api.enabled=true", "server.address=127.0.0.1" })
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
public abstract class AbstractDomainApiIntegrationTest {

	@Autowired
	protected MockMvc mockMvc;

	@Autowired
	protected JsonMapper jsonMapper;

	@Autowired
	protected JdbcTemplate jdbcTemplate;

	protected static String uniqueSlug(String prefix) {
		return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
	}

	protected static String randomSha() {
		return (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "").substring(0, 40);
	}

	protected JsonNode json(MvcResult result) throws Exception {
		return this.jsonMapper.readTree(result.getResponse().getContentAsString());
	}

	protected MvcResult postJson(String path, String body) throws Exception {
		return this.mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
	}

	protected UUID createOrganization() throws Exception {
		String slug = uniqueSlug("org");
		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "Org %s", "slug": "%s"}
						""".formatted(slug, slug)))
			.andExpect(status().isCreated())
			.andReturn();
		return UUID.fromString(json(result).get("id").asString());
	}

	protected UUID createProject(UUID organizationId, String repositoryName) throws Exception {
		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations/{id}/projects", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "Project %1$s", "repositoryProvider": "GITHUB", "repositoryOwner": "acme",
						 "repositoryName": "%1$s", "defaultBranch": "main"}
						""".formatted(repositoryName)))
			.andExpect(status().isCreated())
			.andReturn();
		return UUID.fromString(json(result).get("id").asString());
	}

	protected UUID createProject() throws Exception {
		return createProject(createOrganization(), "repo");
	}

	protected MvcResult requestScan(UUID projectId, String commitSha, String idempotencyKey) throws Exception {
		var request = post("/api/v1/projects/{id}/scans", projectId).contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"commitSha": "%s", "branch": "main", "triggerType": "PUSH"}
					""".formatted(commitSha));
		if (idempotencyKey != null) {
			request.header("Idempotency-Key", idempotencyKey);
		}
		return this.mockMvc.perform(request).andReturn();
	}

}

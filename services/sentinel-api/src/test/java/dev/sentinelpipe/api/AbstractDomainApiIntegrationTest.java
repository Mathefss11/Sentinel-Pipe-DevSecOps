package dev.sentinelpipe.api;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Integration tests with the domain API enabled, as in the {@code local} profile, against
 * real PostgreSQL and RabbitMQ containers and the production JWT decoder configured with a
 * test-only public key (see {@link TestJwts}). All subclasses share one application
 * context. Tests isolate their data by creating uniquely named organizations.
 *
 * <p>
 * {@link #mockMvc} authenticates every request as {@link TestJwts#PLATFORM_ADMIN}, who
 * creates the organizations used by the helpers and is therefore their OWNER. An explicit
 * {@code Authorization} header on a request replaces that default. {@link #anonymousMvc}
 * sends no token.
 */
@SpringBootTest(properties = { "sentinel.domain-api.enabled=true", "server.address=127.0.0.1",
		"sentinel.security.jwt.issuer=" + TestJwts.ISSUER, "sentinel.security.jwt.audience=" + TestJwts.AUDIENCE,
		"sentinel.security.platform-admin-subjects=" + TestJwts.PLATFORM_ADMIN })
@Import(TestcontainersConfiguration.class)
public abstract class AbstractDomainApiIntegrationTest {

	@DynamicPropertySource
	static void jwtPublicKey(DynamicPropertyRegistry registry) {
		registry.add("sentinel.security.jwt.public-key-location", TestJwts::publicKeyLocation);
	}

	@Autowired
	private WebApplicationContext context;

	@Autowired
	protected JsonMapper jsonMapper;

	@Autowired
	protected JdbcTemplate jdbcTemplate;

	/** Authenticated as {@link TestJwts#PLATFORM_ADMIN} unless a request sets its own token. */
	protected MockMvc mockMvc;

	/** Sends no credentials. */
	protected MockMvc anonymousMvc;

	@BeforeEach
	void setUpMockMvc() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context)
			.apply(springSecurity())
			.defaultRequest(get("/").header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(TestJwts.PLATFORM_ADMIN)))
			.build();
		this.anonymousMvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
	}

	protected static String uniqueSlug(String prefix) {
		return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
	}

	protected static String uniqueSubject(String prefix) {
		return prefix + "-" + UUID.randomUUID();
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

	/** Grants {@code role} to {@code subject}, acting as the organization's OWNER. */
	protected UUID grant(UUID organizationId, String subject, String role) throws Exception {
		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations/{id}/members", organizationId).contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"subject": "%s", "role": "%s"}
						""".formatted(subject, role)))
			.andExpect(status().isCreated())
			.andReturn();
		return UUID.fromString(json(result).get("id").asString());
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

package dev.sentinelpipe.api.contract;

import static dev.sentinelpipe.api.contract.ContractSchemas.assertValid;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.scan.ScanLifecycleService;
import dev.sentinelpipe.api.scan.SecurityDecision;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScannerType;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Validates real API responses and the schemas themselves against
 * {@code packages/contracts/schemas/v1}.
 */
class ContractIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private ScanLifecycleService lifecycle;

	private JsonNode getJson(String path, Object... variables) throws Exception {
		return json(this.mockMvc.perform(get(path, variables)).andReturn());
	}

	@Test
	void everySchemaIsAValidJsonSchema202012Document() throws Exception {
		SchemaRegistry metaRegistry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12);
		var metaSchema = metaRegistry.getSchema(SchemaLocation.of("https://json-schema.org/draft/2020-12/schema"));
		List<String> files = ContractSchemas.schemaFileNames();

		assertThat(files).contains("organization.schema.json", "project.schema.json", "scan-request.schema.json",
				"scan.schema.json", "scan-job.schema.json", "problem-details.schema.json");
		for (String file : files) {
			JsonNode schema = this.jsonMapper.readTree(Files.readString(ContractSchemas.SCHEMAS_DIR.resolve(file)));
			assertThat(metaSchema.validate(schema)).as(file).isEmpty();
			assertThat(schema.get("$schema").asString()).as(file)
				.isEqualTo("https://json-schema.org/draft/2020-12/schema");
			assertThat(schema.get("$id").asString()).as(file).isEqualTo(ContractSchemas.SCHEMA_ID_PREFIX + file);
		}
	}

	@Test
	void everySchemaReferenceResolvesToAnExistingDefinition() throws Exception {
		List<String> unresolved = new ArrayList<>();
		for (String file : ContractSchemas.schemaFileNames()) {
			JsonNode schema = this.jsonMapper.readTree(Files.readString(ContractSchemas.SCHEMAS_DIR.resolve(file)));
			for (String ref : collectRefs(schema, new ArrayList<>())) {
				String targetFile = ref.contains("#") ? ref.substring(0, ref.indexOf('#')) : ref;
				String pointer = ref.contains("#") ? ref.substring(ref.indexOf('#') + 1) : "";
				JsonNode target = targetFile.isEmpty() ? schema
						: Files.isRegularFile(ContractSchemas.SCHEMAS_DIR.resolve(targetFile))
								? this.jsonMapper
									.readTree(Files.readString(ContractSchemas.SCHEMAS_DIR.resolve(targetFile)))
								: null;
				if (target == null || target.at(pointer).isMissingNode()) {
					unresolved.add(file + " -> " + ref);
				}
			}
		}
		assertThat(unresolved).isEmpty();
	}

	@Test
	void organizationAndProjectResponsesMatchTheirSchemas() throws Exception {
		UUID organizationId = createOrganization();
		UUID projectId = createProject(organizationId, "contract-repo");

		assertValid("organization.schema.json", getJson("/api/v1/organizations/{id}", organizationId));
		assertValid("project.schema.json", getJson("/api/v1/projects/{id}", projectId));
		assertValid("project-page.schema.json", getJson("/api/v1/organizations/{id}/projects", organizationId));
	}

	@Test
	void scanResponsesMatchTheirSchemasInEveryLifecycleState() throws Exception {
		UUID projectId = createProject();
		MvcResult created = requestScan(projectId, randomSha(), "contract-key");
		JsonNode queued = json(created);
		assertValid("scan.schema.json", queued);

		UUID scanId = UUID.fromString(queued.get("id").asString());
		ScanJob semgrep = this.lifecycle.planJob(scanId, ScannerType.SEMGREP);
		this.lifecycle.planJob(scanId, ScannerType.GITLEAKS);
		this.lifecycle.startScan(scanId);
		this.lifecycle.startJob(semgrep.getId());
		JsonNode running = getJson("/api/v1/scans/{id}", scanId);
		assertThat(running.get("jobs")).hasSize(2);
		assertValid("scan.schema.json", running);

		this.lifecycle.cancelScan(scanId);
		JsonNode cancelled = getJson("/api/v1/scans/{id}", scanId);
		assertThat(cancelled.get("securityDecision").asString()).isEqualTo(SecurityDecision.INCOMPLETE.name());
		assertValid("scan.schema.json", cancelled);
		for (JsonNode job : cancelled.get("jobs")) {
			assertValid("scan-job.schema.json", job);
		}
		assertValid("scan-page.schema.json", getJson("/api/v1/projects/{id}/scans", projectId));
	}

	@Test
	void requestBodiesAcceptedByTheApiMatchTheRequestSchemas() throws Exception {
		assertValid("create-organization-request.schema.json",
				this.jsonMapper.readTree("{\"name\": \"Acme\", \"slug\": \"acme\"}"));
		assertValid("create-project-request.schema.json", this.jsonMapper.readTree("""
				{"name": "P", "repositoryProvider": "GITHUB", "repositoryOwner": "Acme-Corp",
				 "repositoryName": ".github", "defaultBranch": "release/1.0"}
				"""));
		assertValid("scan-request.schema.json", this.jsonMapper.readTree("""
				{"commitSha": "%s", "branch": "main", "triggerType": "MANUAL"}
				""".formatted(randomSha().toUpperCase())));
	}

	@Test
	void schemasRejectWhatTheApiRejects() throws Exception {
		Map<String, String> invalidScanRequests = Map.of("abbreviated sha", """
				{"commitSha": "4f2c8e1", "branch": "main", "triggerType": "PUSH"}""", "full ref", """
				{"commitSha": "%s", "branch": "refs/heads/main", "triggerType": "PUSH"}""".formatted(randomSha()),
				"client-supplied status", """
						{"commitSha": "%s", "branch": "main", "triggerType": "PUSH", "executionStatus": "COMPLETED"}"""
					.formatted(randomSha()),
				"unknown trigger", """
						{"commitSha": "%s", "branch": "main", "triggerType": "WEBHOOK"}""".formatted(randomSha()));
		for (Map.Entry<String, String> invalid : invalidScanRequests.entrySet()) {
			assertThat(ContractSchemas.validate("scan-request.schema.json", this.jsonMapper.readTree(invalid.getValue())))
				.as(invalid.getKey())
				.isNotEmpty();
		}

		ObjectNode scan = (ObjectNode) json(requestScan(createProject(), randomSha(), null));
		scan.put("securityDecision", "PASS");
		assertThat(ContractSchemas.validate("scan.schema.json", scan)).as("QUEUED scan with PASS").isNotEmpty();
	}

	@Test
	void problemResponsesMatchTheProblemDetailsSchema() throws Exception {
		UUID projectId = createProject();
		List<MvcResult> problems = new ArrayList<>();
		problems.add(postJson("/api/v1/organizations", "{\"name\": \"\", \"slug\": \"BAD\"}"));
		problems.add(postJson("/api/v1/organizations", "{not json"));
		problems.add(this.mockMvc.perform(get("/api/v1/scans/{id}", UUID.randomUUID())).andReturn());
		problems.add(this.mockMvc.perform(get("/api/v1/scans/{id}", "not-a-uuid")).andReturn());
		problems.add(this.mockMvc.perform(get("/api/v1/projects/{id}/scans", projectId).param("size", "0")).andReturn());
		String slug = uniqueSlug("contract");
		postJson("/api/v1/organizations", "{\"name\": \"A\", \"slug\": \"%s\"}".formatted(slug));
		problems.add(postJson("/api/v1/organizations", "{\"name\": \"A\", \"slug\": \"%s\"}".formatted(slug)));
		requestScan(projectId, randomSha(), "problem-key");
		problems.add(requestScan(projectId, randomSha(), "problem-key"));
		problems.add(this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.TEXT_PLAIN).content("x"))
			.andReturn());

		assertThat(problems).extracting((result) -> result.getResponse().getStatus())
			.containsExactly(400, 400, 404, 400, 400, 409, 422, 415);
		for (MvcResult result : problems) {
			assertThat(result.getResponse().getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
			JsonNode body = json(result);
			assertValid("problem-details.schema.json", body);
			assertThat(body.toString()).doesNotContain("Exception", "trace", "org.springframework", "SQL");
		}
	}

	private static List<String> collectRefs(JsonNode node, List<String> refs) {
		if (node.isObject()) {
			for (Map.Entry<String, JsonNode> property : node.properties()) {
				if (property.getKey().equals("$ref") && property.getValue().isString()) {
					refs.add(property.getValue().asString());
				}
				else {
					collectRefs(property.getValue(), refs);
				}
			}
		}
		else if (node.isArray()) {
			node.forEach((child) -> collectRefs(child, refs));
		}
		return refs;
	}

}

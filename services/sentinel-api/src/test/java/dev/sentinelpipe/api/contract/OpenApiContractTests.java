package dev.sentinelpipe.api.contract;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.yaml.YAMLMapper;

/**
 * Keeps {@code packages/contracts/openapi/sentinel-api-v1.yaml} consistent with the
 * application and with the JSON Schemas it references.
 */
class OpenApiContractTests extends AbstractDomainApiIntegrationTest {

	private static final Set<String> HTTP_METHODS = Set.of("get", "put", "post", "delete", "patch", "head",
			"options", "trace");

	private static final String SCHEMA_REF_PREFIX = "../schemas/v1/";

	@Autowired
	@Qualifier("requestMappingHandlerMapping")
	private RequestMappingHandlerMapping handlerMapping;

	private JsonNode openApi;

	@BeforeEach
	void loadDocument() throws Exception {
		this.openApi = YAMLMapper.builder().build().readTree(Files.readString(ContractSchemas.OPENAPI_FILE));
	}

	@Test
	void documentIsOpenApi31() {
		assertThat(this.openApi.get("openapi").asString()).isEqualTo("3.1.0");
		assertThat(this.openApi.path("info").path("title").asString()).isNotBlank();
		assertThat(this.openApi.path("info").path("version").asString()).isNotBlank();
	}

	@Test
	void documentedOperationsExactlyMatchRegisteredEndpoints() {
		Set<String> documented = new TreeSet<>();
		for (Map.Entry<String, JsonNode> path : this.openApi.get("paths").properties()) {
			for (Map.Entry<String, JsonNode> operation : path.getValue().properties()) {
				if (HTTP_METHODS.contains(operation.getKey())) {
					documented.add(operation.getKey().toUpperCase(Locale.ROOT) + " " + path.getKey());
				}
			}
		}

		Set<String> registered = new TreeSet<>();
		for (RequestMappingInfo info : this.handlerMapping.getHandlerMethods().keySet()) {
			for (String pattern : info.getPatternValues()) {
				if (pattern.startsWith("/api/")) {
					info.getMethodsCondition().getMethods().forEach((method) -> registered.add(method + " " + pattern));
				}
			}
		}

		assertThat(registered).isNotEmpty();
		assertThat(documented).isEqualTo(registered);
	}

	@Test
	void everyReferencedSchemaFileExists() {
		List<String> refs = new ArrayList<>();
		collectSchemaRefs(this.openApi, refs);

		assertThat(refs).isNotEmpty();
		assertThat(refs).allSatisfy((ref) -> assertThat(schemaFile(ref)).isRegularFile());
	}

	@Test
	void everyExampleValidatesAgainstItsSchema() {
		List<JsonNode> mediaTypes = new ArrayList<>();
		collectMediaTypes(this.openApi, mediaTypes);
		int validated = 0;
		for (JsonNode mediaType : mediaTypes) {
			String ref = mediaType.path("schema").path("$ref").asString("");
			if (mediaType.has("example") && ref.startsWith(SCHEMA_REF_PREFIX)) {
				ContractSchemas.assertValid(ref.substring(SCHEMA_REF_PREFIX.length()), mediaType.get("example"));
				validated++;
			}
		}

		assertThat(validated).as("number of validated OpenAPI examples").isGreaterThanOrEqualTo(10);
	}

	private static Path schemaFile(String ref) {
		return ContractSchemas.SCHEMAS_DIR.resolve(ref.substring(SCHEMA_REF_PREFIX.length())).normalize();
	}

	private static void collectSchemaRefs(JsonNode node, List<String> refs) {
		if (node.isObject()) {
			for (Map.Entry<String, JsonNode> property : node.properties()) {
				if (property.getKey().equals("$ref") && property.getValue().asString("").startsWith("../")) {
					refs.add(property.getValue().asString());
				}
				else {
					collectSchemaRefs(property.getValue(), refs);
				}
			}
		}
		else if (node.isArray()) {
			node.forEach((child) -> collectSchemaRefs(child, refs));
		}
	}

	/** Collects every media type object under a {@code content} map. */
	private static void collectMediaTypes(JsonNode node, List<JsonNode> mediaTypes) {
		if (!node.isObject()) {
			return;
		}
		for (Map.Entry<String, JsonNode> property : node.properties()) {
			if (property.getKey().equals("content") && property.getValue().isObject()) {
				property.getValue().forEach(mediaTypes::add);
			}
			else {
				collectMediaTypes(property.getValue(), mediaTypes);
			}
		}
	}

}

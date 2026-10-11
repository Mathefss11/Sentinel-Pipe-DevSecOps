package dev.sentinelpipe.api.policy;

import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * JSON Schemas the control plane enforces at run time, bundled on the classpath as
 * byte-identical copies of {@code packages/contracts} (checked by a test, like the
 * worker's bundled copies). Only these identifiers resolve; nothing is fetched over the
 * network. Format assertions are enabled.
 */
final class RuntimeSchemas {

	static final String POLICY_DEFINITION_ID = "https://sentinelpipe.dev/schemas/v1/policy-definition.schema.json";

	static final String FINDINGS_ID = "https://sentinelpipe.dev/schemas/messages/v1/findings.v1.schema.json";

	/** Schema identifier to classpath resource. */
	static final Map<String, String> RESOURCES = Map.of(POLICY_DEFINITION_ID,
			"contracts/schemas/v1/policy-definition.schema.json", FINDINGS_ID,
			"contracts/messages/v1/findings.v1.schema.json");

	private static final SchemaRegistry REGISTRY = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12,
			(builder) -> builder.schemas(RuntimeSchemas::load));

	private static final Schema POLICY_DEFINITION = REGISTRY.getSchema(SchemaLocation.of(POLICY_DEFINITION_ID));

	private static final Schema FINDINGS = REGISTRY.getSchema(SchemaLocation.of(FINDINGS_ID));

	private RuntimeSchemas() {
	}

	static List<Error> validatePolicyDefinition(JsonNode document) {
		return validate(POLICY_DEFINITION, document);
	}

	static List<Error> validateFindings(JsonNode document) {
		return validate(FINDINGS, document);
	}

	private static List<Error> validate(Schema schema, JsonNode document) {
		return schema.validate(document,
				(context) -> context.executionConfig((config) -> config.formatAssertionsEnabled(true)));
	}

	static String load(String iri) {
		String resource = RESOURCES.get(iri);
		if (resource == null) {
			return null;
		}
		try (InputStream in = RuntimeSchemas.class.getClassLoader().getResourceAsStream(resource)) {
			if (in == null) {
				throw new IllegalStateException("bundled schema missing: " + resource);
			}
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

}

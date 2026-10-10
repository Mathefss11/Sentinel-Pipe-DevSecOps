package dev.sentinelpipe.api.contract;

import static org.assertj.core.api.Assertions.assertThat;

import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import tools.jackson.databind.JsonNode;

/**
 * Loads the JSON Schemas in {@code packages/contracts} from the repository working tree
 * and validates JSON documents against them, with format assertions enabled.
 *
 * <p>
 * Schema {@code $id}s ({@code https://sentinelpipe.dev/schemas/v1/...}) are mapped to the
 * local files; nothing is fetched over the network. Any other remote reference fails.
 */
public final class ContractSchemas {

	public static final Path CONTRACTS_DIR = Path.of("..", "..", "packages", "contracts").toAbsolutePath().normalize();

	public static final Path SCHEMAS_DIR = CONTRACTS_DIR.resolve("schemas").resolve("v1");

	public static final Path OPENAPI_FILE = CONTRACTS_DIR.resolve("openapi").resolve("sentinel-api-v1.yaml");

	public static final String SCHEMA_ID_PREFIX = "https://sentinelpipe.dev/schemas/v1/";

	public static final Path MESSAGE_SCHEMAS_DIR = CONTRACTS_DIR.resolve("messages").resolve("v1");

	public static final String MESSAGE_SCHEMA_ID_PREFIX = "https://sentinelpipe.dev/schemas/messages/v1/";

	public static final Path TOPOLOGY_FILE = CONTRACTS_DIR.resolve("messaging").resolve("topology.v1.json");

	private static final SchemaRegistry REGISTRY = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12,
			(builder) -> builder.schemas(ContractSchemas::loadLocal));

	private ContractSchemas() {
	}

	public static Schema schema(String fileName) {
		return REGISTRY.getSchema(SchemaLocation.of(SCHEMA_ID_PREFIX + fileName));
	}

	public static Schema messageSchema(String fileName) {
		return REGISTRY.getSchema(SchemaLocation.of(MESSAGE_SCHEMA_ID_PREFIX + fileName));
	}

	public static List<String> validateMessage(String schemaFileName, JsonNode document) {
		return messageSchema(schemaFileName)
			.validate(document,
					(context) -> context.executionConfig((config) -> config.formatAssertionsEnabled(true)))
			.stream()
			.map(Error::toString)
			.toList();
	}

	public static void assertValidMessage(String schemaFileName, JsonNode document) {
		assertThat(validateMessage(schemaFileName, document))
			.as("%s must validate against %s", document, schemaFileName)
			.isEmpty();
	}

	public static List<String> messageSchemaFileNames() {
		return listSchemas(MESSAGE_SCHEMAS_DIR);
	}

	public static List<String> schemaFileNames() {
		return listSchemas(SCHEMAS_DIR);
	}

	private static List<String> listSchemas(Path directory) {
		try (Stream<Path> files = Files.list(directory)) {
			return files.map((file) -> file.getFileName().toString())
				.filter((name) -> name.endsWith(".schema.json"))
				.sorted()
				.toList();
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	public static List<String> validate(String schemaFileName, JsonNode document) {
		List<Error> errors = schema(schemaFileName).validate(document,
				(context) -> context.executionConfig((config) -> config.formatAssertionsEnabled(true)));
		return errors.stream().map(Error::toString).toList();
	}

	public static void assertValid(String schemaFileName, JsonNode document) {
		assertThat(validate(schemaFileName, document))
			.as("%s must validate against %s", document, schemaFileName)
			.isEmpty();
	}

	private static String loadLocal(String iri) {
		Path directory;
		String fileName;
		if (iri.startsWith(MESSAGE_SCHEMA_ID_PREFIX)) {
			directory = MESSAGE_SCHEMAS_DIR;
			fileName = iri.substring(MESSAGE_SCHEMA_ID_PREFIX.length());
		}
		else if (iri.startsWith(SCHEMA_ID_PREFIX)) {
			directory = SCHEMAS_DIR;
			fileName = iri.substring(SCHEMA_ID_PREFIX.length());
		}
		else {
			return null;
		}
		Path file = directory.resolve(fileName).normalize();
		if (!file.startsWith(directory) || !Files.isRegularFile(file)) {
			return null;
		}
		try {
			return Files.readString(file);
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

}

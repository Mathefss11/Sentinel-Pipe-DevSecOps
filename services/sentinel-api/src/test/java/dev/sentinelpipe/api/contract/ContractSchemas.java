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

	private static final SchemaRegistry REGISTRY = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12,
			(builder) -> builder.schemas(ContractSchemas::loadLocal));

	private ContractSchemas() {
	}

	public static Schema schema(String fileName) {
		return REGISTRY.getSchema(SchemaLocation.of(SCHEMA_ID_PREFIX + fileName));
	}

	public static List<String> schemaFileNames() {
		try (Stream<Path> files = Files.list(SCHEMAS_DIR)) {
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
		if (!iri.startsWith(SCHEMA_ID_PREFIX)) {
			return null;
		}
		String fileName = iri.substring(SCHEMA_ID_PREFIX.length());
		Path file = SCHEMAS_DIR.resolve(fileName).normalize();
		if (!file.startsWith(SCHEMAS_DIR) || !Files.isRegularFile(file)) {
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

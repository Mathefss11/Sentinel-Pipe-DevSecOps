package dev.sentinelpipe.api.policy;

import com.networknt.schema.Error;
import dev.sentinelpipe.api.common.InvalidDocumentException;
import dev.sentinelpipe.api.common.InvalidDocumentException.Violation;
import dev.sentinelpipe.api.evidence.EvidenceVerifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Validation and canonicalization of policy.v1 definitions
 * ({@code packages/contracts/schemas/v1/policy-definition.schema.json}).
 *
 * <p>
 * A definition is parsed strictly (no duplicate keys, no trailing content), validated
 * against the closed schema (unknown fields, values outside the per-scanner vocabularies
 * and out-of-range numbers are rejected), required to use integer literals, and then
 * rebuilt from the validated model in canonical form: sorted keys, sorted set-like arrays,
 * no whitespace. The SHA-256 of that text identifies the definition, so equivalent
 * definitions have the same digest regardless of key order, array order or formatting.
 * Error messages are fixed and never echo submitted values.
 */
public final class PolicyDocuments {

	/** Upper bound of a definition, before and after canonicalization. */
	public static final int MAX_BYTES = 16 * 1024;

	/** A validated definition with its canonical text and digest. */
	public record ValidatedPolicy(PolicyDefinition definition, String canonical, String sha256) {
	}

	private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

	/** Every property name policy.v1 defines; nothing else appears in a reported location. */
	private static final Set<String> SCHEMA_PROPERTIES = Set.of("schema_version", "name", "evidence", "scanners",
			"findings_schema_versions", "max_age_seconds", "GITLEAKS", "SEMGREP", "TRIVY", "require_complete_coverage",
			"accepted_limitations", "blocking_severities", "max_blocking_findings", "max_database_age_seconds");

	private PolicyDocuments() {
	}

	/**
	 * Validates a submitted definition.
	 * @throws InvalidDocumentException with sanitized violations
	 */
	public static ValidatedPolicy parse(String text) {
		if (text == null || text.isBlank()) {
			throw new InvalidDocumentException("definition", "must be a JSON object");
		}
		byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
		if (bytes.length > MAX_BYTES) {
			throw new InvalidDocumentException("definition", "must not exceed " + MAX_BYTES + " bytes");
		}
		JsonNode document;
		try {
			document = CanonicalJson.parse(bytes);
		}
		catch (IllegalArgumentException ex) {
			throw new InvalidDocumentException("definition",
					"must be valid JSON without duplicate keys or trailing content");
		}
		List<Violation> violations = new ArrayList<>();
		for (Error error : RuntimeSchemas.validatePolicyDefinition(document)) {
			violations.add(violation(error));
		}
		collectNonIntegralNumbers(document, "$", violations);
		if (!violations.isEmpty()) {
			throw new InvalidDocumentException(violations);
		}
		PolicyDefinition definition = model(document);
		String canonical = CanonicalJson.write(canonicalNode(definition));
		if (canonical.length() > MAX_BYTES) {
			throw new InvalidDocumentException("definition", "must not exceed " + MAX_BYTES + " bytes");
		}
		return new ValidatedPolicy(definition, canonical, EvidenceVerifier.sha256(canonical.getBytes(StandardCharsets.US_ASCII)));
	}

	/**
	 * Re-validates a stored definition before evaluation: the text must still be valid,
	 * canonical and have the recorded digest (defense in depth; the database also checks
	 * the digest).
	 * @throws IllegalArgumentException if any check fails
	 */
	public static ValidatedPolicy parseStored(String canonical, String sha256) {
		if (canonical == null || sha256 == null
				|| !EvidenceVerifier.sha256(canonical.getBytes(StandardCharsets.UTF_8)).equals(sha256)) {
			throw new IllegalArgumentException("stored policy does not match its digest");
		}
		ValidatedPolicy policy;
		try {
			policy = parse(canonical);
		}
		catch (InvalidDocumentException ex) {
			throw new IllegalArgumentException("stored policy is not valid policy.v1");
		}
		if (!policy.canonical().equals(canonical)) {
			throw new IllegalArgumentException("stored policy is not canonical");
		}
		return policy;
	}

	private static PolicyDefinition model(JsonNode document) {
		JsonNode evidence = document.get("evidence");
		SortedSet<Integer> versions = new TreeSet<>();
		evidence.get("findings_schema_versions").values().forEach((v) -> versions.add(v.intValue()));
		Map<PolicyScanner, PolicyDefinition.ScannerRules> scanners = new EnumMap<>(PolicyScanner.class);
		for (Map.Entry<String, JsonNode> entry : document.get("scanners").properties()) {
			PolicyScanner scanner = PolicyScanner.valueOf(entry.getKey());
			JsonNode rules = entry.getValue();
			JsonNode databaseAge = rules.get("max_database_age_seconds");
			scanners.put(scanner,
					new PolicyDefinition.ScannerRules(rules.get("require_complete_coverage").booleanValue(),
							strings(rules.get("accepted_limitations")), strings(rules.get("blocking_severities")),
							rules.get("max_blocking_findings").intValue(),
							(databaseAge != null) ? databaseAge.longValue() : null));
		}
		return new PolicyDefinition(document.get("name").stringValue(), versions,
				evidence.get("max_age_seconds").longValue(), scanners);
	}

	private static SortedSet<String> strings(JsonNode array) {
		SortedSet<String> values = new TreeSet<>();
		if (array != null) {
			array.values().forEach((value) -> values.add(value.stringValue()));
		}
		return values;
	}

	/** The canonical document of a definition (set-like arrays sorted). */
	static ObjectNode canonicalNode(PolicyDefinition definition) {
		ObjectNode root = NODES.objectNode();
		root.put("schema_version", 1);
		root.put("name", definition.name());
		ObjectNode evidence = root.putObject("evidence");
		ArrayNode versions = evidence.putArray("findings_schema_versions");
		definition.findingsSchemaVersions().forEach(versions::add);
		evidence.put("max_age_seconds", definition.maxEvidenceAgeSeconds());
		ObjectNode scanners = root.putObject("scanners");
		definition.scanners().forEach((scanner, rules) -> {
			ObjectNode node = scanners.putObject(scanner.name());
			node.put("require_complete_coverage", rules.requireCompleteCoverage());
			ArrayNode accepted = node.putArray("accepted_limitations");
			rules.acceptedLimitations().forEach(accepted::add);
			if (scanner != PolicyScanner.GITLEAKS) {
				ArrayNode severities = node.putArray("blocking_severities");
				rules.blockingSeverities().forEach(severities::add);
			}
			node.put("max_blocking_findings", rules.maxBlockingFindings());
			if (rules.maxDatabaseAgeSeconds() != null) {
				node.put("max_database_age_seconds", rules.maxDatabaseAgeSeconds());
			}
		});
		return root;
	}

	/** JSON Schema's "integer" admits 1.0; canonical policies use integer literals only. */
	private static void collectNonIntegralNumbers(JsonNode node, String path, List<Violation> violations) {
		if (node.isNumber() && !node.isIntegralNumber()) {
			violations.add(new Violation(path, "must be an integer literal"));
		}
		else if (node.isObject()) {
			node.properties().forEach((entry) -> collectNonIntegralNumbers(entry.getValue(),
					path + "." + sanitizedSegment(entry.getKey()), violations));
		}
		else if (node.isArray()) {
			int index = 0;
			for (JsonNode child : node.values()) {
				collectNonIntegralNumbers(child, path + "[" + index++ + "]", violations);
			}
		}
	}

	private static Violation violation(Error error) {
		String location = sanitizedPath(String.valueOf(error.getInstanceLocation()));
		String keyword = String.valueOf(error.getKeyword());
		return switch (keyword) {
			// The missing property name comes from the schema, never from the request.
			case "required" -> new Violation(location + "." + sanitizedSegment(String.valueOf(error.getProperty())),
					"is required");
			case "additionalProperties" -> new Violation(location, "contains an unsupported property");
			case "const", "enum" -> new Violation(location, "has an unsupported value");
			case "type" -> new Violation(location, "has an invalid type");
			case "pattern" -> new Violation(location, "has an invalid format");
			case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum" ->
				new Violation(location, "is out of range");
			case "uniqueItems" -> new Violation(location, "must not contain duplicates");
			case "minItems", "maxItems", "minProperties", "maxProperties" ->
				new Violation(location, "has an invalid number of entries");
			default -> new Violation(location, "is invalid");
		};
	}

	/**
	 * Rebuilds a validator location from schema property names and array indexes only. Any
	 * other segment (for example an unknown key a caller submitted) becomes {@code *}, so a
	 * location never echoes request content, whatever path syntax the validator uses.
	 */
	private static String sanitizedPath(String path) {
		StringBuilder out = new StringBuilder("$");
		for (String segment : path.split("[./\\[\\]]")) {
			if (segment.isEmpty() || segment.equals("$") || segment.equals("#")) {
				continue;
			}
			if (segment.matches("[0-9]{1,4}")) {
				out.append('[').append(segment).append(']');
			}
			else {
				out.append('.').append(sanitizedSegment(segment));
			}
		}
		return out.toString();
	}

	private static String sanitizedSegment(String segment) {
		return SCHEMA_PROPERTIES.contains(segment) ? segment : "*";
	}

}

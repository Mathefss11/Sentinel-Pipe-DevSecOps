package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.common.InvalidDocumentException;
import dev.sentinelpipe.api.contract.ContractSchemas;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** policy.v1 validation, canonicalization and digests (ADR-0013). */
class PolicyDocumentsTests {

	private static final String BASELINE = PolicyFixtures.allScanners("baseline");

	private static InvalidDocumentException rejected(String definition) {
		return (InvalidDocumentException) org.assertj.core.api.Assertions
			.catchThrowableOfType(InvalidDocumentException.class, () -> PolicyDocuments.parse(definition));
	}

	@Test
	void aValidDefinitionIsModelledExactly() {
		PolicyDefinition policy = PolicyDocuments.parse(BASELINE).definition();

		assertThat(policy.name()).isEqualTo("baseline");
		assertThat(policy.findingsSchemaVersions()).containsExactly(1);
		assertThat(policy.maxEvidenceAgeSeconds()).isEqualTo(86400);
		assertThat(policy.mandatoryScanners()).containsExactly(PolicyScanner.GITLEAKS, PolicyScanner.SEMGREP,
				PolicyScanner.TRIVY);
		PolicyDefinition.ScannerRules trivy = policy.scanners().get(PolicyScanner.TRIVY);
		assertThat(trivy.blockingSeverities()).containsExactly("CRITICAL", "HIGH");
		assertThat(trivy.maxDatabaseAgeSeconds()).isEqualTo(172800);
		assertThat(policy.scanners().get(PolicyScanner.GITLEAKS).blockingSeverities()).isEmpty();
		assertThat(policy.scanners().get(PolicyScanner.GITLEAKS).maxDatabaseAgeSeconds()).isNull();
	}

	@Test
	void theCanonicalFormAndDigestDoNotDependOnFormattingKeyOrderOrSetOrder() {
		String reordered = """
				{ "scanners": {"GITLEAKS": {"max_blocking_findings": 0,
				    "accepted_limitations": ["RULESET_DEFAULT_ONLY", "GIT_HISTORY_NOT_SCANNED", "COMMIT_NOT_VERIFIED",
				                             "ARCHIVES_NOT_SCANNED"],
				    "require_complete_coverage": true}},
				  "evidence": {"max_age_seconds": 86400, "findings_schema_versions": [1]},
				  "name": "gitleaks", "schema_version": 1 }
				""";

		PolicyDocuments.ValidatedPolicy a = PolicyDocuments.parse(PolicyFixtures.gitleaksOnly("gitleaks"));
		PolicyDocuments.ValidatedPolicy b = PolicyDocuments.parse(reordered);

		assertThat(a.canonical()).isEqualTo(b.canonical());
		assertThat(a.sha256()).isEqualTo(b.sha256()).matches("[0-9a-f]{64}");
		assertThat(a.canonical()).isEqualTo("{\"evidence\":{\"findings_schema_versions\":[1],\"max_age_seconds\":86400},"
				+ "\"name\":\"gitleaks\",\"scanners\":{\"GITLEAKS\":{\"accepted_limitations\":[\"ARCHIVES_NOT_SCANNED\","
				+ "\"COMMIT_NOT_VERIFIED\",\"GIT_HISTORY_NOT_SCANNED\",\"RULESET_DEFAULT_ONLY\"],"
				+ "\"max_blocking_findings\":0,\"require_complete_coverage\":true}},\"schema_version\":1}");
		// Any semantic change changes the digest.
		assertThat(PolicyDocuments.parse(PolicyFixtures.gitleaksOnly("gitleaks").replace("\"max_blocking_findings\": 0",
				"\"max_blocking_findings\": 1")).sha256()).isNotEqualTo(a.sha256());
	}

	@ParameterizedTest
	@ValueSource(strings = {
			// Unknown or misplaced fields.
			"\"schema_version\": 1,|\"schema_version\": 1, \"expression\": \"true\",",
			"\"max_blocking_findings\": 0}}}|\"max_blocking_findings\": 0, \"allow\": true}}}",
			"\"max_blocking_findings\": 0}}}|\"max_blocking_findings\": 0, \"blocking_severities\": [\"ERROR\"]}}}",
			// Unsupported versions and values.
			"\"schema_version\": 1,|\"schema_version\": 2,",
			"\"findings_schema_versions\": [1]|\"findings_schema_versions\": [2]",
			"\"findings_schema_versions\": [1]|\"findings_schema_versions\": []",
			"\"max_age_seconds\": 86400|\"max_age_seconds\": 59",
			"\"max_age_seconds\": 86400|\"max_age_seconds\": 86400.0",
			"\"max_age_seconds\": 86400|\"max_age_seconds\": \"86400\"",
			"\"max_blocking_findings\": 0|\"max_blocking_findings\": -1",
			"\"max_blocking_findings\": 0|\"max_blocking_findings\": 1001",
			"\"name\": \"gitleaks\"|\"name\": \"Gitleaks Policy\"",
			// Limitations a policy can never accept, or that are not this scanner's.
			"\"RULESET_DEFAULT_ONLY\"]|\"RULESET_DEFAULT_ONLY\", \"EMPTY_INPUT\"]",
			"\"RULESET_DEFAULT_ONLY\"]|\"RULESET_DEFAULT_ONLY\", \"VULNERABILITY_DB_STALE\"]",
			"\"RULESET_DEFAULT_ONLY\"]|\"RULESET_DEFAULT_ONLY\", \"RULESET_DEFAULT_ONLY\"]",
			// Unknown scanners.
			"\"GITLEAKS\":|\"FIXTURE\":", "\"GITLEAKS\":|\"gitleaks\":" })
	void malformedOrUnsupportedDefinitionsAreRejected(String edit) {
		String[] parts = edit.split("\\|");
		String definition = PolicyFixtures.gitleaksOnly("gitleaks").replace(parts[0], parts[1]);
		assertThat(definition).isNotEqualTo(PolicyFixtures.gitleaksOnly("gitleaks"));

		assertThat(rejected(definition).getViolations()).isNotEmpty();
	}

	/** Final review: every numeric bound is inclusive and exact; nothing else is a number. */
	@ParameterizedTest
	@org.junit.jupiter.params.provider.CsvSource({ "max_age_seconds, 86400, 60, true", "max_age_seconds, 86400, 2592000, true",
			"max_age_seconds, 86400, 59, false", "max_age_seconds, 86400, 2592001, false",
			"max_blocking_findings, 0, 1000, true", "max_blocking_findings, 0, -1, false",
			"max_blocking_findings, 0, 1001, false", "max_blocking_findings, 0, -0, true",
			"max_blocking_findings, 0, 99999999999999999999999999, false", "max_blocking_findings, 0, 1e2, false",
			"max_blocking_findings, 0, 0.0, false", "max_database_age_seconds, 172800, 3600, true",
			"max_database_age_seconds, 172800, 604800, true", "max_database_age_seconds, 172800, 3599, false",
			"max_database_age_seconds, 172800, 604801, false" })
	void numericBoundariesAreExact(String field, String original, String value, boolean accepted) {
		String definition = BASELINE.replaceFirst("\"" + field + "\": " + original, "\"" + field + "\": " + value);
		assertThat(definition).isNotEqualTo(BASELINE);

		if (accepted) {
			assertThat(PolicyDocuments.parse(definition).canonical()).contains("\"" + field + "\":"
					+ new java.math.BigInteger(value));
		}
		else {
			assertThat(rejected(definition).getViolations()).isNotEmpty();
		}
	}

	@Test
	void deeplyNestedInputIsRejectedAsAValidationErrorNotACrash() {
		String deep = "{\"schema_version\": 1, \"name\": " + "[".repeat(6000) + "]".repeat(6000) + "}";
		String nestedInKnownField = PolicyFixtures.gitleaksOnly("gitleaks")
			.replace("[\"ARCHIVES_NOT_SCANNED\",", "[" + "[".repeat(300) + "]".repeat(300) + ", \"ARCHIVES_NOT_SCANNED\",");

		assertThat(deep.length()).isLessThan(PolicyDocuments.MAX_BYTES);
		assertThat(rejected(deep).getViolations()).isNotEmpty();
		assertThat(rejected(nestedInKnownField).getViolations()).isNotEmpty();
	}

	@Test
	void unicodeEscapesAreNormalizedBeforeValidationAndNeverWidenTheVocabulary() {
		// "\u0062aseline" is "baseline"; an escaped scanner key is the same key.
		String escaped = PolicyFixtures.gitleaksOnly("baseline")
			.replace("\"name\": \"baseline\"", "\"name\": \"\\u0062aseline\"")
			.replace("\"GITLEAKS\":", "\"\\u0047ITLEAKS\":");
		assertThat(PolicyDocuments.parse(escaped).sha256())
			.isEqualTo(PolicyDocuments.parse(PolicyFixtures.gitleaksOnly("baseline")).sha256());
		// Look-alike characters are other characters, and are refused.
		assertThat(rejected(PolicyFixtures.gitleaksOnly("baseline").replace("\"GITLEAKS\":", "\"GITLEAK\\u0405\":")))
			.isNotNull();
	}

	@Test
	void scannerSpecificVocabulariesAreEnforced() {
		// Trivy's labels are not Semgrep's, and vice versa: no shared severity scale.
		assertThat(rejected(BASELINE.replace("\"blocking_severities\": [\"ERROR\", \"WARNING\"]",
				"\"blocking_severities\": [\"HIGH\"]")))
			.isNotNull();
		assertThat(rejected(BASELINE.replace("\"blocking_severities\": [\"CRITICAL\", \"HIGH\"]",
				"\"blocking_severities\": [\"ERROR\"]")))
			.isNotNull();
		assertThat(rejected(BASELINE.replace("\"blocking_severities\": [\"CRITICAL\", \"HIGH\"]",
				"\"blocking_severities\": []")))
			.isNotNull();
		// Trivy requires a database age; NO_SUPPORTED_FILES can never be accepted.
		assertThat(rejected(BASELINE.replace(",\n   \"max_database_age_seconds\": 172800", ""))).isNotNull();
		assertThat(rejected(BASELINE.replace("\"SYNTHETIC_VULNERABILITY_DATABASE\"]",
				"\"SYNTHETIC_VULNERABILITY_DATABASE\", \"NO_SUPPORTED_FILES\"]")))
			.isNotNull();
		assertThat(rejected(BASELINE.replace("\"max_database_age_seconds\": 172800",
				"\"max_database_age_seconds\": 604801")))
			.isNotNull();
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "   ", "[]", "null", "{", "{\"schema_version\": 1, \"schema_version\": 1}",
			"{\"schema_version\": 1} {}", "{\"schema_version\": NaN}" })
	void nonObjectsDuplicateKeysAndTrailingContentAreRejected(String definition) {
		assertThatThrownBy(() -> PolicyDocuments.parse(definition)).isInstanceOf(InvalidDocumentException.class);
	}

	@Test
	void duplicateKeysAnywhereAreRejectedRatherThanResolved() {
		String duplicate = PolicyFixtures.gitleaksOnly("gitleaks")
			.replace("\"max_blocking_findings\": 0", "\"max_blocking_findings\": 0, \"max_blocking_findings\": 1000");

		assertThat(rejected(duplicate).getViolations()).extracting(InvalidDocumentException.Violation::field)
			.containsExactly("definition");
	}

	@Test
	void oversizedDefinitionsAreRejectedBeforeParsing() {
		String oversized = PolicyFixtures.gitleaksOnly("gitleaks") + " ".repeat(PolicyDocuments.MAX_BYTES);

		assertThat(rejected(oversized).getViolations().get(0).message()).contains("16384");
	}

	@Test
	void violationsNeverEchoSubmittedValues() {
		String marker = "SENTINEL_SUBMITTED_VALUE_" + "Q".repeat(20);
		String definition = PolicyFixtures.gitleaksOnly("gitleaks")
			.replace("\"schema_version\": 1,", "\"schema_version\": 1, \"" + marker + "\": \"" + marker + "\",")
			.replace("\"name\": \"gitleaks\"", "\"name\": \"" + marker.toLowerCase() + "\"");

		InvalidDocumentException ex = rejected(definition);

		assertThat(ex.getViolations()).isNotEmpty();
		assertThat(ex.getViolations().toString()).doesNotContainIgnoringCase(marker);
		assertThat(ex.getMessage()).doesNotContainIgnoringCase(marker);
	}

	@Test
	void storedDefinitionsAreReverifiedBeforeUse() {
		PolicyDocuments.ValidatedPolicy policy = PolicyDocuments.parse(BASELINE);

		assertThat(PolicyDocuments.parseStored(policy.canonical(), policy.sha256()).definition())
			.isEqualTo(policy.definition());
		// Tampered text, a wrong digest, or a stored text that is not canonical are refused.
		String tampered = policy.canonical().replace("\"max_blocking_findings\":0", "\"max_blocking_findings\":9");
		assertThatThrownBy(() -> PolicyDocuments.parseStored(tampered, policy.sha256()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> PolicyDocuments.parseStored(policy.canonical(), "0".repeat(64)))
			.isInstanceOf(IllegalArgumentException.class);
		String spaced = policy.canonical().replace(",", ", ");
		assertThatThrownBy(() -> PolicyDocuments.parseStored(spaced,
				dev.sentinelpipe.api.evidence.EvidenceVerifier.sha256(spaced.getBytes(StandardCharsets.UTF_8))))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void theSchemaExampleIsAValidPolicy() throws Exception {
		var schema = ContractSchemas.schema("policy-definition.schema.json");
		assertThat(schema).isNotNull();
		var document = tools.jackson.databind.json.JsonMapper.builder()
			.build()
			.readTree(Files.readString(ContractSchemas.SCHEMAS_DIR.resolve("policy-definition.schema.json")));
		String example = document.get("examples").get(0).toString();

		assertThat(PolicyDocuments.parse(example).definition().mandatoryScanners()).hasSize(3);
	}

	@Test
	void theRuntimeSchemasAreByteIdenticalToTheContracts() throws Exception {
		Map<String, Path> contracts = Map.of(RuntimeSchemas.POLICY_DEFINITION_ID,
				ContractSchemas.SCHEMAS_DIR.resolve("policy-definition.schema.json"), RuntimeSchemas.FINDINGS_ID,
				ContractSchemas.MESSAGE_SCHEMAS_DIR.resolve("findings.v1.schema.json"));
		assertThat(RuntimeSchemas.RESOURCES.keySet()).isEqualTo(contracts.keySet());
		for (Map.Entry<String, Path> contract : contracts.entrySet()) {
			assertThat(RuntimeSchemas.load(contract.getKey())).as(contract.getKey())
				.isEqualTo(Files.readString(contract.getValue()));
		}
		assertThat(RuntimeSchemas.load("https://sentinelpipe.dev/schemas/v1/scan.schema.json")).isNull();
	}

}

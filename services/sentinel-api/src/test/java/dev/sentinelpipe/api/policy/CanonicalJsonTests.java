package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.WorkerProtocol;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Canonical JSON must be byte-identical to the worker's
 * {@code json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)}, because
 * the policy engine re-derives the digest of accepted {@code job-result.v1} documents.
 * The expected strings below were produced by CPython 3.14.6's {@code json} module for the
 * same input text.
 */
class CanonicalJsonTests {

	@Test
	void matchesPythonCanonicalSerialization() {
		String input = "{\"b\": [1, true, null, \"x\"], \"a\": {\"\u00e9\": \"\\u2028\\n\\t\\\"\\\\\\u0001\\u007f\"},"
				+ " \"A\": -12345678901234567890}";

		assertThat(CanonicalJson.write(CanonicalJson.parse(input)))
			.isEqualTo("{\"A\":-12345678901234567890,\"a\":{\"\\u00e9\":\"\\u2028\\n\\t\\\"\\\\\\u0001\\u007f\"},"
					+ "\"b\":[1,true,null,\"x\"]}");
	}

	@Test
	void keysAreOrderedByCodePointIncludingSupplementaryCharacters() {
		// U+FF5E sorts before U+1F600 by code point, but after its surrogate pair by UTF-16 unit.
		String input = "{\"\\ud83d\\ude00\": 1, \"\\uff5e\": 2, \"z\": 3}";

		assertThat(CanonicalJson.write(CanonicalJson.parse(input)))
			.isEqualTo("{\"z\":3,\"\\uff5e\":2,\"\\ud83d\\ude00\":1}");
	}

	@Test
	void agreesWithTheJobResultCanonicalFormUsedByWorkers() {
		Map<String, Object> document = new TreeMap<>(Map.of("schema_version", 1, "job_id", "a", "artifacts",
				List.of(Map.of("name", "findings.json", "size_bytes", 12)), "failure_reason", "x"));
		document.put("failure_reason", null);
		String expected = WorkerProtocol.canonical(document);

		// A stored JSONB rendering (spaces, different key order) canonicalizes back to it.
		String jsonb = "{\"job_id\": \"a\", \"artifacts\": [{\"name\": \"findings.json\", \"size_bytes\": 12}],"
				+ " \"failure_reason\": null, \"schema_version\": 1}";
		assertThat(CanonicalJson.write(CanonicalJson.parse(jsonb))).isEqualTo(expected);
	}

	@Test
	void ambiguousOrNonCanonicalInputIsRefused() {
		assertThatThrownBy(() -> CanonicalJson.parse("{\"a\": 1, \"a\": 2}")).isInstanceOf(IllegalArgumentException.class)
			.hasMessageNotContaining("\"a\"");
		assertThatThrownBy(() -> CanonicalJson.parse("{} []")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> CanonicalJson.parse("")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> CanonicalJson.write(CanonicalJson.parse("{\"a\": 1.5}")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> CanonicalJson.write(CanonicalJson.parse("{\"a\": 1e3}")))
			.isInstanceOf(IllegalArgumentException.class);
	}

}

package dev.sentinelpipe.api.policy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Canonical JSON, byte-compatible with the worker's
 * {@code json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)} for the
 * documents SentinelPipe exchanges (policy.v1 definitions, evaluation reasons,
 * {@code job-result.v1} results): keys sorted by code point, no whitespace, integers only,
 * ASCII output with Python's escapes.
 *
 * <p>
 * Parsing is strict: duplicate keys, trailing content and non-standard tokens are
 * refused, so a document has exactly one meaning before it is canonicalized and digested.
 */
public final class CanonicalJson {

	private static final JsonMapper STRICT = JsonMapper.builder()
		.enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
		.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
		.enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
		.build();

	private CanonicalJson() {
	}

	/**
	 * Parses UTF-8 JSON strictly.
	 * @throws IllegalArgumentException for malformed input (the message never contains the
	 * input)
	 */
	public static JsonNode parse(byte[] json) {
		try {
			JsonNode node = STRICT.readTree(json);
			if (node == null || node.isMissingNode()) {
				throw new IllegalArgumentException("empty JSON document");
			}
			return node;
		}
		catch (tools.jackson.core.JacksonException ex) {
			// The parser message can quote input: never propagate it.
			throw new IllegalArgumentException("malformed JSON document");
		}
	}

	public static JsonNode parse(String json) {
		return parse(json.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * The canonical serialization of {@code node}.
	 * @throws IllegalArgumentException if the document contains a non-integral number
	 */
	public static String write(JsonNode node) {
		StringBuilder out = new StringBuilder();
		write(out, node);
		return out.toString();
	}

	private static void write(StringBuilder out, JsonNode node) {
		if (node.isObject()) {
			List<Map.Entry<String, JsonNode>> entries = new ArrayList<>(node.properties());
			// Code-point order (Python's sort_keys); keys are compared as code point sequences.
			entries.sort((a, b) -> compareCodePoints(a.getKey(), b.getKey()));
			out.append('{');
			for (int i = 0; i < entries.size(); i++) {
				if (i > 0) {
					out.append(',');
				}
				writeString(out, entries.get(i).getKey());
				out.append(':');
				write(out, entries.get(i).getValue());
			}
			out.append('}');
		}
		else if (node.isArray()) {
			out.append('[');
			int i = 0;
			for (JsonNode child : node.values()) {
				if (i++ > 0) {
					out.append(',');
				}
				write(out, child);
			}
			out.append(']');
		}
		else if (node.isString()) {
			writeString(out, node.stringValue());
		}
		else if (node.isIntegralNumber()) {
			BigInteger value = node.bigIntegerValue();
			out.append(value.toString());
		}
		else if (node.isNumber()) {
			throw new IllegalArgumentException("non-integral numbers are not canonical");
		}
		else if (node.isBoolean()) {
			out.append(node.booleanValue() ? "true" : "false");
		}
		else if (node.isNull()) {
			out.append("null");
		}
		else {
			throw new IllegalArgumentException("unsupported JSON node");
		}
	}

	private static int compareCodePoints(String a, String b) {
		int i = 0;
		int j = 0;
		while (i < a.length() && j < b.length()) {
			int ca = a.codePointAt(i);
			int cb = b.codePointAt(j);
			if (ca != cb) {
				return Integer.compare(ca, cb);
			}
			i += Character.charCount(ca);
			j += Character.charCount(cb);
		}
		return Integer.compare(a.length() - i, b.length() - j);
	}

	/** Python's {@code ensure_ascii} escaping: short escapes, then lowercase {@code \\uXXXX}. */
	private static void writeString(StringBuilder out, String value) {
		out.append('"');
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			switch (c) {
				case '"' -> out.append("\\\"");
				case '\\' -> out.append("\\\\");
				case '\n' -> out.append("\\n");
				case '\r' -> out.append("\\r");
				case '\t' -> out.append("\\t");
				case '\b' -> out.append("\\b");
				case '\f' -> out.append("\\f");
				default -> {
					if (c < 0x20 || c > 0x7e) {
						out.append(String.format("\\u%04x", (int) c));
					}
					else {
						out.append(c);
					}
				}
			}
		}
		out.append('"');
	}

}

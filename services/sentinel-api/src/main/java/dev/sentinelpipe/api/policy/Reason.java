package dev.sentinelpipe.api.policy;

import dev.sentinelpipe.api.scanjob.ScannerType;
import java.util.Comparator;
import java.util.Objects;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * One structured reason of an evaluation. Values are codes, counts and scanner types only:
 * never finding content, paths or evidence excerpts.
 *
 * @param scanner the scanner the reason concerns, or {@code null} for the scan as a whole
 * @param subject a sanitized code qualifying the reason (a limitation, failure reason or
 * check name), or {@code null}
 * @param observed a measured value (a count or seconds), or {@code null}
 * @param limit the policy's limit for {@code observed}, or {@code null}
 */
public record Reason(ReasonCode code, ScannerType scanner, String subject, Long observed, Long limit) {

	/** Deterministic, total order of reasons in a record (equal only when identical). */
	public static final Comparator<Reason> ORDER = Comparator
		.comparing((Reason reason) -> (reason.scanner() == null) ? -1 : reason.scanner().ordinal())
		.thenComparing(Reason::code)
		.thenComparing((Reason reason) -> Objects.toString(reason.subject(), ""))
		.thenComparing(Reason::observed, Comparator.nullsFirst(Comparator.naturalOrder()))
		.thenComparing(Reason::limit, Comparator.nullsFirst(Comparator.naturalOrder()));

	public Reason {
		Objects.requireNonNull(code, "code");
		if (subject != null && !subject.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")) {
			throw new IllegalArgumentException("reason subjects are sanitized codes");
		}
	}

	public static Reason of(ReasonCode code, ScannerType scanner) {
		return new Reason(code, scanner, null, null, null);
	}

	public static Reason of(ReasonCode code, ScannerType scanner, String subject) {
		return new Reason(code, scanner, subject, null, null);
	}

	public static Reason measured(ReasonCode code, ScannerType scanner, long observed, Long limit) {
		return new Reason(code, scanner, null, observed, limit);
	}

	public ReasonEffect effect() {
		return this.code.effect();
	}

	ObjectNode toJson() {
		ObjectNode node = JsonNodeFactory.instance.objectNode();
		node.put("code", this.code.name());
		node.put("effect", effect().name());
		node.put("scanner", (this.scanner != null) ? this.scanner.name() : null);
		node.put("subject", this.subject);
		node.put("observed", this.observed);
		node.put("limit", this.limit);
		return node;
	}

}

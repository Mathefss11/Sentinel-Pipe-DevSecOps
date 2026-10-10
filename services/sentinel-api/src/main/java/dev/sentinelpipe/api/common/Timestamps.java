package dev.sentinelpipe.api.common;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Server-side timestamp source. Values are truncated to microseconds, the precision of
 * PostgreSQL {@code TIMESTAMPTZ}, so a freshly created resource and the same resource
 * read back from the database expose identical timestamps.
 */
public final class Timestamps {

	private Timestamps() {
	}

	public static Instant now(Clock clock) {
		return Instant.now(clock).truncatedTo(ChronoUnit.MICROS);
	}

}

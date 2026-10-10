package dev.sentinelpipe.api.identity;

import java.util.Objects;

/**
 * The caller of the current request, as established by a validated access token. Only
 * the token's {@code iss} and {@code sub} claims identify a user; no other claim is used
 * for authorization.
 */
public record AuthenticatedPrincipal(String issuer, String subject) {

	public AuthenticatedPrincipal {
		Objects.requireNonNull(issuer, "issuer");
		Objects.requireNonNull(subject, "subject");
	}

}

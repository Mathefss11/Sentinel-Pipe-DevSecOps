package dev.sentinelpipe.api.identity;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/** Resolves the {@link AuthenticatedPrincipal} of the current request. */
@Component
public class CurrentPrincipal {

	/**
	 * Returns the authenticated caller. Fails closed if the request was not authenticated
	 * with a validated JWT, which the security filter chain normally already prevents.
	 */
	public AuthenticatedPrincipal require() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()
				|| !(authentication.getPrincipal() instanceof Jwt jwt)) {
			throw new AuthenticationCredentialsNotFoundException("No authenticated principal");
		}
		String issuer = jwt.getClaimAsString("iss");
		String subject = jwt.getSubject();
		if (issuer == null || subject == null) {
			throw new AuthenticationCredentialsNotFoundException("Token has no issuer or subject");
		}
		return new AuthenticatedPrincipal(issuer, subject);
	}

}

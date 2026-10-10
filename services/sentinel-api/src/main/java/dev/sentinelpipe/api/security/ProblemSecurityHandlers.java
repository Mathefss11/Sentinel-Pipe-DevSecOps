package dev.sentinelpipe.api.security;

import dev.sentinelpipe.api.common.ProblemTypes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import tools.jackson.databind.json.JsonMapper;

/**
 * RFC 9457 responses for requests rejected by the security filter chain.
 *
 * <p>
 * The reason a token was rejected (expired, wrong audience, bad signature, ...) is logged
 * at debug level only and never returned to the client. The {@code WWW-Authenticate}
 * header follows RFC 6750 without an {@code error_description}.
 */
final class ProblemSecurityHandlers {

	private static final Logger log = LoggerFactory.getLogger(ProblemSecurityHandlers.class);

	private ProblemSecurityHandlers() {
	}

	/** 401 for missing or invalid bearer tokens. */
	static AuthenticationEntryPoint bearerEntryPoint(JsonMapper jsonMapper) {
		return (request, response, exception) -> {
			boolean invalidToken = exception instanceof OAuth2AuthenticationException;
			if (invalidToken) {
				log.debug("Rejected bearer token: {}", exception.getMessage());
			}
			response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
					invalidToken ? "Bearer error=\"invalid_token\"" : "Bearer");
			write(jsonMapper, request, response, HttpStatus.UNAUTHORIZED, ProblemTypes.UNAUTHORIZED, "Unauthorized",
					"A valid bearer access token is required.");
		};
	}

	/** 403 for requests denied to everyone (default deny) when no authentication is configured. */
	static AuthenticationEntryPoint denyEntryPoint(JsonMapper jsonMapper) {
		return (request, response, exception) -> forbidden(jsonMapper, request, response);
	}

	static AccessDeniedHandler accessDeniedHandler(JsonMapper jsonMapper) {
		return (request, response, exception) -> forbidden(jsonMapper, request, response);
	}

	private static void forbidden(JsonMapper jsonMapper, HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		write(jsonMapper, request, response, HttpStatus.FORBIDDEN, ProblemTypes.FORBIDDEN, "Forbidden",
				"Access to this resource is not permitted.");
	}

	private static void write(JsonMapper jsonMapper, HttpServletRequest request, HttpServletResponse response,
			HttpStatus status, URI type, String title, String detail) throws IOException {
		Map<String, Object> problem = new LinkedHashMap<>();
		problem.put("type", type.toString());
		problem.put("title", title);
		problem.put("status", status.value());
		problem.put("detail", detail);
		try {
			problem.put("instance", URI.create(request.getRequestURI()).toString());
		}
		catch (IllegalArgumentException ex) {
			// Omit an unparseable request URI rather than echoing it.
		}
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
		jsonMapper.writeValue(response.getOutputStream(), problem);
	}

}

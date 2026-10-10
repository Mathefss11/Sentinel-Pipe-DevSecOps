package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.security.DomainApiExposureGuard;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * With the default configuration (no profile, no override) the domain API does not exist:
 * no controller is registered, no token decoder is configured, and every non-health
 * request is denied by the security filter chain, even with a syntactically valid token.
 */
class DomainApiDisabledByDefaultIntegrationTests extends AbstractIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ApplicationContext context;

	@Autowired
	@Qualifier("requestMappingHandlerMapping")
	private RequestMappingHandlerMapping handlerMapping;

	@Test
	void noDomainRouteOrAuthenticationMechanismIsRegistered() {
		assertThat(this.handlerMapping.getHandlerMethods().keySet())
			.flatExtracting((info) -> info.getPatternValues())
			.noneMatch((pattern) -> pattern.startsWith("/api/"));
		assertThat(this.context.getBeanNamesForType(DomainApiExposureGuard.class)).isEmpty();
		assertThat(this.context.getBeanNamesForType(JwtDecoder.class)).isEmpty();
	}

	@Test
	void domainEndpointsAreDenied() throws Exception {
		UUID id = UUID.randomUUID();
		String token = TestJwts.bearer(TestJwts.PLATFORM_ADMIN);
		this.mockMvc
			.perform(post("/api/v1/organizations").header(HttpHeaders.AUTHORIZATION, token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"name\": \"x\", \"slug\": \"x\"}"))
			.andExpect(status().isForbidden())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:forbidden"));
		for (String path : new String[] { "/api/v1/me", "/api/v1/organizations/" + id,
				"/api/v1/organizations/" + id + "/projects", "/api/v1/organizations/" + id + "/members",
				"/api/v1/projects/" + id, "/api/v1/projects/" + id + "/scans", "/api/v1/scans/" + id }) {
			this.mockMvc.perform(get(path).header(HttpHeaders.AUTHORIZATION, token)).andExpect(status().isForbidden());
			this.mockMvc.perform(get(path)).andExpect(status().isForbidden());
		}
	}

}

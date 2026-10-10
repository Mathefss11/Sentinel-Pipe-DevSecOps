package dev.sentinelpipe.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.security.DomainApiExposureGuard;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * With the default configuration (no profile, no override) the unauthenticated domain API
 * does not exist: no controller is registered and every route returns 404.
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
	void noDomainRouteIsRegistered() {
		assertThat(this.handlerMapping.getHandlerMethods().keySet())
			.flatExtracting((info) -> info.getPatternValues())
			.noneMatch((pattern) -> pattern.startsWith("/api/"));
		assertThat(this.context.getBeanNamesForType(DomainApiExposureGuard.class)).isEmpty();
	}

	@Test
	void domainEndpointsAreNotFound() throws Exception {
		UUID id = UUID.randomUUID();
		this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
				.content("{\"name\": \"x\", \"slug\": \"x\"}"))
			.andExpect(status().isNotFound());
		this.mockMvc.perform(get("/api/v1/organizations/{id}", id)).andExpect(status().isNotFound());
		this.mockMvc.perform(get("/api/v1/organizations/{id}/projects", id)).andExpect(status().isNotFound());
		this.mockMvc.perform(get("/api/v1/projects/{id}", id)).andExpect(status().isNotFound());
		this.mockMvc
			.perform(post("/api/v1/projects/{id}/scans", id).contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isNotFound());
		this.mockMvc.perform(get("/api/v1/scans/{id}", id)).andExpect(status().isNotFound());
	}

}

package dev.sentinelpipe.api.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.common.ConflictException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

class OrganizationApiIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private OrganizationService organizationService;

	@Test
	void createsOrganizationWithLocationAndServerGeneratedFields() throws Exception {
		String slug = uniqueSlug("acme");

		MvcResult result = this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "  Acme Security  ", "slug": "%s"}
						""".formatted(slug)))
			.andExpect(status().isCreated())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andExpect(jsonPath("$.name").value("Acme Security"))
			.andExpect(jsonPath("$.slug").value(slug))
			.andExpect(jsonPath("$.createdAt").isString())
			.andReturn();
		String id = json(result).get("id").asString();

		assertThat(result.getResponse().getHeader("Location")).isEqualTo("/api/v1/organizations/" + id);
		this.mockMvc.perform(get("/api/v1/organizations/{id}", id))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.id").value(id))
			.andExpect(jsonPath("$.createdAt").value(json(result).get("createdAt").asString()));
	}

	@Test
	void rejectsDuplicateSlugWithConflict() throws Exception {
		String slug = uniqueSlug("dup");
		String body = """
				{"name": "First", "slug": "%s"}
				""".formatted(slug);
		this.mockMvc.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated());

		this.mockMvc.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isConflict())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:conflict"))
			.andExpect(jsonPath("$.status").value(409))
			.andExpect(jsonPath("$.code").value("organization-slug-taken"));
	}

	@Test
	void concurrentCreationWithTheSameSlugCreatesExactlyOneOrganization() throws Exception {
		String slug = uniqueSlug("race");
		int threads = 8;
		List<Callable<Boolean>> attempts = new ArrayList<>();
		for (int i = 0; i < threads; i++) {
			attempts.add(() -> {
				try {
					this.organizationService.create("Race", slug);
					return true;
				}
				catch (ConflictException ex) {
					return false;
				}
			});
		}

		int created = 0;
		try (ExecutorService executor = Executors.newFixedThreadPool(threads)) {
			for (Future<Boolean> outcome : executor.invokeAll(attempts)) {
				created += outcome.get() ? 1 : 0;
			}
		}

		assertThat(created).isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM organizations WHERE slug = ?", Integer.class,
				slug))
			.isEqualTo(1);
	}

	@Test
	void reportsAllInvalidFieldsAsProblemDetails() throws Exception {
		this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "", "slug": "Not A Slug"}
						"""))
			.andExpect(status().isBadRequest())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:validation-error"))
			.andExpect(jsonPath("$.title").value("Validation failed"))
			.andExpect(jsonPath("$.instance").value("/api/v1/organizations"))
			.andExpect(jsonPath("$.errors[*].field").value(org.hamcrest.Matchers.hasItems("name", "slug")))
			// The rejected value is never echoed back.
			.andExpect(content().string(not(containsString("Not A Slug"))));
	}

	@Test
	void rejectsControlCharactersInNames() throws Exception {
		this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"name": "evil\\nname", "slug": "%s"}
						""".formatted(uniqueSlug("ctl"))))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[0].field").value("name"));
	}

	@Test
	void rejectsClientSuppliedIdentifiersAndUnknownProperties() throws Exception {
		this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"id": "%s", "name": "Acme", "slug": "%s"}
						""".formatted(UUID.randomUUID(), uniqueSlug("id"))))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:malformed-request"));
	}

	@Test
	void rejectsMalformedJsonWithoutLeakingParserDetails() throws Exception {
		this.mockMvc
			.perform(post("/api/v1/organizations").contentType(MediaType.APPLICATION_JSON).content("{\"name\": "))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:malformed-request"))
			.andExpect(content().string(not(containsString("jackson"))))
			.andExpect(content().string(not(containsString("Exception"))));
	}

	@Test
	void rejectsNonJsonContentType() throws Exception {
		this.mockMvc.perform(post("/api/v1/organizations").contentType(MediaType.TEXT_PLAIN).content("name=acme"))
			.andExpect(status().isUnsupportedMediaType());
	}

	@Test
	void unknownOrganizationIsNotFound() throws Exception {
		this.mockMvc.perform(get("/api/v1/organizations/{id}", UUID.randomUUID()))
			.andExpect(status().isNotFound())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
			.andExpect(jsonPath("$.type").value("urn:sentinelpipe:problem:not-found"));
	}

	@Test
	void malformedIdentifierIsABadRequestThatDoesNotEchoTheInput() throws Exception {
		this.mockMvc.perform(get("/api/v1/organizations/{id}", "<script>alert(1)"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[0].field").value("organizationId"))
			.andExpect(jsonPath("$.errors[0].message").value(not(containsString("script"))))
			.andExpect(jsonPath("$.detail").value(not(containsString("script"))))
			// `instance` is the request URI (RFC 9457) and stays percent-encoded.
			.andExpect(content().string(not(containsString("<"))));
	}

	@Test
	void responsesDoNotExposeInternalFields() throws Exception {
		MvcResult result = this.mockMvc.perform(get("/api/v1/organizations/{id}", createOrganization()))
			.andExpect(status().isOk())
			.andReturn();

		assertThat(json(result).properties().stream().map(Map.Entry::getKey)).containsExactlyInAnyOrder("id", "name",
				"slug", "createdAt", "updatedAt");
	}

}

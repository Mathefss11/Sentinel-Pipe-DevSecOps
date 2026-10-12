package dev.sentinelpipe.api.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import dev.sentinelpipe.api.policy.PolicyFixtures;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * Discovers every registered {@code /api} operation and verifies that it is protected.
 * A new endpoint added without authentication or tenant authorization fails this test.
 */
class EndpointProtectionCoverageTests extends AbstractDomainApiIntegrationTest {

	/** Operations that any authenticated caller may use, with the reason. */
	private static final Set<String> CALLER_SCOPED = Set.of("GET /api/v1/me");

	@Autowired
	@Qualifier("requestMappingHandlerMapping")
	private RequestMappingHandlerMapping handlerMapping;

	private Map<String, String> pathVariables;

	private UUID foreignPolicyVersionId;

	@BeforeEach
	void foreignResources() throws Exception {
		// Real resources owned by the platform admin's organization; the outsider is no member.
		UUID organizationId = createOrganization();
		UUID projectId = createProject(organizationId, "covered");
		UUID scanId = UUID.fromString(json(requestScan(projectId, randomSha(), null)).get("id").asString());
		UUID membershipId = grant(organizationId, uniqueSubject("m"), "MEMBER");
		UUID policyVersionId = UUID.fromString(json(postJson("/api/v1/organizations/" + organizationId + "/policies",
				PolicyFixtures.gitleaksOnly("covered"))).get("id").asString());
		this.pathVariables = Map.of("organizationId", organizationId.toString(), "projectId", projectId.toString(),
				"scanId", scanId.toString(), "membershipId", membershipId.toString(), "policyVersionId",
				policyVersionId.toString(), "evaluationId", UUID.randomUUID().toString(), "exceptionId",
				UUID.randomUUID().toString());
		this.foreignPolicyVersionId = policyVersionId;
	}

	private List<String[]> operations() {
		List<String[]> operations = new ArrayList<>();
		for (RequestMappingInfo info : this.handlerMapping.getHandlerMethods().keySet()) {
			for (String pattern : info.getPatternValues()) {
				if (pattern.startsWith("/api/")) {
					info.getMethodsCondition()
						.getMethods()
						.forEach((method) -> operations.add(new String[] { method.name(), pattern }));
				}
			}
		}
		return operations;
	}

	private String expand(String pattern) {
		String path = pattern;
		for (Map.Entry<String, String> variable : this.pathVariables.entrySet()) {
			path = path.replace("{" + variable.getKey() + "}", variable.getValue());
		}
		assertThat(path).as("unknown path variable in %s", pattern).doesNotContain("{");
		return path;
	}

	private int status(String method, String path, String authorization) throws Exception {
		var builder = request(HttpMethod.valueOf(method), path).contentType(MediaType.APPLICATION_JSON)
			.content(bodyFor(method, path));
		if (authorization != null) {
			builder.header(HttpHeaders.AUTHORIZATION, authorization);
		}
		return this.anonymousMvc.perform(builder).andReturn().getResponse().getStatus();
	}

	/** Valid bodies, so that authorization rather than validation decides the outcome. */
	private String bodyFor(String method, String path) {
		if (method.equals("POST") && path.endsWith("/policies")) {
			return PolicyFixtures.gitleaksOnly("intruder");
		}
		if (method.equals("POST") && path.endsWith("/reevaluations")) {
			return "{\"policyVersionId\": \"%s\"}".formatted(this.foreignPolicyVersionId);
		}
		if (method.equals("POST") && path.endsWith("/exceptions")) {
			return """
					{"scanner": "GITLEAKS", "findingFingerprint": "%s", "justification": "an intruder justification",
					 "expiresAt": "%s"}""".formatted("a".repeat(64), Instant.now().plusSeconds(86400));
		}
		if (method.equals("POST") && path.matches(".*/exceptions/[^/]+/(approve|reject|withdraw|revoke)")) {
			return "{\"rationale\": \"intruder\"}";
		}
		if (method.equals("PUT") && path.endsWith("/policy")) {
			return "{\"policyVersionId\": \"%s\"}".formatted(this.foreignPolicyVersionId);
		}
		if (method.equals("POST") && path.endsWith("/organizations")) {
			return "{\"name\": \"x\", \"slug\": \"cov-%s\"}".formatted(UUID.randomUUID().toString().substring(0, 8));
		}
		if (method.equals("POST") && path.endsWith("/projects")) {
			return """
					{"name": "x", "repositoryProvider": "GITHUB", "repositoryOwner": "x", "repositoryName": "x",
					 "defaultBranch": "main"}""";
		}
		if (method.equals("POST") && path.endsWith("/scans")) {
			return "{\"commitSha\": \"%s\", \"branch\": \"main\", \"triggerType\": \"PUSH\"}".formatted(randomSha());
		}
		if (method.equals("POST") && path.endsWith("/members")) {
			return "{\"subject\": \"intruder\", \"role\": \"OWNER\"}";
		}
		if (method.equals("PUT")) {
			return "{\"role\": \"OWNER\"}";
		}
		return "";
	}

	@Test
	void everyOperationRequiresAuthentication() throws Exception {
		List<String[]> operations = operations();
		assertThat(operations).hasSizeGreaterThanOrEqualTo(19);
		for (String[] operation : operations) {
			assertThat(status(operation[0], expand(operation[1]), null)).as("%s %s without token", operation[0],
					operation[1])
				.isEqualTo(401);
			assertThat(status(operation[0], expand(operation[1]), "Bearer " + TestJwts.unsigned("x")))
				.as("%s %s with unsigned token", operation[0], operation[1])
				.isEqualTo(401);
		}
	}

	@Test
	void everyTenantOperationIsDeniedToAuthenticatedOutsiders() throws Exception {
		String outsider = TestJwts.bearer(uniqueSubject("outsider"));
		for (String[] operation : operations()) {
			String key = operation[0] + " " + operation[1];
			int status = status(operation[0], expand(operation[1]), outsider);
			if (CALLER_SCOPED.contains(key)) {
				assertThat(status).as(key).isEqualTo(200);
			}
			else {
				assertThat(status).as("%s as an authenticated non-member", key).isIn(403, 404);
			}
		}
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM user_identities u JOIN organization_memberships m ON m.user_identity_id = u.id "
						+ "WHERE u.subject = 'intruder'",
				Integer.class))
			.isZero();
		// No policy was created or activated by the outsider.
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.policies WHERE name = 'intruder'",
				Integer.class))
			.isZero();
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.project_assignments WHERE project_id = ?",
				Integer.class, UUID.fromString(this.pathVariables.get("projectId"))))
			.isZero();
		// No security exception was requested or decided by the outsider.
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.exception_requests WHERE scan_id = ?",
				Integer.class, UUID.fromString(this.pathVariables.get("scanId"))))
			.isZero();
		// No historical re-evaluation was recorded for the outsider.
		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM policy.historical_evaluations WHERE scan_id = ?",
				Integer.class, UUID.fromString(this.pathVariables.get("scanId"))))
			.isZero();
	}

}

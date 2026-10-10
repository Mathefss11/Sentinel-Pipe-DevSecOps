package dev.sentinelpipe.api.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.TestJwts;
import dev.sentinelpipe.api.identity.AuthenticatedPrincipal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Membership management, role escalation and last-owner protection. */
class MembershipManagementIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private MembershipService membershipService;

	private UUID organizationId;

	@BeforeEach
	void organization() throws Exception {
		this.organizationId = createOrganization();
	}

	private ResultActions as(String subject, MockHttpServletRequestBuilder request) throws Exception {
		return this.mockMvc.perform(request.header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(subject)));
	}

	private MockHttpServletRequestBuilder grantRequest(String subject, String role) {
		return post("/api/v1/organizations/{id}/members", this.organizationId).contentType(MediaType.APPLICATION_JSON)
			.content("{\"subject\": \"%s\", \"role\": \"%s\"}".formatted(subject, role));
	}

	private MockHttpServletRequestBuilder changeRequest(UUID membershipId, String role) {
		return put("/api/v1/organizations/{o}/members/{m}", this.organizationId, membershipId)
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"role\": \"%s\"}".formatted(role));
	}

	private String roleOf(UUID membershipId) {
		return this.jdbcTemplate.queryForObject("SELECT role FROM organization_memberships WHERE id = ?", String.class,
				membershipId);
	}

	private UUID ownMembershipId(String subject) {
		return this.jdbcTemplate.queryForObject("""
				SELECT m.id FROM organization_memberships m JOIN user_identities u ON u.id = m.user_identity_id
				WHERE m.organization_id = ? AND u.subject = ?
				""", UUID.class, this.organizationId, subject);
	}

	@Test
	void ownerManagesTheFullMembershipLifecycle() throws Exception {
		String subject = uniqueSubject("dev");

		String body = this.mockMvc.perform(grantRequest(subject, "MEMBER"))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.organizationId").value(this.organizationId.toString()))
			.andExpect(jsonPath("$.issuer").value(TestJwts.ISSUER))
			.andExpect(jsonPath("$.subject").value(subject))
			.andExpect(jsonPath("$.role").value("MEMBER"))
			.andReturn()
			.getResponse()
			.getContentAsString();
		UUID membershipId = UUID.fromString(this.jsonMapper.readTree(body).get("id").asString());

		this.mockMvc.perform(get("/api/v1/organizations/{o}/members/{m}", this.organizationId, membershipId))
			.andExpect(status().isOk());
		this.mockMvc.perform(changeRequest(membershipId, "ADMIN"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.role").value("ADMIN"));
		this.mockMvc.perform(get("/api/v1/organizations/{id}/members", this.organizationId).param("size", "1"))
			.andExpect(jsonPath("$.items[0].role").value("OWNER"))
			.andExpect(jsonPath("$.page.totalElements").value(2));
		this.mockMvc.perform(delete("/api/v1/organizations/{o}/members/{m}", this.organizationId, membershipId))
			.andExpect(status().isNoContent());

		as(subject, get("/api/v1/organizations/{id}", this.organizationId)).andExpect(status().isNotFound());
	}

	@Test
	void duplicateMembershipIsAConflict() throws Exception {
		String subject = uniqueSubject("dup");
		grant(this.organizationId, subject, "VIEWER");

		this.mockMvc.perform(grantRequest(subject, "ADMIN"))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("membership-already-exists"));
	}

	@ParameterizedTest(name = "ADMIN grants {0}: {1}")
	@CsvSource({ "OWNER, 403", "ADMIN, 403", "MEMBER, 201", "VIEWER, 201" })
	void adminsCanOnlyGrantMemberAndViewer(String role, int expectedStatus) throws Exception {
		String admin = uniqueSubject("admin");
		grant(this.organizationId, admin, "ADMIN");

		as(admin, grantRequest(uniqueSubject("target"), role)).andExpect(status().is(expectedStatus));
	}

	@Test
	void adminsCannotModifyOrRemoveOwnersOrOtherAdmins() throws Exception {
		String admin = uniqueSubject("admin");
		grant(this.organizationId, admin, "ADMIN");
		UUID otherAdmin = grant(this.organizationId, uniqueSubject("admin2"), "ADMIN");
		UUID owner = ownMembershipId(TestJwts.PLATFORM_ADMIN);
		UUID member = grant(this.organizationId, uniqueSubject("member"), "MEMBER");

		as(admin, changeRequest(otherAdmin, "VIEWER")).andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("role-escalation"));
		as(admin, changeRequest(owner, "VIEWER")).andExpect(status().isForbidden());
		as(admin, delete("/api/v1/organizations/{o}/members/{m}", this.organizationId, owner))
			.andExpect(status().isForbidden());
		as(admin, changeRequest(member, "ADMIN")).andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("role-escalation"));
		as(admin, changeRequest(member, "VIEWER")).andExpect(status().isOk());

		assertThat(roleOf(otherAdmin)).isEqualTo("ADMIN");
		assertThat(roleOf(owner)).isEqualTo("OWNER");
		assertThat(roleOf(member)).isEqualTo("VIEWER");
	}

	@ParameterizedTest
	@CsvSource({ "ADMIN, OWNER", "MEMBER, ADMIN", "VIEWER, MEMBER", "OWNER, VIEWER" })
	void nobodyCanChangeOrRevokeTheirOwnMembership(String role, String requested) throws Exception {
		String subject = uniqueSubject("self");
		UUID own = grant(this.organizationId, subject, role);

		as(subject, changeRequest(own, requested)).andExpect(status().isForbidden());
		as(subject, delete("/api/v1/organizations/{o}/members/{m}", this.organizationId, own))
			.andExpect(status().isForbidden());

		assertThat(roleOf(own)).isEqualTo(role);
	}

	@Test
	void ownersCannotGrantThemselvesAgainOrDemoteThemselves() throws Exception {
		this.mockMvc.perform(grantRequest(TestJwts.PLATFORM_ADMIN, "VIEWER"))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("self-modification"));
		this.mockMvc.perform(changeRequest(ownMembershipId(TestJwts.PLATFORM_ADMIN), "VIEWER"))
			.andExpect(status().isForbidden());
	}

	@ParameterizedTest
	@CsvSource({ "MEMBER", "VIEWER" })
	void membersAndViewersCannotManageMemberships(String role) throws Exception {
		String subject = uniqueSubject("low");
		grant(this.organizationId, subject, role);
		UUID other = grant(this.organizationId, uniqueSubject("other"), "VIEWER");

		as(subject, grantRequest(uniqueSubject("x"), "VIEWER")).andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("insufficient-role"));
		as(subject, changeRequest(other, "MEMBER")).andExpect(status().isForbidden());
		as(subject, delete("/api/v1/organizations/{o}/members/{m}", this.organizationId, other))
			.andExpect(status().isForbidden());
		assertThat(roleOf(other)).isEqualTo("VIEWER");
	}

	@Test
	void grantRequestsCannotCarryIssuerOrganizationOrGrantor() throws Exception {
		for (String extra : List.of("\"issuer\": \"https://evil.example\"",
				"\"organizationId\": \"" + UUID.randomUUID() + "\"", "\"grantedBy\": \"" + UUID.randomUUID() + "\"")) {
			this.mockMvc
				.perform(post("/api/v1/organizations/{id}/members", this.organizationId)
					.contentType(MediaType.APPLICATION_JSON)
					.content("{\"subject\": \"s\", \"role\": \"VIEWER\", %s}".formatted(extra)))
				.andExpect(status().isBadRequest());
		}
		this.mockMvc.perform(grantRequest("bad\\u0000subject", "VIEWER")).andExpect(status().isBadRequest());
		this.mockMvc.perform(grantRequest("x", "SUPERUSER")).andExpect(status().isBadRequest());
	}

	@Test
	void revokedOwnerLosesAccessImmediately() throws Exception {
		String coOwner = uniqueSubject("co-owner");
		UUID membership = grant(this.organizationId, coOwner, "OWNER");
		as(coOwner, get("/api/v1/organizations/{id}", this.organizationId)).andExpect(status().isOk());

		this.mockMvc.perform(delete("/api/v1/organizations/{o}/members/{m}", this.organizationId, membership))
			.andExpect(status().isNoContent());

		as(coOwner, get("/api/v1/organizations/{id}", this.organizationId)).andExpect(status().isNotFound());
	}

	@Test
	void concurrentMutualDemotionOfTwoOwnersLeavesAnOwner() throws Exception {
		String a = uniqueSubject("owner-a");
		String b = uniqueSubject("owner-b");
		UUID membershipA = grant(this.organizationId, a, "OWNER");
		UUID membershipB = grant(this.organizationId, b, "OWNER");
		// Remove the bootstrap owner so that A and B are the only owners.
		this.mockMvc
			.perform(delete("/api/v1/organizations/{o}/members/{m}", this.organizationId,
					ownMembershipId(TestJwts.PLATFORM_ADMIN))
				.header(HttpHeaders.AUTHORIZATION, TestJwts.bearer(a)))
			.andExpect(status().isNoContent());

		CountDownLatch start = new CountDownLatch(1);
		List<Callable<Boolean>> demotions = new ArrayList<>();
		demotions.add(demotion(start, a, membershipB));
		demotions.add(demotion(start, b, membershipA));
		int succeeded = 0;
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			List<Future<Boolean>> results = demotions.stream().map(executor::submit).toList();
			start.countDown();
			for (Future<Boolean> result : results) {
				succeeded += result.get() ? 1 : 0;
			}
		}

		assertThat(succeeded).isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject(
				"SELECT count(*) FROM organization_memberships WHERE organization_id = ? AND role = 'OWNER'",
				Integer.class, this.organizationId))
			.isEqualTo(1);
	}

	@Test
	void concurrentGrantsToTheSameNewUserCreateOneIdentity() throws Exception {
		String subject = uniqueSubject("concurrent");
		AuthenticatedPrincipal owner = new AuthenticatedPrincipal(TestJwts.ISSUER, TestJwts.PLATFORM_ADMIN);
		List<UUID> organizations = new ArrayList<>();
		for (int i = 0; i < 6; i++) {
			organizations.add(createOrganization());
		}
		CountDownLatch start = new CountDownLatch(1);
		try (ExecutorService executor = Executors.newFixedThreadPool(organizations.size())) {
			List<Future<?>> grants = organizations.stream().map((organization) -> executor.submit(() -> {
				start.await();
				return this.membershipService.grant(organization, owner, subject, OrganizationRole.VIEWER);
			})).collect(java.util.stream.Collectors.toList());
			start.countDown();
			for (Future<?> grant : grants) {
				grant.get();
			}
		}

		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM user_identities WHERE subject = ?",
				Integer.class, subject))
			.isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject("""
				SELECT count(*) FROM organization_memberships m JOIN user_identities u ON u.id = m.user_identity_id
				WHERE u.subject = ?""", Integer.class, subject))
			.isEqualTo(organizations.size());
	}

	@Test
	void unauthorizedGrantAttemptsDoNotCreateIdentities() throws Exception {
		String subject = uniqueSubject("never-created");
		as(uniqueSubject("outsider"), grantRequest(subject, "OWNER")).andExpect(status().isNotFound());

		assertThat(this.jdbcTemplate.queryForObject("SELECT count(*) FROM user_identities WHERE subject = ?",
				Integer.class, subject))
			.isZero();
	}

	private Callable<Boolean> demotion(CountDownLatch start, String actor, UUID target) {
		AuthenticatedPrincipal principal = new AuthenticatedPrincipal(TestJwts.ISSUER, actor);
		return () -> {
			start.await();
			try {
				this.membershipService.changeRole(this.organizationId, target, principal, OrganizationRole.VIEWER);
				return true;
			}
			catch (RuntimeException ex) {
				// The loser was demoted first and is no longer allowed to manage owners.
				return false;
			}
		};
	}

}

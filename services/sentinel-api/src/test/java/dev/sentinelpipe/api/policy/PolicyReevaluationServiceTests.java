package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import dev.sentinelpipe.api.common.ConflictException;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.UncategorizedSQLException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * The control flow of {@link PolicyReevaluationService} around the database: a record
 * refused because the evidence changed after it was read is retried once from a fresh
 * snapshot, every other refusal is surfaced unchanged, and an unusable stored policy is a
 * request failure that records nothing. Database behavior itself is covered by
 * {@code PolicyReevaluationIntegrationTests}.
 */
class PolicyReevaluationServiceTests {

	private static final UUID SCAN = UUID.randomUUID();

	private static final UUID VERSION = UUID.randomUUID();

	private static final String ACTOR = "user:" + UUID.randomUUID();

	private final AtomicInteger reads = new AtomicInteger();

	private final AtomicInteger records = new AtomicInteger();

	private final Deque<Supplier<Map<String, Object>>> recordOutcomes = new ArrayDeque<>();

	private String definition = PolicyDocuments.parse(PolicyFixtures.gitleaksOnly("secrets")).canonical();

	private String sha256 = PolicyDocuments.parse(PolicyFixtures.gitleaksOnly("secrets")).sha256();

	private PolicyReevaluationService service() {
		JdbcTemplate jdbc = mock(JdbcTemplate.class, (invocation) -> {
			Object first = (invocation.getArguments().length > 0) ? invocation.getArgument(0) : null;
			String sql = (first instanceof String text) ? text : "";
			String method = invocation.getMethod().getName();
			if (method.equals("queryForList") && sql.contains("policy.historical_context")) {
				this.reads.incrementAndGet();
				return List.of(Map.of("scan_id", SCAN, "project_id", UUID.randomUUID(), "organization_id",
						UUID.randomUUID(), "commit_sha", "a".repeat(40), "execution_status", "COMPLETED",
						"evaluated_as_of", Timestamp.from(Instant.parse("2026-10-11T12:00:00Z")), "inputs_sha256",
						"b".repeat(64)));
			}
			if (method.equals("queryForList") && sql.contains("policy.policy_versions")) {
				return List.of(Map.of("definition", this.definition, "definition_sha256", this.sha256));
			}
			if (method.equals("queryForMap") && sql.contains("policy.record_historical_evaluation")) {
				this.records.incrementAndGet();
				return this.recordOutcomes.removeFirst().get();
			}
			return null;
		});
		return new PolicyReevaluationService(jdbc, new PolicyEvaluationService(jdbc),
				mock(PlatformTransactionManager.class));
	}

	private static Supplier<Map<String, Object>> rejected(String code) {
		return () -> {
			throw new UncategorizedSQLException("record", "SELECT",
					new SQLException("ERROR: evaluation rejected: " + code, "22023"));
		};
	}

	private static Supplier<Map<String, Object>> outcome(String outcome, UUID id) {
		return () -> Map.of("outcome", outcome, "evaluation_id", id);
	}

	@Test
	void evidenceThatChangedAfterReadingIsReadAgainOnceFromAFreshSnapshot() {
		UUID id = UUID.randomUUID();
		this.recordOutcomes.add(rejected("INPUTS_CHANGED"));
		this.recordOutcomes.add(outcome("RECORDED", id));

		PolicyReevaluationService.Result result = service().reevaluate(SCAN, VERSION, ACTOR);

		assertThat(result).isEqualTo(new PolicyReevaluationService.Result(PolicyReevaluationService.Outcome.RECORDED, id));
		assertThat(this.reads).hasValue(2);
		assertThat(this.records).hasValue(2);
	}

	@Test
	void evidenceThatKeepsChangingIsAnExplicitConflict() {
		this.recordOutcomes.add(rejected("INPUTS_CHANGED"));
		this.recordOutcomes.add(rejected("INPUTS_CHANGED"));

		assertThatThrownBy(() -> service().reevaluate(SCAN, VERSION, ACTOR)).isInstanceOf(ConflictException.class)
			.extracting((ex) -> ((ConflictException) ex).getCode())
			.isEqualTo(PolicyReevaluationService.INPUTS_CHANGED);
		assertThat(this.records).hasValue(2);
	}

	@Test
	void anyOtherRefusalIsNeverRetriedOrHidden() {
		this.recordOutcomes.add(rejected("NONDETERMINISTIC"));

		assertThatThrownBy(() -> service().reevaluate(SCAN, VERSION, ACTOR))
			.isInstanceOf(UncategorizedSQLException.class)
			.hasStackTraceContaining("NONDETERMINISTIC");
		assertThat(this.records).hasValue(1);
	}

	@Test
	void anExistingIdentityIsReportedAsSuch() {
		UUID id = UUID.randomUUID();
		this.recordOutcomes.add(outcome("EXISTING", id));

		assertThat(service().reevaluate(SCAN, VERSION, ACTOR).outcome())
			.isEqualTo(PolicyReevaluationService.Outcome.EXISTING);
	}

	@Test
	void aStoredPolicyThatNoLongerMatchesItsDigestRecordsNothing() {
		this.sha256 = "c".repeat(64);

		assertThatThrownBy(() -> service().reevaluate(SCAN, VERSION, ACTOR)).isInstanceOf(ConflictException.class)
			.extracting((ex) -> ((ConflictException) ex).getCode())
			.isEqualTo(PolicyReevaluationService.POLICY_VERSION_UNUSABLE);
		assertThat(this.records).hasValue(0);
	}

}

package dev.sentinelpipe.api.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import dev.sentinelpipe.api.common.ConflictException;
import dev.sentinelpipe.api.common.DomainValidationException;
import dev.sentinelpipe.api.common.ForbiddenException;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.UncategorizedSQLException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * The control flow of {@link ExceptionRequestService} around the database (ADR-0015): the
 * application refuses self-decisions before calling the database, and refusals the database
 * raises after its function's checks passed (security review M4P3-1, M4P3-2) are client
 * conditions, never server errors. Database behavior itself is covered by
 * {@code SecurityExceptionIntegrationTests}.
 */
class ExceptionRequestServiceTests {

	private static final UUID SCAN = UUID.randomUUID();

	private static final UUID EXCEPTION = UUID.randomUUID();

	private static final String REQUESTER = "user:" + UUID.randomUUID();

	private static final String OWNER = "user:" + UUID.randomUUID();

	private final AtomicInteger transitions = new AtomicInteger();

	private ExceptionRequestService service(Supplier<String> transitionOutcome) {
		ExceptionRequestService.ExceptionRecord record = new ExceptionRequestService.ExceptionRecord(EXCEPTION, SCAN,
				UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "a".repeat(64),
				PolicyEvaluator.ENGINE_VERSION, UUID.randomUUID(), "GITLEAKS", 1, "b".repeat(64), "c".repeat(64),
				"d".repeat(64), "github-pat", "SECRET", null, "A justification of sufficient length.", REQUESTER,
				Instant.now(), Instant.now().plusSeconds(86400), "APPROVED", "ACTIVE", Instant.now(), List.of());
		JdbcTemplate jdbc = mock(JdbcTemplate.class, (invocation) -> {
			Object first = (invocation.getArguments().length > 0) ? invocation.getArgument(0) : null;
			String sql = (first instanceof String text) ? text : "";
			String method = invocation.getMethod().getName();
			if (method.equals("query") && sql.contains("FROM policy.exception_status")) {
				return List.of(record);
			}
			if (method.equals("queryForObject") && sql.contains("policy.transition_exception")) {
				this.transitions.incrementAndGet();
				return transitionOutcome.get();
			}
			return null;
		});
		return new ExceptionRequestService(jdbc, mock(OriginalEvaluationVerifier.class),
				mock(PlatformTransactionManager.class));
	}

	private static Supplier<String> violates(String constraint) {
		return () -> {
			throw new DataIntegrityViolationException("transition", new SQLException(
					"ERROR: new row for relation \"exception_transitions\" violates check constraint \"" + constraint
							+ "\"",
					"23514"));
		};
	}

	@Test
	void anExpiryPassingDuringTheTransitionIsAConflictNotAServerError() {
		ExceptionRequestService service = service(violates("ck_exception_transitions_before_expiry"));

		assertThatThrownBy(() -> service.transition(SCAN, EXCEPTION, ExceptionRequestService.Action.REVOKE, OWNER,
				"ok"))
			.isInstanceOf(ConflictException.class)
			.extracting((ex) -> ((ConflictException) ex).getCode())
			.isEqualTo(ExceptionRequestService.EXPIRED);
	}

	@Test
	void anApprovalWindowClosingDuringTheTransitionIsAConflict() {
		ExceptionRequestService service = service(violates("ck_exception_transitions_approval_window"));

		assertThatThrownBy(() -> service.transition(SCAN, EXCEPTION, ExceptionRequestService.Action.REVOKE, OWNER,
				"ok"))
			.isInstanceOf(ConflictException.class)
			.extracting((ex) -> ((ConflictException) ex).getCode())
			.isEqualTo(ExceptionRequestService.EXPIRES_TOO_SOON);
	}

	@Test
	void textTheDatabaseRefusesIsAValidationErrorAndOtherRefusalsAreNeverHidden() {
		ExceptionRequestService invalid = service(() -> {
			throw new UncategorizedSQLException("transition", "SELECT",
					new SQLException("ERROR: exception rejected: INVALID_ARGUMENTS", "22023"));
		});
		assertThatThrownBy(() -> invalid.transition(SCAN, EXCEPTION, ExceptionRequestService.Action.REVOKE, OWNER,
				"ok"))
			.isInstanceOf(DomainValidationException.class)
			.extracting((ex) -> ((DomainValidationException) ex).getField())
			.isEqualTo("rationale");

		ExceptionRequestService other = service(violates("pk_exception_transitions"));
		assertThatThrownBy(() -> other.transition(SCAN, EXCEPTION, ExceptionRequestService.Action.REVOKE, OWNER, "ok"))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void theRequesterIsRefusedBeforeTheDatabaseIsCalled() {
		ExceptionRequestService service = service(() -> "TRANSITIONED");

		for (ExceptionRequestService.Action action : List.of(ExceptionRequestService.Action.APPROVE,
				ExceptionRequestService.Action.REJECT)) {
			assertThatThrownBy(() -> service.transition(SCAN, EXCEPTION, action, REQUESTER, "self"))
				.isInstanceOf(ForbiddenException.class)
				.extracting((ex) -> ((ForbiddenException) ex).getCode())
				.isEqualTo(ExceptionRequestService.SELF_DECISION);
		}
		assertThatThrownBy(() -> service.transition(SCAN, EXCEPTION, ExceptionRequestService.Action.WITHDRAW, OWNER,
				"not mine"))
			.isInstanceOf(ForbiddenException.class);
		assertThat(this.transitions).hasValue(0);
	}

}

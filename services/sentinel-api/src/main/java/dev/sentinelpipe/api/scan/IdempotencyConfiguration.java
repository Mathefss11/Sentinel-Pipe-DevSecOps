package dev.sentinelpipe.api.scan;

import io.micrometer.core.instrument.MeterRegistry;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(IdempotencyProperties.class)
class IdempotencyConfiguration {

	@Bean
	IdempotencyKeyCleanup idempotencyKeyCleanup(NamedParameterJdbcTemplate jdbc,
			PlatformTransactionManager transactionManager, IdempotencyProperties properties, Clock clock,
			MeterRegistry registry) {
		return new IdempotencyKeyCleanup(jdbc, transactionManager, properties, clock, registry);
	}

	/** Periodic cleanup; disable to run it elsewhere (or in tests). */
	@Configuration(proxyBeanMethods = false)
	@EnableScheduling
	@ConditionalOnBooleanProperty(name = "sentinel.idempotency.cleanup-enabled", matchIfMissing = true)
	static class IdempotencyKeyCleanupScheduler {

		private static final Logger log = LoggerFactory.getLogger(IdempotencyKeyCleanupScheduler.class);

		private final IdempotencyKeyCleanup cleanup;

		IdempotencyKeyCleanupScheduler(IdempotencyKeyCleanup cleanup) {
			this.cleanup = cleanup;
		}

		@Scheduled(fixedDelayString = "${sentinel.idempotency.cleanup-interval:10m}",
				initialDelayString = "${sentinel.idempotency.cleanup-interval:10m}")
		void releaseExpiredKeys() {
			try {
				this.cleanup.run();
			}
			catch (RuntimeException ex) {
				// Typically the database is unavailable; the next run retries.
				log.warn("idempotency.cleanup_failed error_type={}", ex.getClass().getSimpleName());
			}
		}

	}

}

package dev.sentinelpipe.api.scan;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ExecutionProperties.class)
class ExecutionConfiguration {

	private static final Logger log = LoggerFactory.getLogger(ExecutionConfiguration.class);

	ExecutionConfiguration(ExecutionProperties properties, Environment environment) {
		// Fails startup on invalid limits, unsupported planned scanners, or the execution
		// fixture under a production profile.
		properties.validate(environment.getActiveProfiles());
		if (properties.isFixtureEnabled()) {
			log.warn("The harmless FIXTURE scanner is enabled (sentinel.execution.fixture-enabled=true). "
					+ "Intended for development, CI and tests only.");
		}
	}

	@Bean
	ExecutionSupervisor executionSupervisor(JdbcTemplate jdbc, ScanLifecycleService lifecycle,
			ExecutionProperties properties, MeterRegistry registry) {
		return new ExecutionSupervisor(jdbc, lifecycle, properties, registry);
	}

	/** Periodic supervisor; disable to run it elsewhere (or drive it explicitly in tests). */
	@Configuration(proxyBeanMethods = false)
	@EnableScheduling
	@ConditionalOnBooleanProperty(name = "sentinel.execution.supervisor.enabled", matchIfMissing = true)
	static class ExecutionSupervisorScheduler {

		private static final Logger log = LoggerFactory.getLogger(ExecutionSupervisorScheduler.class);

		private final ExecutionSupervisor supervisor;

		ExecutionSupervisorScheduler(ExecutionSupervisor supervisor) {
			this.supervisor = supervisor;
		}

		@Scheduled(fixedDelayString = "${sentinel.execution.supervisor.interval:5s}",
				initialDelayString = "${sentinel.execution.supervisor.interval:5s}")
		void supervise() {
			try {
				this.supervisor.runOnce();
			}
			catch (RuntimeException ex) {
				// Typically the database is unavailable. Nothing is lost: leases and deadlines
				// are evaluated against the database clock on the next pass.
				log.warn("execution.supervisor_failed error_type={}", ex.getClass().getSimpleName());
			}
		}

	}

}

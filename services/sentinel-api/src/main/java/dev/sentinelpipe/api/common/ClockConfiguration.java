package dev.sentinelpipe.api.common;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class ClockConfiguration {

	/** All domain timestamps are generated server-side in UTC. */
	@Bean
	Clock clock() {
		return Clock.systemUTC();
	}

}

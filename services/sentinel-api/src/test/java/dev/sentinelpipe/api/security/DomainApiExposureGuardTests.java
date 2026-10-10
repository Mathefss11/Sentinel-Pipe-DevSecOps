package dev.sentinelpipe.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class DomainApiExposureGuardTests {

	private static final String[] NO_PROFILES = {};

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
		.withUserConfiguration(DomainApiExposureGuard.class);

	@ParameterizedTest
	@ValueSource(strings = { "127.0.0.1", "127.1.2.3", "::1", "[::1]", "0:0:0:0:0:0:0:1" })
	void acceptsLiteralLoopbackAddresses(String address) {
		assertThatCode(() -> DomainApiExposureGuard.verify(address, NO_PROFILES)).doesNotThrowAnyException();
	}

	@ParameterizedTest
	@ValueSource(strings = { "0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "localhost", "example.com", "128.0.0.1",
			"127.0.0.256", "127.0.0", "1.127.0.0.1", "" })
	void rejectsNonLoopbackOrNonLiteralAddresses(String address) {
		assertThatThrownBy(() -> DomainApiExposureGuard.verify(address, NO_PROFILES))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void rejectsMissingServerAddressBecauseTheDefaultBindsAllInterfaces() {
		assertThatThrownBy(() -> DomainApiExposureGuard.verify(null, NO_PROFILES))
			.isInstanceOf(IllegalStateException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "prod", "production", "PROD", "Production" })
	void rejectsProductionProfilesEvenOnLoopback(String profile) {
		assertThatThrownBy(() -> DomainApiExposureGuard.verify("127.0.0.1", new String[] { "local", profile }))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void guardIsInactiveWhenDomainApiIsDisabled() {
		this.contextRunner.withPropertyValues("server.address=0.0.0.0")
			.run((context) -> assertThat(context).hasNotFailed().doesNotHaveBean(DomainApiExposureGuard.class));
	}

	@Test
	void contextFailsWhenEnabledWithoutLoopbackBinding() {
		this.contextRunner.withPropertyValues("sentinel.domain-api.enabled=true", "server.address=0.0.0.0")
			.run((context) -> assertThat(context).hasFailed());
		this.contextRunner.withPropertyValues("sentinel.domain-api.enabled=true")
			.run((context) -> assertThat(context).hasFailed());
	}

	@Test
	void contextStartsWhenEnabledOnLoopback() {
		this.contextRunner.withPropertyValues("sentinel.domain-api.enabled=true", "server.address=127.0.0.1")
			.run((context) -> assertThat(context).hasNotFailed().hasSingleBean(DomainApiExposureGuard.class));
	}

}

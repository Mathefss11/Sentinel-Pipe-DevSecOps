package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class OutboxPublisherSettingsTests {

	private static OutboxPublisher publisher(MessagingProperties.Outbox settings) {
		return new OutboxPublisher(null, null, OutboxRoutes.standard(), settings, null, "unit");
	}

	@Test
	void retryDelayGrowsExponentiallyAndIsCapped() {
		MessagingProperties.Outbox settings = new MessagingProperties.Outbox();
		settings.setBackoffInitial(Duration.ofSeconds(2));
		settings.setBackoffMax(Duration.ofSeconds(60));
		OutboxPublisher publisher = publisher(settings);

		assertThat(publisher.retryDelay(1)).isEqualTo(Duration.ofSeconds(2));
		assertThat(publisher.retryDelay(2)).isEqualTo(Duration.ofSeconds(4));
		assertThat(publisher.retryDelay(3)).isEqualTo(Duration.ofSeconds(8));
		assertThat(publisher.retryDelay(5)).isEqualTo(Duration.ofSeconds(32));
		assertThat(publisher.retryDelay(6)).isEqualTo(Duration.ofSeconds(60));
		assertThat(publisher.retryDelay(1000)).isEqualTo(Duration.ofSeconds(60));
	}

	private static void assertRejected(Consumer<MessagingProperties.Outbox> change) {
		MessagingProperties.Outbox settings = new MessagingProperties.Outbox();
		change.accept(settings);
		assertThatThrownBy(() -> publisher(settings)).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void unsafeSettingsFailFast() {
		assertRejected((s) -> s.setBatchSize(0));
		assertRejected((s) -> s.setBatchSize(501));
		assertRejected((s) -> s.setMaxAttempts(0));
		assertRejected((s) -> s.setBackoffInitial(Duration.ZERO));
		assertRejected((s) -> s.setBackoffMax(Duration.ofMillis(1)));
		assertRejected((s) -> s.setConfirmTimeout(Duration.ZERO));
		// A lease shorter than two confirm timeouts could expire while still publishing.
		assertRejected((s) -> s.setLeaseDuration(Duration.ofSeconds(15)));
	}

}

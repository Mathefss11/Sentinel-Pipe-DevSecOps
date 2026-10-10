package dev.sentinelpipe.api.messaging;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Messaging and transactional outbox settings ({@code sentinel.messaging.*}). */
@ConfigurationProperties("sentinel.messaging")
public class MessagingProperties {

	/**
	 * Declare the RabbitMQ topology at startup. Requires configure permission on the
	 * {@code sentinel.*} names. Disable when the topology is provisioned out of band so the
	 * API connection can run with write-only permissions.
	 */
	private boolean declareTopology = true;

	private final Outbox outbox = new Outbox();

	public boolean isDeclareTopology() {
		return this.declareTopology;
	}

	public void setDeclareTopology(boolean declareTopology) {
		this.declareTopology = declareTopology;
	}

	public Outbox getOutbox() {
		return this.outbox;
	}

	public static class Outbox {

		/** Run the scheduled publisher in this instance. */
		private boolean publisherEnabled = true;

		/** Delay between publisher runs, in milliseconds. */
		private long pollIntervalMs = 1000;

		/** Maximum events claimed per run. */
		private int batchSize = 50;

		/**
		 * How long a claim is exclusive. Must exceed the worst-case publication time of a
		 * batch; an expired claim is taken over by another publisher.
		 */
		private Duration leaseDuration = Duration.ofSeconds(60);

		/** Publication attempts before an event becomes FAILED (terminal, recoverable). */
		private int maxAttempts = 8;

		/** First retry delay; doubles per attempt. */
		private Duration backoffInitial = Duration.ofSeconds(2);

		/** Upper bound of the retry delay. */
		private Duration backoffMax = Duration.ofMinutes(5);

		/** Maximum wait for a broker publisher confirm. */
		private Duration confirmTimeout = Duration.ofSeconds(10);

		/** Oldest pending event age above which the {@code outbox} health is DOWN. */
		private Duration maxPendingAge = Duration.ofMinutes(15);

		public Duration getMaxPendingAge() {
			return this.maxPendingAge;
		}

		public void setMaxPendingAge(Duration maxPendingAge) {
			this.maxPendingAge = maxPendingAge;
		}

		public boolean isPublisherEnabled() {
			return this.publisherEnabled;
		}

		public void setPublisherEnabled(boolean publisherEnabled) {
			this.publisherEnabled = publisherEnabled;
		}

		public long getPollIntervalMs() {
			return this.pollIntervalMs;
		}

		public void setPollIntervalMs(long pollIntervalMs) {
			this.pollIntervalMs = pollIntervalMs;
		}

		public int getBatchSize() {
			return this.batchSize;
		}

		public void setBatchSize(int batchSize) {
			this.batchSize = batchSize;
		}

		public Duration getLeaseDuration() {
			return this.leaseDuration;
		}

		public void setLeaseDuration(Duration leaseDuration) {
			this.leaseDuration = leaseDuration;
		}

		public int getMaxAttempts() {
			return this.maxAttempts;
		}

		public void setMaxAttempts(int maxAttempts) {
			this.maxAttempts = maxAttempts;
		}

		public Duration getBackoffInitial() {
			return this.backoffInitial;
		}

		public void setBackoffInitial(Duration backoffInitial) {
			this.backoffInitial = backoffInitial;
		}

		public Duration getBackoffMax() {
			return this.backoffMax;
		}

		public void setBackoffMax(Duration backoffMax) {
			this.backoffMax = backoffMax;
		}

		public Duration getConfirmTimeout() {
			return this.confirmTimeout;
		}

		public void setConfirmTimeout(Duration confirmTimeout) {
			this.confirmTimeout = confirmTimeout;
		}

		/** Fails startup on unsafe values. */
		void validate() {
			if (this.batchSize < 1 || this.batchSize > 500) {
				throw new IllegalStateException("sentinel.messaging.outbox.batch-size must be between 1 and 500");
			}
			if (this.maxAttempts < 1 || this.maxAttempts > 100) {
				throw new IllegalStateException("sentinel.messaging.outbox.max-attempts must be between 1 and 100");
			}
			if (this.backoffInitial.isNegative() || this.backoffInitial.isZero()
					|| this.backoffMax.compareTo(this.backoffInitial) < 0) {
				throw new IllegalStateException(
						"sentinel.messaging.outbox backoff must satisfy 0 < backoff-initial <= backoff-max");
			}
			if (this.confirmTimeout.isNegative() || this.confirmTimeout.isZero()) {
				throw new IllegalStateException("sentinel.messaging.outbox.confirm-timeout must be positive");
			}
			// The publisher only starts a publication while the remaining lease covers the
			// confirm wait plus a safety margin (OutboxPublisher#publishingBudget). Require room
			// for at least two publications per claim.
			if (this.leaseDuration.compareTo(this.confirmTimeout.multipliedBy(2).plusSeconds(2)) < 0) {
				throw new IllegalStateException(
						"sentinel.messaging.outbox.lease-duration must be at least 2 x confirm-timeout + 2s");
			}
		}

	}

}

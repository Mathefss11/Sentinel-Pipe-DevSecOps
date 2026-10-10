package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.ChannelCallback;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.rabbitmq.RabbitMQContainer;
import org.testcontainers.utility.MountableFile;

/**
 * The API's runtime broker identity is the least-privileged publisher created by the
 * production provisioning script (infrastructure/docker/rabbitmq/provision.sh), not the
 * broker administrator. Provisioning also imports definitions.json over the topology the
 * test context declared, which fails if the two disagree.
 */
class PublisherLeastPrivilegeIntegrationTests extends AbstractDomainApiIntegrationTest {

	private static final Path PROVISIONING_DIR = Path.of("..", "..", "infrastructure", "docker", "rabbitmq")
		.toAbsolutePath()
		.normalize();

	private static final String PUBLISHER = "sentinel-publisher";

	@Autowired
	private RabbitMQContainer rabbit;

	@Autowired
	private ConnectionFactory adminConnectionFactory;

	@Autowired
	private OutboxStore store;

	@Autowired
	private MeterRegistry meterRegistry;

	private CachingConnectionFactory publisherConnectionFactory;

	@BeforeEach
	void provisionAndConnectAsPublisher() throws Exception {
		// Hexadecimal: rabbitmqctl parses an argument starting with "-" as an option.
		String password = HexFormat.of().formatHex(UUID.randomUUID().toString().getBytes()).substring(0, 32);
		for (String file : new String[] { "provision.sh", "definitions.json" }) {
			this.rabbit.copyFileToContainer(MountableFile.forHostPath(PROVISIONING_DIR.resolve(file)),
					"/etc/sentinelpipe/rabbitmq/" + file);
		}
		ExecResult result = this.rabbit.execInContainer("sh", "-c",
				"SENTINEL_RABBITMQ_PUBLISHER_PASSWORD=" + password + " SENTINEL_WORKER_RABBITMQ_PASSWORD=w"
						+ password + " sh /etc/sentinelpipe/rabbitmq/provision.sh");
		assertThat(result.getExitCode()).as(result.getStderr().replace(password, "<redacted>")).isZero();

		this.publisherConnectionFactory = new CachingConnectionFactory(this.rabbit.getHost(),
				this.rabbit.getAmqpPort());
		this.publisherConnectionFactory.setUsername(PUBLISHER);
		this.publisherConnectionFactory.setPassword(password);
		this.publisherConnectionFactory.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
		this.publisherConnectionFactory.setPublisherReturns(true);
		this.jdbcTemplate.update("DELETE FROM outbox_events");
		new RabbitAdmin(this.adminConnectionFactory).purgeQueue(MessagingTopology.SCAN_REQUESTS_QUEUE, false);
	}

	@AfterEach
	void close() {
		this.publisherConnectionFactory.destroy();
		new RabbitAdmin(this.adminConnectionFactory).purgeQueue(MessagingTopology.SCAN_REQUESTS_QUEUE, false);
	}

	@Test
	void theOutboxPublishesWithConfirmsAsTheLeastPrivilegedPublisher() throws Exception {
		requestScan(createProject(), randomSha(), null);
		RabbitTemplate template = new RabbitTemplate(this.publisherConnectionFactory);
		template.setMandatory(true);
		MessagingProperties.Outbox settings = new MessagingProperties.Outbox();
		settings.setConfirmTimeout(Duration.ofSeconds(5));
		OutboxPublisher publisher = new OutboxPublisher(this.store, template, OutboxRoutes.standard(), settings,
				new OutboxMetrics(this.meterRegistry, this.store), "least-privilege-" + UUID.randomUUID());

		assertThat(publisher.publishBatch().published()).isEqualTo(1);
		assertThat(new RabbitAdmin(this.adminConnectionFactory).getQueueInfo(MessagingTopology.SCAN_REQUESTS_QUEUE)
			.getMessageCount()).isEqualTo(1);
	}

	@Test
	void thePublisherCannotAlterTopologyOrReadQueues() {
		RabbitTemplate template = new RabbitTemplate(this.publisherConnectionFactory);
		String worker = MessagingTopology.SCAN_REQUESTS_QUEUE;
		String deadLetters = MessagingTopology.DEAD_LETTER_QUEUE;

		// Raw channel operations: RabbitAdmin would log and swallow some of these refusals.
		assertRefused(template, (channel) -> channel.queueDeclare("attacker-queue", true, false, false, null));
		assertRefused(template, (channel) -> channel.exchangeDeclare("attacker-exchange", "fanout", true));
		assertRefused(template, (channel) -> channel.queueDelete(worker));
		assertRefused(template, (channel) -> channel.exchangeDelete(MessagingTopology.SCAN_REQUESTS_EXCHANGE));
		assertRefused(template, (channel) -> channel.queuePurge(deadLetters));
		assertRefused(template, (channel) -> channel.basicGet(worker, false));
		assertRefused(template, (channel) -> channel.basicGet(deadLetters, false));
		assertThat(new RabbitAdmin(this.adminConnectionFactory).getQueueInfo("attacker-queue")).isNull();
	}

	private static void assertRefused(RabbitTemplate template, ChannelCallback<?> action) {
		assertThatThrownBy(() -> template.execute(action)).isInstanceOf(AmqpException.class)
			.rootCause()
			.hasMessageContaining("ACCESS_REFUSED");
	}

}

package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;

import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import dev.sentinelpipe.api.AbstractDomainApiIntegrationTest;
import dev.sentinelpipe.api.contract.ContractSchemas;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.Declarables;
import org.springframework.amqp.core.Exchange;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.JsonNode;

/**
 * The declared RabbitMQ topology and the message schemas match
 * {@code packages/contracts}; the Python worker is checked against the same files.
 */
class MessagingContractIntegrationTests extends AbstractDomainApiIntegrationTest {

	@Autowired
	private Declarables topology;

	@Autowired
	private RabbitTemplate rabbitTemplate;

	@Autowired
	private ConnectionFactory connectionFactory;

	private JsonNode topologyContract() throws Exception {
		return this.jsonMapper.readTree(Files.readString(ContractSchemas.TOPOLOGY_FILE));
	}

	@Test
	void declaredExchangesQueuesAndBindingsMatchTheContract() throws Exception {
		JsonNode contract = topologyContract();

		List<Exchange> exchanges = this.topology.getDeclarablesByType(Exchange.class);
		assertThat(exchanges).hasSize(contract.get("exchanges").size());
		for (JsonNode expected : contract.get("exchanges")) {
			Exchange actual = exchanges.stream()
				.filter((e) -> e.getName().equals(expected.get("name").asString()))
				.findFirst()
				.orElseThrow();
			assertThat(actual.getType()).isEqualTo(expected.get("type").asString());
			assertThat(actual.isDurable()).isEqualTo(expected.get("durable").asBoolean());
			assertThat(actual.isAutoDelete()).isEqualTo(expected.get("auto_delete").asBoolean());
		}

		List<Queue> queues = this.topology.getDeclarablesByType(Queue.class);
		assertThat(queues).hasSize(contract.get("queues").size());
		for (JsonNode expected : contract.get("queues")) {
			Queue actual = queues.stream()
				.filter((q) -> q.getName().equals(expected.get("name").asString()))
				.findFirst()
				.orElseThrow();
			assertThat(actual.isDurable()).isTrue();
			assertThat(actual.isAutoDelete()).isFalse();
			assertThat(actual.isExclusive()).isFalse();
			Map<String, Object> expectedArguments = this.jsonMapper.convertValue(expected.get("arguments"), Map.class);
			assertThat(actual.getArguments()).isEqualTo(expectedArguments);
		}

		List<Binding> bindings = this.topology.getDeclarablesByType(Binding.class);
		assertThat(bindings).hasSize(contract.get("bindings").size());
		for (JsonNode expected : contract.get("bindings")) {
			assertThat(bindings).anySatisfy((binding) -> {
				assertThat(binding.getExchange()).isEqualTo(expected.get("exchange").asString());
				assertThat(binding.getDestination()).isEqualTo(expected.get("queue").asString());
				assertThat(binding.getRoutingKey()).isEqualTo(expected.get("routing_key").asString());
			});
		}

		JsonNode route = contract.get("messages").get(OutboxRoutes.SCAN_REQUESTED);
		OutboxRoutes.Route standard = OutboxRoutes.standard().routeFor(OutboxRoutes.SCAN_REQUESTED).orElseThrow();
		assertThat(standard.exchange()).isEqualTo(route.get("exchange").asString());
		assertThat(standard.routingKey()).isEqualTo(route.get("routing_key").asString());
	}

	@Test
	void topologyExistsOnTheBroker() throws Exception {
		JsonNode contract = topologyContract();
		this.rabbitTemplate.execute((channel) -> {
			for (JsonNode exchange : contract.get("exchanges")) {
				channel.exchangeDeclarePassive(exchange.get("name").asString());
			}
			for (JsonNode queue : contract.get("queues")) {
				channel.queueDeclarePassive(queue.get("name").asString());
			}
			return null;
		});
		assertThat(new org.springframework.amqp.rabbit.core.RabbitAdmin(this.connectionFactory)
			.getQueueInfo("sentinel.scan-requests.worker")).isNotNull();
	}

	@Test
	void messageSchemasAreValidAndTheirExamplesConform() throws Exception {
		var metaSchema = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
			.getSchema(SchemaLocation.of("https://json-schema.org/draft/2020-12/schema"));
		List<String> files = ContractSchemas.messageSchemaFileNames();
		assertThat(files).containsExactlyInAnyOrder("scan-requested.v1.schema.json",
				"processing-receipt.v1.schema.json", "dead-letter-metadata.v1.schema.json", "job-result.v1.schema.json",
				"sandbox-output.v1.schema.json", "findings.v1.schema.json");
		for (String file : files) {
			JsonNode schema = this.jsonMapper.readTree(Files.readString(ContractSchemas.MESSAGE_SCHEMAS_DIR.resolve(file)));
			assertThat(metaSchema.validate(schema)).as(file).isEmpty();
			assertThat(schema.get("$id").asString()).isEqualTo(ContractSchemas.MESSAGE_SCHEMA_ID_PREFIX + file);
			for (JsonNode example : schema.path("examples")) {
				ContractSchemas.assertValidMessage(file, example);
			}
		}
	}

	@Test
	void scanRequestedSchemaRejectsTamperedOrIncompleteMessages() throws Exception {
		JsonNode example = this.jsonMapper
			.readTree(Files.readString(ContractSchemas.MESSAGE_SCHEMAS_DIR.resolve("scan-requested.v1.schema.json")))
			.get("examples")
			.get(0);
		List<String> invalid = new ArrayList<>();
		for (String field : List.of("event_id", "schema_version", "scan_id", "project_id", "organization_id",
				"commit_sha", "occurred_at", "correlation_id")) {
			var copy = (tools.jackson.databind.node.ObjectNode) example.deepCopy();
			copy.remove(field);
			invalid.add(field + " missing: " + ContractSchemas.validateMessage("scan-requested.v1.schema.json", copy));
		}
		var extra = (tools.jackson.databind.node.ObjectNode) example.deepCopy();
		extra.put("access_token", "x");
		var version = (tools.jackson.databind.node.ObjectNode) example.deepCopy();
		version.put("schema_version", 2);
		var sha = (tools.jackson.databind.node.ObjectNode) example.deepCopy();
		sha.put("commit_sha", "main");

		assertThat(invalid).allSatisfy((entry) -> assertThat(entry).doesNotEndWith("[]"));
		assertThat(ContractSchemas.validateMessage("scan-requested.v1.schema.json", extra)).isNotEmpty();
		assertThat(ContractSchemas.validateMessage("scan-requested.v1.schema.json", version)).isNotEmpty();
		assertThat(ContractSchemas.validateMessage("scan-requested.v1.schema.json", sha)).isNotEmpty();
	}

}

package dev.sentinelpipe.api.messaging;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sentinelpipe.api.contract.ContractSchemas;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The broker provisioning artifact (infrastructure/docker/rabbitmq/definitions.json)
 * declares exactly the contract topology, plus the dead-letter retention policy; and the
 * API's defaults use the least-privileged publisher without declaring topology.
 */
class ProvisioningDefinitionsTests {

	private static final Path DEFINITIONS = Path.of("..", "..", "infrastructure", "docker", "rabbitmq",
			"definitions.json");

	private final JsonMapper mapper = JsonMapper.builder().build();

	private JsonNode read(Path path) throws IOException {
		return this.mapper.readTree(Files.readString(path.toAbsolutePath().normalize()));
	}

	private static List<String> entries(JsonNode array, String... fields) {
		List<String> result = new ArrayList<>();
		array.forEach((node) -> {
			Map<String, String> values = new TreeMap<>();
			for (String field : fields) {
				values.put(field, node.get(field).toString());
			}
			result.add(values.toString());
		});
		return result;
	}

	@Test
	void definitionsMatchTheTopologyContract() throws IOException {
		JsonNode topology = read(ContractSchemas.TOPOLOGY_FILE);
		JsonNode definitions = read(DEFINITIONS);

		assertThat(entries(definitions.get("exchanges"), "name", "type", "durable", "auto_delete"))
			.containsExactlyInAnyOrderElementsOf(
					entries(topology.get("exchanges"), "name", "type", "durable", "auto_delete"));
		assertThat(entries(definitions.get("queues"), "name", "durable", "auto_delete", "arguments"))
			.containsExactlyInAnyOrderElementsOf(
					entries(topology.get("queues"), "name", "durable", "auto_delete", "arguments"));
		List<String> bindings = new ArrayList<>();
		definitions.get("bindings")
			.forEach((b) -> bindings.add(b.get("source").asString() + "->" + b.get("destination").asString() + ":"
					+ b.get("routing_key").asString()));
		List<String> expected = new ArrayList<>();
		topology.get("bindings")
			.forEach((b) -> expected.add(b.get("exchange").asString() + "->" + b.get("queue").asString() + ":"
					+ b.get("routing_key").asString()));
		assertThat(bindings).containsExactlyInAnyOrderElementsOf(expected);
		assertThat(definitions.has("users")).as("no users or secrets in the definitions").isFalse();
		assertThat(definitions.has("permissions")).isFalse();
	}

	@Test
	void theDeadLetterQueueNeverDropsMessagesAtTheDefaultDeliveryLimit() throws IOException {
		JsonNode policies = read(DEFINITIONS).get("policies");

		assertThat(policies).hasSize(1);
		JsonNode policy = policies.get(0);
		assertThat(policy.get("pattern").asString()).isEqualTo("^sentinel\\.scan-requests\\.dead-letter$");
		assertThat(policy.get("apply-to").asString()).isEqualTo("quorum_queues");
		assertThat(policy.get("definition").get("delivery-limit").asInt()).isEqualTo(-1);
	}

	@Test
	void theApiDefaultsToThePublisherIdentityWithoutTopologyDeclaration() {
		YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
		yaml.setResources(new ClassPathResource("application.yml"));
		var properties = yaml.getObject();

		assertThat(properties).isNotNull();
		assertThat(properties.getProperty("spring.rabbitmq.username"))
			.isEqualTo("${SENTINEL_RABBITMQ_USERNAME:sentinel-publisher}");
		assertThat(properties.getProperty("sentinel.messaging.declare-topology")).isEqualTo("false");
		assertThat(properties.getProperty("management.endpoints.web.exposure.include")).isEqualTo("health");
	}

}

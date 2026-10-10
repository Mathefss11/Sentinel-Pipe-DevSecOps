package dev.sentinelpipe.api;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;

/**
 * Shared configuration for integration tests backed by real PostgreSQL and RabbitMQ
 * containers. Keeping the annotations identical lets all subclasses reuse one cached
 * application context and one set of containers.
 * <p>
 * The test broker connection uses the container's administrative user, so the API
 * declares the topology itself here; in deployments the topology is provisioned out of
 * band and the API runs as the least-privileged publisher (see
 * {@code PublisherLeastPrivilegeIntegrationTests}).
 */
@SpringBootTest(properties = "sentinel.messaging.declare-topology=true")
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
abstract class AbstractIntegrationTest {

}

package dev.sentinelpipe.api;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;

/**
 * Shared configuration for integration tests backed by real PostgreSQL and RabbitMQ
 * containers. Keeping the annotations identical lets all subclasses reuse one cached
 * application context and one set of containers.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
abstract class AbstractIntegrationTest {

}

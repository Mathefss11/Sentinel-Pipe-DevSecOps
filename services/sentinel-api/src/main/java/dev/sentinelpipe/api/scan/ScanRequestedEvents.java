package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.messaging.OutboxEvent;
import dev.sentinelpipe.api.messaging.OutboxRoutes;
import dev.sentinelpipe.api.messaging.OutboxStore;
import dev.sentinelpipe.api.project.Project;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * Builds {@code scan.requested} v1 events (packages/contracts/messages/v1) and appends
 * them to the outbox.
 *
 * <p>
 * Every field is taken from committed server-side state: the organization is the
 * project's owner, never a client-supplied value. The payload contains no tokens,
 * credentials or personal data; the requesting user is deliberately not included.
 */
@Component
class ScanRequestedEvents {

	static final int SCHEMA_VERSION = 1;

	private final OutboxStore outbox;

	private final JsonMapper jsonMapper;

	ScanRequestedEvents(OutboxStore outbox, JsonMapper jsonMapper) {
		this.outbox = outbox;
		this.jsonMapper = jsonMapper;
	}

	/** Must be called in the transaction that creates the scan. */
	void append(Scan scan, Project project, UUID correlationId) {
		UUID eventId = UUID.randomUUID();
		Map<String, Object> repository = new LinkedHashMap<>();
		repository.put("provider", project.getRepositoryProvider().name());
		repository.put("owner", project.getRepositoryOwner());
		repository.put("name", project.getRepositoryName());
		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("event_id", eventId.toString());
		payload.put("event_type", OutboxRoutes.SCAN_REQUESTED);
		payload.put("schema_version", SCHEMA_VERSION);
		payload.put("occurred_at", scan.getRequestedAt().toString());
		payload.put("correlation_id", correlationId.toString());
		payload.put("scan_id", scan.getId().toString());
		payload.put("project_id", project.getId().toString());
		payload.put("organization_id", project.getOrganizationId().toString());
		payload.put("commit_sha", scan.getCommitSha());
		payload.put("branch", scan.getBranch());
		payload.put("trigger_type", scan.getTriggerType().name());
		payload.put("repository", repository);
		this.outbox.append(new OutboxEvent(eventId, OutboxRoutes.SCAN_REQUESTED, SCHEMA_VERSION, "scan", scan.getId(),
				project.getOrganizationId(), correlationId, this.jsonMapper.writeValueAsString(payload),
				scan.getRequestedAt()));
	}

}

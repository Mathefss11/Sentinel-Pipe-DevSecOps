package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.PageResponse;
import dev.sentinelpipe.api.common.Pagination;
import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scan request and read endpoints. Lifecycle transitions are intentionally not exposed;
 * see {@link ScanLifecycleService}.
 */
@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1", produces = MediaType.APPLICATION_JSON_VALUE)
class ScanController {

	static final String IDEMPOTENCY_KEY_HEADER = "Idempotency-Key";

	static final String IDEMPOTENT_REPLAYED_HEADER = "Idempotent-Replayed";

	private final ScanService scanService;

	ScanController(ScanService scanService) {
		this.scanService = scanService;
	}

	/** Returns 202: the scan is queued, not performed, by this request. */
	@PostMapping(path = "/projects/{projectId}/scans", consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<ScanResponse> request(@PathVariable("projectId") UUID projectId,
			@RequestHeader(name = IDEMPOTENCY_KEY_HEADER, required = false) @Pattern(
					regexp = ScanService.IDEMPOTENCY_KEY_REGEX,
					message = "must be 1-128 characters: letters, digits, '.', '_', ':' or '-'") String idempotencyKey,
			@Valid @RequestBody CreateScanRequest request) {
		ScanService.ScanRequestOutcome outcome = this.scanService.requestScan(projectId, request.commitSha(),
				request.branch(), request.triggerType(), idempotencyKey);
		ScanResponse body = ScanResponse.from(outcome.details());
		return ResponseEntity.accepted()
			.location(URI.create("/api/v1/scans/" + body.id()))
			.header(IDEMPOTENT_REPLAYED_HEADER, Boolean.toString(outcome.replayed()))
			.body(body);
	}

	@GetMapping("/scans/{scanId}")
	ScanResponse get(@PathVariable("scanId") UUID scanId) {
		return ScanResponse.from(this.scanService.get(scanId));
	}

	@GetMapping("/projects/{projectId}/scans")
	PageResponse<ScanResponse> list(@PathVariable("projectId") UUID projectId,
			@RequestParam(name = "page", defaultValue = Pagination.DEFAULT_PAGE) @Min(0) @Max(Pagination.MAX_PAGE) int page,
			@RequestParam(name = "size", defaultValue = Pagination.DEFAULT_SIZE) @Min(1) @Max(Pagination.MAX_SIZE) int size) {
		return PageResponse.of(this.scanService.listByProject(projectId, page, size), ScanResponse::from);
	}

}

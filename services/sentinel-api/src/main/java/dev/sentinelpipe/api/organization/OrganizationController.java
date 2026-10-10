package dev.sentinelpipe.api.organization;

import dev.sentinelpipe.api.security.ConditionalOnDomainApiEnabled;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnDomainApiEnabled
@RequestMapping(path = "/api/v1/organizations", produces = MediaType.APPLICATION_JSON_VALUE)
class OrganizationController {

	private final OrganizationService organizationService;

	OrganizationController(OrganizationService organizationService) {
		this.organizationService = organizationService;
	}

	@PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<OrganizationResponse> create(@Valid @RequestBody CreateOrganizationRequest request) {
		Organization organization = this.organizationService.create(request.name(), request.slug());
		return ResponseEntity.created(URI.create("/api/v1/organizations/" + organization.getId()))
			.body(OrganizationResponse.from(organization));
	}

	@GetMapping("/{organizationId}")
	OrganizationResponse get(@PathVariable("organizationId") UUID organizationId) {
		return OrganizationResponse.from(this.organizationService.get(organizationId));
	}

}

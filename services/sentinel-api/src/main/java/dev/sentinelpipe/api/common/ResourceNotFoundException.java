package dev.sentinelpipe.api.common;

import java.util.UUID;

/** A requested resource does not exist. Mapped to HTTP 404. */
public class ResourceNotFoundException extends RuntimeException {

	private final String resourceType;

	public ResourceNotFoundException(String resourceType, UUID id) {
		super(resourceType + " " + id + " was not found");
		this.resourceType = resourceType;
	}

	public String getResourceType() {
		return this.resourceType;
	}

}

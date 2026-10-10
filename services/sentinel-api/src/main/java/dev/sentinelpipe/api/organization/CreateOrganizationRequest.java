package dev.sentinelpipe.api.organization;

import dev.sentinelpipe.api.common.DisplayNames;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

record CreateOrganizationRequest(
		@NotBlank @Size(max = DisplayNames.MAX_LENGTH) @Pattern(regexp = DisplayNames.NO_CONTROL_CHARACTERS_REGEX,
				message = "must not contain control characters") String name,
		@NotNull @Size(min = 1, max = Organization.SLUG_MAX_LENGTH) @Pattern(regexp = Organization.SLUG_REGEX,
				message = "must be lowercase letters, digits or single hyphens, starting and ending with a letter or digit") String slug) {
}

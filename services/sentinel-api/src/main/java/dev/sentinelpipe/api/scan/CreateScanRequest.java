package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.GitBranchName;
import dev.sentinelpipe.api.common.GitBranchNames;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

record CreateScanRequest(
		@NotNull @Pattern(regexp = CommitShas.INPUT_REGEX,
				message = "must be a full 40- or 64-character hexadecimal commit SHA") String commitSha,
		@NotNull @Size(max = GitBranchNames.MAX_LENGTH) @GitBranchName String branch,
		@NotNull TriggerType triggerType) {
}

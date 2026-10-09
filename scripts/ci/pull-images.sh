#!/bin/sh
# Pull container images with bounded retries and exponential backoff.
#
# Registry availability (token endpoint timeouts, rate limiting) is outside our
# control in CI; this makes transient failures retryable while still failing the
# job with an explicit error once the retry budget is exhausted.
#
# Usage: pull-images.sh IMAGE [IMAGE...]
# Environment: PULL_MAX_ATTEMPTS (default 5), PULL_INITIAL_DELAY_SECONDS (default 10)
set -eu

if [ "$#" -eq 0 ]; then
	echo "usage: $0 IMAGE [IMAGE...]" >&2
	exit 2
fi

max_attempts=${PULL_MAX_ATTEMPTS:-5}
initial_delay=${PULL_INITIAL_DELAY_SECONDS:-10}

for image in "$@"; do
	attempt=1
	delay=$initial_delay
	until docker pull --quiet "$image"; do
		if [ "$attempt" -ge "$max_attempts" ]; then
			echo "::error::Failed to pull $image after $attempt attempts" >&2
			exit 1
		fi
		echo "Pull of $image failed (attempt $attempt/$max_attempts); retrying in ${delay}s" >&2
		sleep "$delay"
		attempt=$((attempt + 1))
		delay=$((delay * 2))
	done
done

#!/bin/sh
# Builds the SYNTHETIC Trivy vulnerability database used by the Trivy tests (ADR-0012).
#
#   sh scripts/trivy/build-fixture-db.sh OUTPUT_DIR [ADVISORIES_DIR]
#
# ADVISORIES_DIR (optional, tests and audits only) replaces the default advisory set, for
# example to build a structurally valid database that lacks an ecosystem.
#
# Input: the synthetic GHSA (OSV format) advisories committed under
# services/sentinel-worker/tests/fixtures/trivy-db/advisories. They describe fictitious
# packages (sentinelpipe-fixture-*) and are not real vulnerabilities.
#
# Builder: the upstream trivy-db builder (Apache-2.0) at the exact commit that Trivy
# v0.75.0 pins in its go.mod, compiled in a digest-pinned Go image. `go install` fetches
# the module and its dependencies through the Go module proxy; every module is verified
# against the Go checksum database (immutable, content-addressed), so the build needs no
# mutable download. The builder itself then runs without network access.
#
# Output: OUTPUT_DIR/trivy.db, OUTPUT_DIR/metadata.json and OUTPUT_DIR/provenance.json.
# The builder records the build time in metadata.json (UpdatedAt/NextUpdate), so the bytes
# differ between builds; the advisory content does not. Tests derive their expectations
# from the built files, never from fixed digests.
#
# This is development and CI tooling: it is not part of the worker package and never runs
# in a scanner sandbox. No real vulnerability database is downloaded or committed.
set -eu

GO_IMAGE="golang:1.26.9-alpine3.23@sha256:6750308561953d451210ed1a8086d36c8c8bdcbf672d38d9d0d424b8a7a0216c"
TRIVY_DB_MODULE="github.com/aquasecurity/trivy-db/cmd/trivy-db@v0.0.0-20261001090913-650c4091f951"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 OUTPUT_DIR [ADVISORIES_DIR]" >&2
  exit 2
fi
out=$1
here=$(cd "$(dirname "$0")" && pwd)
advisories=${2:-"$here/../../services/sentinel-worker/tests/fixtures/trivy-db/advisories"}
[ -d "$advisories/ghsa" ] || { echo "advisory fixtures not found" >&2; exit 2; }
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# 1. Compile the pinned builder (network: Go module proxy + checksum database only).
docker run --rm -e CGO_ENABLED=0 -e GOFLAGS=-trimpath -e GOTOOLCHAIN=local \
  -e GOPROXY=https://proxy.golang.org -e GOSUMDB=sum.golang.org \
  --entrypoint /bin/sh "$GO_IMAGE" -c \
  "go install '$TRIVY_DB_MODULE' >&2 && cat /go/bin/trivy-db" > "$work/trivy-db"
[ -s "$work/trivy-db" ] || { echo "builder compilation failed" >&2; exit 1; }

# 2. Run it without network over the advisories (stdin) and return the DB (stdout).
# The GHSA source loads the Go standard library package list, hence the Go image.
mkdir "$work/input" "$work/input/in"
cp "$work/trivy-db" "$work/input/trivy-db"
cp -R "$advisories/ghsa" "$work/input/in/ghsa"
# The GHSA source maps Swift advisories to CocoaPods names and requires the (here empty)
# CocoaPods specs directory; the fixtures contain no Swift advisories.
mkdir -p "$work/input/in/cocoapods-specs/Specs"
(cd "$work/input" && tar -cf - trivy-db in) |
docker run --rm -i --network none -e GOTOOLCHAIN=local --entrypoint /bin/sh "$GO_IMAGE" -c '
  set -eu
  mkdir /work /out
  tar -x -f - -C /work
  chmod 0755 /work/trivy-db
  /work/trivy-db build --only-update ghsa --cache-dir /work/in --output-dir /out --update-interval 24h >&2
  tar -C /out -cf - trivy.db metadata.json
' > "$work/db.tar"

tar -x -f "$work/db.tar" -C "$out" trivy.db metadata.json

# Provenance for the image builder (sentinel-worker trivy-image build): the builder and a
# digest over the advisory inputs: SHA-256 of the lines "<sha256 hex>  <path>" (LF) of
# every advisory file in byte order of the paths (recomputed by the worker tests).
advisories_sha256=$(cd "$advisories" && find ghsa -type f | LC_ALL=C sort |
  while IFS= read -r f; do echo "$(sha256sum < "$f" | cut -c1-64)  $f"; done |
  sha256sum | cut -c1-64)
echo "{\"advisories_sha256\":\"$advisories_sha256\",\"builder\":\"$TRIVY_DB_MODULE\",\"kind\":\"SYNTHETIC_FIXTURE\"}" \
  > "$out/provenance.json"
echo "synthetic Trivy DB written to $out" >&2

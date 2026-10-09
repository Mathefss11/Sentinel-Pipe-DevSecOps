# Security Policy

## Project status

SentinelPipe is pre-release software under active development (Milestone 1: Foundation).
It is not yet intended for production use, and no version is currently supported for
production deployments. Security fixes are applied to the `main` branch.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, discussions,
or pull requests.

Report them privately through GitHub's private vulnerability reporting: open the repository's
**Security** tab and select **Report a vulnerability**. Please include:

- a description of the issue and its potential impact;
- the affected component, file, or configuration;
- steps to reproduce or a minimal proof of concept;
- any suggested remediation.

Please do not include real credentials, personal data, or third-party secrets in a report.
Reports are acknowledged on a best-effort basis. This is a personal open-source project with
no formal response-time commitment.

## Scope

In scope:

- code and configuration in this repository (`services/`, `infrastructure/`, `compose.yaml`,
  `.github/workflows/`);
- weaknesses that could cause SentinelPipe to report a passing security decision without
  complete, verified evidence (fail-open behavior).

Out of scope:

- vulnerabilities in third-party dependencies or container images that have not been shown to
  be exploitable through SentinelPipe (please report those upstream);
- the local development stack (`compose.yaml`) when it is deliberately exposed beyond
  `127.0.0.1` or run with placeholder credentials outside a workstation;
- the intentionally vulnerable example applications planned under `examples/`.

## Security baseline (Milestone 1)

The current foundation implements the following controls:

- **Secrets:** no credentials are committed. Passwords have no defaults in the application
  configuration or in `compose.yaml`. Both fail to start if a password is missing. `.env` is
  git-ignored, and `.env.example` contains development-only placeholders.
- **Local network exposure:** all Docker Compose host ports bind to `127.0.0.1` only.
- **Image supply chain:** container images in `compose.yaml` and in the Testcontainers test
  configuration are pinned to immutable multi-arch digests.
- **OPA:** the server runs with `--authorization=basic` and a deny-by-default `system.authz`
  policy. It permits health checks and decision queries and rejects policy and data
  management requests. The container runs as a non-root user with a read-only root
  filesystem, all Linux capabilities dropped, and `no-new-privileges`.
- **API surface:** only the Actuator health endpoint is exposed over HTTP, without component
  details.
- **Database:** the schema is managed exclusively by versioned Flyway migrations. Hibernate
  only validates the schema.
- **CI:** GitHub Actions runs with a read-only token (`contents: read`). Checkout credentials
  are not persisted, third-party actions are pinned to commit SHAs, and there are no deployment
  or publishing steps.

## Known limitations

- The API has no authentication or authorization yet. Tenant-scoped authorization is planned
  for Milestone 2. Do not expose the API to untrusted networks.
- The Compose stack is for local development only. It does not use TLS between services, and
  OPA does not authenticate clients.
- Scanner execution, evidence integrity verification, GitHub webhook and OIDC validation, and
  policy-based security decisions are not implemented yet.
- Image digests and action SHAs are pinned but not yet updated automatically. Dependency
  update automation and provenance verification are planned for later milestones.

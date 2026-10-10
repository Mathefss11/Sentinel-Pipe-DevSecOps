# SentinelPipe contracts

Machine-readable contracts of the SentinelPipe control plane API.

| Path | Content |
|---|---|
| `openapi/sentinel-api-v1.yaml` | OpenAPI 3.1 description of the `/api/v1` REST API |
| `schemas/v1/*.schema.json` | JSON Schema 2020-12 documents for request and response bodies |

## Schemas

| Schema | Describes |
|---|---|
| `organization.schema.json` | Organization response |
| `create-organization-request.schema.json` | `POST /api/v1/organizations` body |
| `project.schema.json` | Project response |
| `create-project-request.schema.json` | `POST /api/v1/organizations/{id}/projects` body |
| `scan-request.schema.json` | `POST /api/v1/projects/{id}/scans` body |
| `scan.schema.json` | Scan response, including its jobs |
| `scan-job.schema.json` | Scanner job representation |
| `membership.schema.json` | Organization membership response |
| `create-membership-request.schema.json` | `POST /api/v1/organizations/{id}/members` body |
| `update-membership-request.schema.json` | `PUT /api/v1/organizations/{id}/members/{membershipId}` body |
| `current-user.schema.json` | `GET /api/v1/me` response |
| `project-page.schema.json`, `scan-page.schema.json`, `membership-page.schema.json`, `page-metadata.schema.json` | Paginated collections |
| `problem-details.schema.json` | RFC 9457 error responses |
| `common.schema.json` | Shared value types (`$defs`) |

## Message contracts (RabbitMQ)

| File | Describes |
|---|---|
| `messages/v1/scan-requested.v1.schema.json` | `scan.requested` v1 event (outbox → worker). Self-contained, snake_case, no credentials |
| `messages/v1/processing-receipt.v1.schema.json` | Durable worker receipt committed before acknowledgement |
| `messages/v1/dead-letter-metadata.v1.schema.json` | `x-sentinel-dead-letter` header attached to dead-lettered messages |
| `messages/v1/sandbox-output.v1.schema.json` | The only channel from a sandboxed scanner to the worker (stdout): artifacts as data under identifier names, never paths (ADR-0009) |
| `messages/v1/findings.v1.schema.json` | Normalized, redacted findings of one scanner run, stored as the `findings.json` evidence artifact; coverage and limitations included; never a security decision ([contract](../../docs/api/findings-contract-v1.md), ADR-0010) |
| `messages/v1/job-result.v1.schema.json` | Result of a leased scan job (worker → `worker.submit_result`), with database-verified evidence references; canonical serialization, at most 16 KiB (ADR-0008) |
| `messaging/topology.v1.json` | Exchanges, queues, bindings, routing keys and retry settings |

Message schemas are versioned in the file name and `schema_version`. Consumers must reject
unknown versions. The Python worker bundles byte-identical copies, verified by its tests.
The Java tests verify the declared topology and the published payloads against these
files.

## Versioning and compatibility

- The major version is part of the URL path (`/api/v1`) and of the schema directory and
  `$id` (`.../schemas/v1/...`). Schema `$id` values are stable identifiers; they are not
  guaranteed to be resolvable URLs.
- Within `v1`, changes must be backward compatible for clients: new optional request
  properties, new response properties, or new enum values documented in advance. Removing
  or renaming properties, tightening validation, or changing semantics requires `v2`.
- Response schemas use `additionalProperties: false`. This is intentional: any change to a
  response shape fails the contract tests until the schema is updated in the same change,
  so the contract cannot drift silently. Clients should still ignore unknown properties.
- Request schemas use `additionalProperties: false` because the API rejects unknown
  request properties.
- REST bodies do not carry a `schema_version` field; the version is the URL/`$id` major
  version. Asynchronous messages and evidence documents introduced in later phases will
  carry an explicit `schema_version`.

## Automated validation

The API test suite (`services/sentinel-api`, `ContractIntegrationTests` and
`OpenApiContractTests`) verifies that:

- every schema is a valid JSON Schema 2020-12 document and all `$ref`s resolve;
- real API responses validate against the corresponding schemas;
- every request/response example in the OpenAPI document validates against its schema;
- the set of `/api/v1` operations in the OpenAPI document exactly matches the operations
  registered by the application;
- the document declares the `bearerAuth` scheme globally, no operation overrides it, and
  every operation documents `401` (and `403`, except `GET /api/v1/me`).

## Security

All operations require an OAuth 2.0 bearer access token (JWT) from the configured OIDC
provider. Authorization is based on server-side organization memberships; see the
OpenAPI `info.description` and [ADR-0003](../../docs/adr/0003-identity-and-tenant-authorization.md).

Not yet automated: validation of the OpenAPI document against the official OpenAPI 3.1
meta-schema, and breaking-change detection between contract versions.

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
| `project-page.schema.json`, `scan-page.schema.json`, `page-metadata.schema.json` | Paginated collections |
| `problem-details.schema.json` | RFC 9457 error responses |
| `common.schema.json` | Shared value types (`$defs`) |

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
  registered by the application.

Not yet automated: validation of the OpenAPI document against the official OpenAPI 3.1
meta-schema, and breaking-change detection between contract versions.

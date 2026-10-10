# ADR-0003: External OIDC identity and membership-based tenant authorization

- **Status:** Accepted (pending owner review)
- **Date:** 2026-10-09
- **Milestone:** M2 Phase 2A
- **Amends:** ADR-0002 (the domain API is now authenticated; the loopback restriction remains)

## Context

The control plane is multi-tenant. Phase 1 shipped the domain API without authentication,
disabled by default (ADR-0002). Before any broader use, every request must be
authenticated and every tenant-scoped access must be authorized against the requesting
user's organization membership. Requirements: no custom password store or
authentication server, standards-based tokens, default deny, no self-service escalation.

## Decision

### Authentication: OAuth 2.0 Resource Server with JWT access tokens

- Users authenticate with an **external OIDC provider** (for example Keycloak, Microsoft
  Entra ID, Auth0, Okta). SentinelPipe only validates access tokens; it stores no
  passwords and implements no login flow.
- Spring Security's resource server validates every `/api/**` request. The decoder is
  built explicitly (`JwtDecoderFactory`) rather than through OIDC discovery at startup:
  - signature with an **allow-listed asymmetric algorithm** (default `RS256`), using the
    provider's JWK Set (`jwk-set-uri`, HTTPS required; HTTP only for loopback) or a
    configured PEM public key; `alg: none` and HMAC tokens are impossible;
  - JOSE `typ` must be allow-listed (default `at+jwt`, RFC 9068), so ID tokens cannot be
    replayed as access tokens;
  - exact `iss`; configured audience contained in `aud`; `exp` **required**; `nbf`/`exp`
    checked with a bounded clock skew (default 30 s);
  - `sub` required, ≤ 255 characters, no control characters.
- **`typ` compatibility.** The comparison is case-insensitive and also accepts the full
  media type (`application/at+jwt`). Providers that only emit `typ: JWT` for access tokens
  can be supported by setting `token-types: JWT`. That weakens ID-token/access-token
  separation, so the audience must then be a dedicated API audience and never an OAuth
  client ID, which ID tokens carry in `aud`. Tokens without `typ` are never accepted. See
  the README section "Access-token `typ` compatibility".
- **Platform administrators** are matched on the exact `(iss, sub)` pair. `sub` is an
  opaque, issuer-scoped identifier. E-mail addresses, user names and other mutable or
  reassignable claims are never used for identity or authorization.
- Tokens are accepted only from the `Authorization: Bearer` header. 401 responses never
  disclose why a token was rejected. The JWK Set client has 5 s timeouts.
- Misconfiguration (missing issuer/audience/key source, insecure JWKS URI, symmetric
  algorithm) aborts startup.

### Identity model

`user_identities(issuer, subject)` with a unique constraint; no profile data or PII.
Identity rows are created only when a privileged actor grants a membership (or a platform
administrator bootstraps an organization), never merely because someone authenticated.

### Authorization: server-side memberships

- `organization_memberships(organization_id, user_identity_id, role, granted_by)`, one
  row per user per organization, role `OWNER | ADMIN | MEMBER | VIEWER`.
- **Token claims are never used for tenant authorization.** Roles, scopes or organization
  claims in tokens are ignored; only `iss` and `sub` identify the caller.
- `AccessControl` resolves the owning organization of every requested resource (project →
  organization, scan → project → organization) and checks the caller's membership.
- **Non-members get 404**, identical to a nonexistent resource, so UUID knowledge neither
  grants access nor confirms existence (IDOR). Members with an insufficient role get 403
  with a stable `code`.
- The permission matrix is defined once in `OrganizationPermission`:

| Permission | OWNER | ADMIN | MEMBER | VIEWER |
|---|---|---|---|---|
| View organization, projects, scans | ✓ | ✓ | ✓ | ✓ |
| Request scan | ✓ | ✓ | ✓ | |
| Register project | ✓ | ✓ | | |
| View / manage members | ✓ | ✓ | | |
| Grant, change or revoke OWNER and ADMIN | ✓ | | | |
| Grant, change or revoke MEMBER and VIEWER | ✓ | ✓ | | |

### Escalation prevention

- Nobody can grant a role they cannot manage (ADMIN → only MEMBER/VIEWER).
- Nobody can grant, change or revoke **their own** membership (also a DB CHECK:
  `granted_by <> user_identity_id`).
- Membership changes take a row lock on the organization and re-read the actor's
  membership under that lock; concurrent mutual demotion cannot leave an organization
  without an OWNER (verified by a concurrency test), and a defensive check rejects any
  change that would.
- Grant requests carry only `subject` and `role`; issuer, organization and grantor come
  from the validated token and the request path. Unknown properties are rejected.

### Bootstrap: platform administrators

Organization creation is restricted to `sentinel.security.platform-admin-subjects`
(subjects of the configured issuer). The creator becomes the first OWNER in the same
transaction. Platform administrators have **no** implicit access to existing
organizations. There is no public registration.

### Default deny and exposure

- Domain API disabled (default): only health endpoints are reachable; everything else is
  403; no token decoder exists.
- Domain API enabled: health public, `/api/**` authenticated, everything else denied.
- The loopback-only guard from ADR-0002 is retained as defense in depth until audit
  logging, rate limiting and a hardened deployment exist.

## Consequences

- Operators must run or subscribe to an OIDC provider and configure issuer, audience and
  JWKS. Local development needs a provider too (for example a local Keycloak); there is
  no development bypass.
- Each request performs one or two indexed membership lookups. Acceptable at current
  scale; caching would need careful invalidation and is deferred.
- Tokens remain valid until expiry after a membership is revoked, but **authorization**
  is re-evaluated on every request, so revocation takes effect immediately.

## Not in scope (later phases)

Audit events for membership changes and authorization failures, machine identities
(GitHub App / Actions OIDC, M5), token introspection or revocation lists, rate limiting,
multiple trusted issuers, SCIM/group sync, and removing the loopback restriction.

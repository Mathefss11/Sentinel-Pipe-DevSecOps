# SentinelPipe — Claude Code Project Instructions

## 1. Project Identity

**Repository:** `Sentinel-Pipe-DevSecOps`  
**Project:** SentinelPipe  
**Purpose:** An open-source, reusable, security-first DevSecOps platform and professional cybersecurity engineering portfolio project.  
**Primary language for code, documentation, comments, tests, and commits:** English.  
**Current phase:** Milestone 1 — Foundation. Do not assume later milestones are implemented.

SentinelPipe analyzes software repositories, consolidates vulnerability findings, applies versioned security policies, and publishes actionable remediation reports to GitHub. It is intended to demonstrate software engineering, application security, DevSecOps, secure systems design, and defensive automation. **Do not introduce commercialization, billing, or SaaS monetization features.**

## 2. Collaboration and Operating Rules

- Act as a careful implementation engineer, not an autonomous product owner. The human owner approves architectural changes and security-sensitive decisions.
- Before a substantial task, inspect the repository, summarize the implementation plan, and identify assumptions, missing dependencies, and risks.
- Implement incrementally. Keep changes focused, testable, and easy to review.
- Do not claim a feature or test is complete unless you actually implemented or executed it. Report commands and results precisely.
- Do not commit, push, force-push, merge, create releases, deploy, or change GitHub settings without explicit approval.
- Never delete data, reset databases, rewrite Git history, or run destructive commands without explicit approval.
- Do not expose secrets in code, output, test fixtures, documentation, logs, or commits. Use `.env.example` with placeholders; ensure local `.env` and credentials are ignored.
- Ask before installing system-wide software, accessing external services, using paid APIs, or making significant architecture changes.
- Prefer official documentation and stable compatible versions. Avoid invented APIs, dependency versions, CVE remediation versions, and unsupported security claims.
- Use Windows PowerShell-compatible commands for the human's local environment unless a task explicitly targets Linux, Docker, or GitHub Actions.
- If a requirement conflicts with security or technical correctness, explain the conflict and propose a safer implementation.

## 3. Architecture Baseline

Use a **modular monolith plus separate workers**, not premature microservices.

### Control Plane — Java / Spring Boot

Responsible for organizations, users, authorization, projects, GitHub installations, scan lifecycle, policies, evaluations, artifacts, audit events, and reporting coordination.

- Java 21; Maven with Maven Wrapper (`mvnw.cmd` on Windows).
- Spring Boot: use the version selected in the generated project, provided it is stable and compatible with Java 21. Review compatibility before adding dependencies.
- Group: `dev.sentinelpipe`.
- Artifact: `sentinel-api`.
- Java package: `dev.sentinelpipe.api` (**not** `sentinel-api`, which is invalid as a Java package).
- Spring Web, Validation, Actuator, Data JPA, PostgreSQL Driver, Flyway, and Spring AMQP (Spring for RabbitMQ) as needed.
- Prefer configuration in `application.yml`; environment variables for local overrides and secrets.
- Keep business logic separate from controllers, persistence, external adapters, and transport contracts.

### Execution / Processing Plane — Python

Responsible for repository discovery, scanner adapters, normalization, finding correlation, and deterministic remediation content. Scanner execution occurs in restricted, isolated execution contexts; never execute arbitrary repository-provided commands inside the API process.

- Python 3.12+; `pyproject.toml`; Pytest.
- Typed interfaces and explicit, versioned JSON contracts.
- Scanner adapters must distinguish tool execution success from security findings.

### Supporting Infrastructure

- PostgreSQL with Flyway migrations.
- RabbitMQ for asynchronous commands and events; durable messages, idempotent consumers, retries, and DLQ when implemented.
- OPA/Rego for deterministic policy evaluation.
- S3-compatible object storage for evidence and large reports in a later milestone.
- Docker Compose for reproducible local development.
- GitHub Actions for CI and, later, isolated scanning and publishing.
- Prometheus/Grafana as later-stage observability enhancements.

### Isolation Decision

Use a **hybrid isolation architecture**: GitHub-hosted ephemeral runners for the initial scan execution path, with appropriately restricted scanner containers where necessary. Preserve interfaces that could later support dedicated VMs/MicroVMs. Containers alone are not a strong security boundary. Do not expose privileged credentials to untrusted pull-request code.

## 4. Target Repository Structure

```text
Sentinel-Pipe-DevSecOps/
├── .github/
│   └── workflows/
├── services/
│   ├── sentinel-api/
│   └── sentinel-worker/
├── packages/
│   ├── contracts/
│   └── policy-bundle/
├── infrastructure/
│   ├── docker/
│   ├── terraform/
│   └── observability/
├── examples/
│   ├── vulnerable-java/
│   ├── vulnerable-python/
│   └── vulnerable-typescript/
├── tests/
│   ├── contract/
│   ├── integration/
│   ├── e2e/
│   └── adversarial/
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── threat-model/
│   ├── api/
│   └── runbooks/
├── scripts/
├── compose.yaml
├── README.md
├── SECURITY.md
└── CLAUDE.md
```

Create directories only when needed. Do not add empty scaffolding merely to imitate the target tree. The Spring Initializr-generated Maven project belongs in `services/sentinel-api/`, not the repository root.

## 5. Core Domain and Contracts

Planned entities: `Organization`, `User`, `OrganizationMember`, `GitHubInstallation`, `Project`, `Scan`, `ScanJob`, `Finding`, `FindingOccurrence`, `Policy`, `PolicyEvaluation`, `SecurityException`, `Artifact`, `AuditEvent`, and `OutboxEvent`.

### Scan Lifecycle

`QUEUED → PLANNING → RUNNING → EVALUATING → COMPLETED`; `FAILED` and `CANCELLED` are terminal alternatives.

### Security Decision (independent of execution state)

- `PASS`: all required security controls completed and policy permits the change.
- `FAIL`: valid evidence violates one or more blocking policies.
- `INCOMPLETE`: required evidence, scanner execution, policy evaluation, or integrity verification is missing/invalid. Must not approve a merge.

A `COMPLETED` scan can have a `FAIL` decision. Never equate scanner exit code zero with no vulnerabilities. Never treat an incomplete scan as clean.

### Data and API Standards

- REST API prefix `/api/v1`; OpenAPI 3.1.
- JSON Schema 2020-12; explicit `schema_version` and compatibility tests.
- UUID primary keys; UTC timestamps; SHA-256 evidence digests.
- RFC 9457 Problem Details for API errors.
- PostgreSQL constraints, foreign keys, indexes, tenant-scoped authorization, and Flyway migrations.
- Transactional Outbox for reliable event publication; idempotent consumers.
- Finding identity separate from scan occurrences; do not mark findings `RESOLVED` if coverage is incomplete or noncomparable.
- Policy decisions and associated evidence references must be auditable and reproducible.

Do not fabricate complete contracts where details remain undecided. Propose schemas for review and implement only the approved milestone scope.

## 6. Security Requirements (Non-Negotiable)

1. **Least privilege:** no unnecessary GitHub, filesystem, container, database, or network permissions.
2. **Untrusted repository content:** PR code, scanner outputs, SARIF, Markdown, and artifact metadata are untrusted inputs.
3. **Separation of duties:** scanning and privileged GitHub publication use separate security contexts.
4. **GitHub webhooks:** verify signatures and installation/repository authorization; handle duplicate deliveries.
5. **GitHub Actions OIDC:** validate issuer, audience, signature, expiry, and workflow/repository/commit claims before granting scoped upload authorization.
6. **Evidence integrity:** associate results with the expected scan, job, commit, scanner, and verified digest; a digest alone does not establish trustworthy provenance.
7. **Fail closed:** missing required scanner output, policy evaluation, or integrity verification cannot yield `PASS`.
8. **Secrets:** redact credentials and sensitive evidence from comments, logs, reports, and artifacts; never publish real secrets.
9. **Isolation:** enforce execution timeouts, resource limits, restricted permissions, and controlled networking as the execution architecture matures.
10. **Authorization:** every tenant-scoped resource access must verify organization/project membership; UUID knowledge is not authorization.
11. **Exceptions:** explicit scope, justification, approver, expiry, and audit record; expired exceptions never bypass policies.
12. **Supply chain:** pin and review actions/images/scanners; verify provenance and artifact integrity for releases.
13. **No unsafe privileged PR execution:** never check out or execute untrusted PR code in a privileged `pull_request_target` context.
14. **No false assurances:** report coverage, uncertainty, scanner limitations, and operational failures accurately.

## 7. Security Scanning and GitHub Reporting Roadmap

Planned tools:
- Semgrep: SAST.
- Gitleaks: secrets detection.
- Trivy: dependencies and container security.
- Checkov: infrastructure as code.
- Syft: SBOM.
- OWASP ZAP: DAST in isolated ephemeral staging.
- OPA/Rego: policy evaluation.
- Cosign and/or GitHub artifact attestations: software supply-chain integrity, subject to actual environment support.

The platform will support Java, Python, and JavaScript/TypeScript first, with scanner-specific coverage reporting. Additional languages may be added later.

**Four required GitHub outputs:**
1. GitHub Checks for merge-gate status.
2. SARIF upload to GitHub Code Scanning when supported by repository plan/visibility and permissions.
3. A single updated PR comment summarizing findings and remediation.
4. GitHub Actions Artifacts containing reports and machine-readable evidence.

**Remediation report requirements:**
- Executive summary and gate decision.
- Required fixes vs. recommended improvements.
- For each blocking finding: what, where, why it matters, how to fix, how to verify, and references (CWE/CVE where available).
- Scan coverage and incomplete checks.
- New, existing, and resolved findings when comparison is valid.
- Markdown, HTML, and JSON outputs; SARIF generated separately.
- Deterministic, versioned remediation knowledge base. AI-generated suggestions are optional future work and must never control gate decisions.

## 8. Milestones — Implement Only the Current One

- **M1 — Foundation:** monorepo, Java API, Python package, Docker Compose (PostgreSQL/RabbitMQ/OPA), Flyway baseline, health checks, CI, initial tests, README.
- **M2 — Domain & Contracts:** formal schemas, entities, migrations, APIs, idempotency, outbox, authorization groundwork.
- **M3 — Scanners:** discovery, Semgrep/Gitleaks/Trivy adapters, normalized findings, correlation, Java/Python/TypeScript examples.
- **M4 — Security Gate & Remediation:** OPA policies, coverage, exceptions, decisions, remediation knowledge base, reports.
- **M5 — GitHub Integration:** GitHub App, webhooks, OIDC, Checks, SARIF, PR comments, artifacts, branch protection tests.
- **M6 — Advanced Security:** Checkov, Syft, ZAP, SBOM, attestation, isolated staging, release verification.
- **M7 — Hardening & Observability:** audit, timeouts, retries/DLQ, monitoring, STRIDE adversarial tests.
- **M8 — Portfolio Release:** reproducible demos, C4 diagrams, ADRs, threat model, English documentation, security review.

### M1 Definition of Done

- Monorepo layout is coherent and documented.
- Spring Boot API builds using Maven Wrapper and exposes a working health endpoint.
- Python package installs and its Pytest suite passes.
- Docker Compose starts PostgreSQL, RabbitMQ, and OPA with appropriate local-only exposure and health checks.
- Flyway applies the initial migration against PostgreSQL.
- CI validates Java and Python builds/tests and configuration where practical.
- `.gitignore`, `.env.example`, README, and baseline security guidance exist.
- All commands and test results are reported; no unsupported claims of success.

## 9. Testing and Quality Standards

- Java: JUnit 5, Spring Boot Test, Testcontainers where appropriate.
- Python: Pytest; typing and linting with agreed tools.
- Contracts: JSON Schema validation and compatibility tests.
- Policies: `opa test` and positive/negative cases.
- Integration: PostgreSQL and RabbitMQ behavior under real containers.
- End-to-end: PR with deliberately planted synthetic vulnerabilities, policy block, fix, rerun, and updated GitHub results.
- Adversarial: forged evidence, invalid OIDC, secret leakage, expired exceptions, scanner failure, resource exhaustion, and unauthorized cross-organization access.

Tests must be deterministic where possible. Never disable security checks just to make CI green. Avoid flaky external dependencies in ordinary unit tests.

## 10. Documentation and Reporting Format

For each implementation task, finish with:

1. **Changes:** what was implemented and key files modified.
2. **Validation:** exact commands run, pass/fail counts, and limitations.
3. **Security considerations:** new trust boundaries, permissions, or risks.
4. **Remaining work:** unimplemented items and blockers.
5. **Suggested commit message:** concise conventional commit in English; do not commit unless approved.

Maintain professional, accurate English documentation suitable for international cybersecurity interviews. Favor clarity and engineering evidence over marketing language.

## 11. Immediate Next Action

**Start M1 only.** First inspect the existing Spring Initializr project and local tool versions, confirm its placement under `services/sentinel-api/`, review dependencies and Java package name, then propose a short step-by-step plan. Do not scaffold the entire platform or implement future milestones in one pass. Ask for approval before making substantial changes.

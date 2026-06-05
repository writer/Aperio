# Security

Aperio is a security product, so the most important implementation details are the tenant boundary, role checks, and secret handling. Those controls live mainly in `apps/api/src/middleware/security.ts`, `packages/security/src/crypto.ts`, and the tenant-scoped Prisma queries throughout `apps/api/src/routes/*.ts`.

## Main controls

### Authentication and demo fallback

`apps/api/src/middleware/security.ts` accepts bearer tokens for API compatibility and an `HttpOnly`, `SameSite=Lax` session cookie for the web console. Cookie-backed unsafe methods require an allowed `Origin`/`Referer` derived from `APERIO_WEB_ORIGIN`. In non-production, auth can fall back to `DEMO_USER_ID` and `DEMO_ORGANIZATION_ID`, which is convenient locally but should be understood before exposing a deployment.

### Tenant isolation

Every route mounted under `/api/v1` uses `requireTenant`, and route handlers include `organizationId: tenantReq.tenantId` in their Prisma queries. The A2A routes also validate that referenced tasks, findings, and agents belong to the same tenant.

### Role enforcement

Privileged routes use `requireRole(...)`, especially around admin settings, member updates, and proposal approvals. Roles are stored in the `Role` model in `packages/db/prisma/schema.prisma`.

### Secret encryption

`packages/security/src/crypto.ts` encrypts integration and SIEM credentials with AES-256-GCM and binds them to a record-specific AAD string. Secrets are decrypted only when a worker or route needs them.

### Audit logging

Routes for connectors, SIEM destinations, admin settings, remediation actions, and proposal decisions all write `TenantAuditLog` entries.

## Security-relevant files

| File | Why it matters |
| --- | --- |
| `apps/api/src/middleware/security.ts` | Auth and tenant boundary |
| `packages/security/src/crypto.ts` | Secret encryption/decryption |
| `apps/api/src/routes/integrations.ts` | Stores provider credentials |
| `apps/api/src/routes/siem.ts` | Stores SIEM credentials |
| `apps/api/src/routes/admin.ts` | Role-sensitive admin mutations |
| `apps/api/src/routes/agents.ts` | Proposal approvals and agent tenant checks |

## Known limits in this checkout

- Local demo-mode auth can mask real auth issues if you forget the environment mode.
- External provider tokens are stored securely, but the repo does not yet show secret rotation workflows.

For the encryption implementation, go to [Security package](packages/security.md). For environment variables that influence auth and crypto, go to [Configuration](reference/configuration.md).

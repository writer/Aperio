# Security

Aperio is a security product, so the most important implementation details are tenant boundaries, role checks, credential encryption, session safety, and outbound integration controls.

## Tenant and session boundary

- The Go API validates the `aperio_session` HttpOnly cookie against hashed session tokens in `user_sessions`.
- Cookie-backed unsafe methods require a trusted browser origin derived from `APERIO_WEB_ORIGIN`.
- API handlers scope reads and writes by organization ID.
- Background workers lease organization-scoped jobs/deliveries from Postgres.
- Development demo auth is controlled by explicit environment flags and should stay disabled in shared environments.

## Roles

Role checks live in `internal/bootstrap/compat_api.go` for compatibility workflows and in typed RPC handlers as workflows are promoted. Owner/admin-only mutations include tenant settings, member management, connector writes, SIEM writes, and remediation approval paths.

## Secrets

Credential material is encrypted at rest with AES-256-GCM helpers in `packages/security/src/crypto.ts`. Go compatibility handlers must write data in the same envelope format consumed by TypeScript workers.

Sensitive paths:

| Path | Why it matters |
| --- | --- |
| `internal/bootstrap/compat_api.go` | Auth, role gates, credential persistence, compatibility mutations |
| `packages/security/src/crypto.ts` | Shared encryption envelope and password helpers |
| `workers/ingestion-worker.ts` | Decrypts connector credentials and writes findings/assets |
| `workers/siem-dispatcher.ts` | Decrypts SIEM credentials and sends outbound data |
| `apps/mcp/src/server.ts` | Agent-facing tools backed by tenant data |

## Outbound safety

SIEM destinations should reject private/link-local endpoints unless explicitly intended, never log raw tokens, and store only encrypted credentials. Test dispatch and force-sync flows should use the same queue contracts as production dispatch paths.

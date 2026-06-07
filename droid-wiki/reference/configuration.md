# Configuration

Aperio reads runtime configuration from environment variables. Use `.env.example` as the source of truth for local development.

## Core variables

| Variable | Consumed by | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Go API, Prisma, workers, MCP | Canonical Postgres connection string; Prisma may include `?schema=public` |
| `APERIO_CONNECT_ADDR` | `cmd/aperio/main.go` | Go API listen address, `:4100` locally |
| `APERIO_WEB_ORIGIN` | Go API | Credentialed CORS origin and web callback origin |
| `NEXT_PUBLIC_CONNECT_API_BASE_URL` | `apps/web/lib/api.ts` | Browser base URL for ConnectRPC |
| `APERIO_ENCRYPTION_KEY` | `internal/runtimeutil`, Go API/workers/MCP, `packages/security` | AES-256-GCM credential encryption key |
| `APERIO_AUTH_SECRET` | Go API | Session/email token HMAC secret |
| `APERIO_SESSION_TTL_HOURS` | Go API | Absolute session lifetime |
| `APERIO_SESSION_IDLE_MINUTES` | Go API | Idle session timeout |
| `APERIO_MFA_ISSUER` | Go API | TOTP issuer label |

## Local commands

```bash
npm run dev:connect
npm run dev:web
npm run worker:ingestion
npm run worker:siem
npm run mcp:broker
```

The Go API, ingestion worker, SIEM dispatcher, and MCP broker are the default runtime commands. Worker and MCP package scripts load local `.env` values through `scripts/dev-env.mjs` and set `DATABASE_URL` from `scripts/dev-config.mjs go-database-url`, which removes Prisma-only parameters and adds `sslmode=disable` for local pgx clients.

Credential-bearing runtime paths share the Go primitives in `internal/runtimeutil`. The same AES-256-GCM envelope is readable by allowed TypeScript frontend/test/tooling surfaces through `packages/security`; malformed, wrong-AAD, missing-key, or tampered envelopes fail closed without plaintext logs.

## Integrations

Google Workspace OAuth uses `GOOGLE_WORKSPACE_CLIENT_ID`, `GOOGLE_WORKSPACE_CLIENT_SECRET`, and `GOOGLE_WORKSPACE_REDIRECT_URI`. Service-account scans can also use `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL` and `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY`.

SIEM JSONL exports use `APERIO_SIEM_EXPORT_DIR`. Optional NATS publication uses `APERIO_EVENT_BUS`, `APERIO_NATS_URL`, and `APERIO_NATS_STREAM`.

## Tenant settings

Some operational settings are stored per tenant in the database and managed through Go API compatibility handlers: retention days, notification email, critical risk threshold, default SLA, auto-resolve behavior, SSO-only mode, and webhook alert URL.

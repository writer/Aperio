# Configuration

Most runtime configuration comes from `.env.example`, `package.json`, and `docker-compose.yml`. There is no layered config system or deployment manifest in this checkout.

## Environment variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Prisma, API, workers, MCP | Database connection string |
| `APERIO_ENCRYPTION_KEY` | `packages/security/src/crypto.ts` | Secret encryption key |
| `APERIO_AUTH_SECRET` | `apps/api/src/middleware/security.ts` | Token verification secret |
| `APERIO_WEB_ORIGIN` | `apps/api/src/server.ts` | CORS allowlist origin |
| `NEXT_PUBLIC_API_BASE_URL` | `apps/web/lib/api.ts` | Browser API base URL |
| `DEMO_ORGANIZATION_ID` | API auth fallback, seed assumptions | Demo tenant identity |
| `DEMO_USER_ID` | API auth fallback, seed assumptions | Demo user identity |
| `NODE_ENV` | API, Prisma, Next.js | Environment mode |

## Script configuration

The repo uses one root `package.json` for all startup and validation commands:

- `npm run dev:api`
- `npm run dev:web`
- `npm run worker:ingestion`
- `npm run worker:siem`
- `npm run mcp:broker`
- `npm run typecheck`
- `npm run build:web`
- `npm run db:generate`
- `npm run db:validate`

## Local services

`docker-compose.yml` defines the local Postgres instance. There are no other containers in the current checkout.

## Runtime assumptions

- The API listens on port 4000.
- The web app listens on port 3000.
- The MCP broker uses stdio rather than a TCP port.
- The API process starts the SIEM dispatcher internally.

## Tenant-level settings stored in the database

Some operational settings are not environment variables. They are stored per tenant through `apps/api/src/routes/admin.ts`, including retention days, notification email, critical risk threshold, default SLA, auto-resolve behavior, SSO-only mode, and webhook alert URL.

For the entities that store these settings, go to [Data models](data-models.md). For setup steps, go to [Getting started](../overview/getting-started.md).

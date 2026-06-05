# Debugging

Most failures in Aperio fall into four buckets: missing env vars, stale Prisma state, old API processes, or tenant/role mismatches. The code is small enough that a quick route-to-worker trace usually gets you to the fault.

## First checks

Health check:

```bash
curl http://127.0.0.1:4000/healthz
```

If the UI and API look out of sync, check which process owns port 4000:

```bash
lsof -nP -iTCP:4000 -sTCP:LISTEN
```

That matters because the repo has already hit stale-process issues where `/api/v1/siem/catalog` returned 404 even though `apps/api/src/routes/siem.ts` existed in the source tree.

## Common failures

### `APERIO_ENCRYPTION_KEY is required`

Source: `packages/security/src/crypto.ts`

Meaning: a route or worker tried to encrypt or decrypt provider credentials without a usable key in `.env`.

### `Invalid authentication configuration` or `Unauthorized`

Source: `apps/api/src/middleware/security.ts`

Meaning: the bearer token is missing or invalid in production mode, or the auth secret is unusable. In non-production, the middleware falls back to `DEMO_USER_ID` and `DEMO_ORGANIZATION_ID`.

### Prisma client errors after schema changes

Sources: `packages/db/prisma/schema.prisma`, `packages/db/src/client.ts`

Fix path:

```bash
npx prisma db push --schema packages/db/prisma/schema.prisma
npm run db:generate
npm run typecheck
```

### Read-only remediation failure

Source: `apps/api/src/routes/remediations.ts`

If an integration is in `READ_ONLY` mode, the route returns a 403 and tells you to reconnect with remediation scopes.

### SIEM 404s from the UI

Sources: `apps/api/src/server.ts`, `apps/api/src/routes/siem.ts`, `apps/web/components/connectors/siem-section.tsx`

If the UI says the SIEM API is missing, confirm the route is live on the currently running API process. A stale local process is the most likely cause.

## Useful files by symptom

| Symptom | First file to inspect |
| --- | --- |
| Auth or tenant errors | `apps/api/src/middleware/security.ts` |
| Missing findings | `workers/ingestion-worker.ts` |
| Remediation failures | `apps/api/src/routes/remediations.ts`, `apps/api/src/remediation/executor.ts` |
| SIEM delivery failures | `workers/siem-dispatcher.ts` |
| Agent proposal/task errors | `apps/api/src/routes/agents.ts`, `apps/mcp/src/server.ts` |
| UI request failures | `apps/web/lib/api.ts` |

## Logging model

There is no structured observability stack in this checkout. Most runtime debugging comes from process stdout, Prisma warnings/errors, and API responses.

If you need the coding patterns that explain these failures, go to [Patterns and conventions](patterns-and-conventions.md). For runtime setup, go to [Getting started](../overview/getting-started.md).

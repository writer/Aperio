# Tooling

The repo is built around a single Node workspace. `package.json` is the control plane for app startup, Prisma generation, and validation. There is no separate build system package or custom CLI in this checkout.

## Main tools

| Tool | Where it appears | Why it matters |
| --- | --- | --- |
| npm scripts | `package.json` | Starts apps and validation commands |
| tsx | `package.json` scripts | Runs TypeScript entry points directly |
| Next.js | `apps/web/app/layout.tsx`, `package.json` | Web application runtime and build |
| Express | `apps/api/src/server.ts` | REST API server |
| Prisma | `packages/db/prisma/schema.prisma`, `packages/db/src/client.ts` | Database access and schema management |
| Zod | `packages/shared/src/*.ts`, route files | Runtime validation and shared contracts |
| Tailwind | `apps/web/tailwind.config.ts`, `apps/web/components/ui/*.tsx` | UI styling |
| Docker Compose | `docker-compose.yml` | Local Postgres |

## Available scripts

From `package.json`:

```json
{
  "dev:api": "tsx apps/api/src/server.ts",
  "dev:web": "next dev apps/web -p 3000",
  "worker:ingestion": "tsx workers/ingestion-worker.ts",
  "worker:siem": "tsx workers/siem-dispatcher.ts",
  "mcp:broker": "tsx apps/mcp/src/server.ts",
  "build:web": "NEXT_TELEMETRY_DISABLED=1 next build apps/web",
  "typecheck": "tsc -p tsconfig.json --noEmit",
  "test:api": "tsx --test tests/**/*.test.ts",
  "verify": "npm run typecheck && npm run test:api && npm run db:validate && npm run audit:prod",
  "audit:prod": "npm audit --omit=dev",
  "db:generate": "prisma generate --schema packages/db/prisma/schema.prisma",
  "db:validate": "prisma validate --schema packages/db/prisma/schema.prisma",
  "backup:check": "tsx scripts/check-backup-readiness.ts"
}
```

## Missing tooling

The current checkout does not include:

- ESLint config
- Prettier config
- end-to-end test runner config

That means the repo is using TypeScript, Prisma, `node:test`, GitHub Actions, and manual smoke tests as its primary guardrails.

## Practical tips

- If types look stale after a schema change, run `npm run db:generate`.
- If the browser shows old behavior, make sure the API process on port 4000 is actually the one started from this checkout.
- Use `scripts/seed.ts` to get the UI into a useful state quickly.

For the commands themselves, go to [Getting started](../overview/getting-started.md). For quality expectations, go to [Testing](testing.md).

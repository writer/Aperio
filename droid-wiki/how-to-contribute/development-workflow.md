# Development workflow

1. Install Node, npm, Go, and Docker.
2. Copy `.env.example` to `.env` and fill in local secrets.
3. Start Postgres with `docker compose up -d`.
4. Run migrations with Prisma.
5. Start the Go API with `npm run dev:connect`.
6. Start the web console and any Go worker or MCP processes you need.

```bash
npm install
npm run db:generate
npx prisma migrate dev --schema packages/db/prisma/schema.prisma
npm run dev:connect
npm run dev:web
npm run mcp:broker
npm run worker:ingestion
npm run worker:siem
```

The worker and MCP scripts load `.env` through the local env helper and use `scripts/dev-config.mjs go-database-url` so Go processes receive a pgx-safe `DATABASE_URL`.

## Validation

Run the fastest relevant checks while iterating, then run the aggregate verifier before opening a PR:

```bash
npm run verify
```

`npm run verify` covers generated-client drift, TypeScript typecheck, migration guardrails, API/contract tests, Prisma validation, Go tests, DB-backed Go tests, Go/protobuf linting, web build, bounded Go worker and SIEM smokes, E2E smoke, production audit, and leak check.

Useful targeted checks:

```bash
npm run guardrails:migration
npm run typecheck
npm run test:api
npm run test:go
npm run db:validate
npm run build:web
npm run leak:check
npm run proto:lint
```

## Where to start

- API contract work: `proto/aperio/v1/api.proto` -> `internal/bootstrap` -> `packages/connect/src` -> `apps/web/lib/api.ts`
- Connector work: `internal/bootstrap/compat_api.go`, `packages/shared/src/connectors.ts`, `internal/ingestionworker`, connector UI
- SIEM work: `internal/bootstrap/compat_api.go`, `packages/shared/src/siem.ts`, `internal/siemdispatcher`, SIEM UI
- Agent work: `packages/shared/src/a2a.ts`, `internal/bootstrap/compat_api.go`, `internal/mcpbroker`

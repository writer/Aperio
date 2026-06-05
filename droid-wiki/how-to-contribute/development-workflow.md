# Development workflow

The repo uses one root `package.json`, one Prisma schema, and several app entry points. Most work starts with the database, then the API, then the web UI.

## Usual workflow

1. Start Postgres from `docker-compose.yml`.
2. Update `.env` from `.env.example` if needed.
3. If the schema changes, run `npx prisma db push --schema packages/db/prisma/schema.prisma` and `npm run db:generate`.
4. Start the API with `npm run dev:api`.
5. Start the web app with `npm run dev:web`.
6. Seed demo data with `npx tsx scripts/seed.ts` if the UI needs fixtures.
7. Run validation commands before you stop.

## Commands you will actually use

```bash
npm run dev:api
npm run dev:web
npm run mcp:broker
npm run worker:ingestion
npm run worker:siem
npm run typecheck
npm run build:web
npm run db:generate
npm run db:validate
```

## Schema-first changes

If you touch `packages/db/prisma/schema.prisma`, follow this order:

1. Update the schema.
2. Push the schema to the local database.
3. Regenerate the Prisma client.
4. Fix TypeScript errors in routes, workers, and UI types.
5. Smoke test the changed flows.

## API-first changes

For route work in `apps/api/src/routes/*.ts`:

- add or update Zod schemas in `packages/shared/src/*.ts` when the payload is reused
- keep tenant scoping on every query
- write audit logs for privileged actions
- return serialized dates as ISO strings

## UI-first changes

For web changes in `apps/web/components/**/*.tsx`:

- start from `apps/web/lib/api.ts`
- match existing component patterns in `apps/web/components/ui/*.tsx`
- prefer adding fields to shared API types over inline `any`
- smoke test the route in the browser after `npm run build:web`

## Agent and SIEM changes

These features span more than one process. If you touch them, trace the end-to-end flow:

- A2A: `packages/shared/src/a2a.ts` -> `apps/api/src/routes/agents.ts` -> `apps/mcp/src/server.ts`
- SIEM: `packages/shared/src/siem.ts` -> `apps/api/src/routes/siem.ts` -> `workers/siem-dispatcher.ts` -> UI in `apps/web/components/connectors/siem-section.tsx`

For validation advice, go to [Testing](testing.md). For debugging patterns, go to [Debugging](debugging.md).

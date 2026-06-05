# Testing

This checkout has no formal test suite. There are no unit-test or integration-test files under `apps/`, `packages/`, `workers/`, or `scripts/`. The current test strategy is static validation plus targeted smoke tests.

## Baseline validation

Run these for most changes:

```bash
npm run typecheck
npm run build:web
npm run db:validate
```

If you changed the Prisma schema, also run:

```bash
npx prisma db push --schema packages/db/prisma/schema.prisma
npm run db:generate
```

## What to smoke test

### Connector changes

- `GET /api/v1/integrations/catalog`
- connect or disconnect through `apps/web/components/connectors/connectors-page.tsx`
- fetch and update check state through `apps/api/src/routes/integrations.ts`

### Finding and remediation changes

- `POST /api/v1/ingestion/events`
- `GET /api/v1/findings`
- `POST /api/v1/findings/:id/remediate`
- dashboard modal flow in `apps/web/components/dashboard/dashboard-page.tsx`

### SIEM changes

- `GET /api/v1/siem/catalog`
- create, test, and delete destinations through `apps/api/src/routes/siem.ts`
- verify outbox behavior in `workers/siem-dispatcher.ts`

### Agent changes

- `GET /api/v1/agents`
- create tasks and proposals through `apps/api/src/routes/agents.ts`
- initialize and `tools/list` the broker in `apps/mcp/src/server.ts`

## Demo data helpers

Use `npx tsx scripts/seed.ts` to create one tenant, three integrations, and three findings. That is the quickest way to get the dashboard, apps page, and admin page into a useful state.

## What is missing

- no Jest, Vitest, Playwright, or Cypress config
- no CI workflow to enforce checks
- no load test or contract test harness

That gap shows up in the code structure. Large files like `apps/web/components/connectors/connectors-page.tsx` and `apps/web/components/admin/admin-page.tsx` are validated mostly by type safety and manual runs.

For day-to-day commands, go to [Development workflow](development-workflow.md). For common failures to check during smoke tests, go to [Debugging](debugging.md).

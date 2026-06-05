# Contributing

Aperio is small enough that most changes touch more than one layer. A connector change usually touches the Prisma schema, shared catalogs, one or more API routes, and the web client in `apps/web/lib/api.ts`. The safest way to work is to trace the whole flow before editing.

## Before you start

- Read [Overview](../overview/index.md) and [Architecture](../overview/architecture.md).
- Check the shared contracts in `packages/shared/src` before adding route-local types.
- Treat the tenant boundary in `apps/api/src/middleware/security.ts` as non-negotiable.
- Check whether a UI change also needs an API or Prisma change.

## Definition of done in this repo

A change is usually done when all of these are true:

1. Prisma schema and generated client are in sync if you touched `packages/db/prisma/schema.prisma`.
2. `npm run typecheck` passes.
3. `npm run build:web` passes for UI changes.
4. Any new route or workflow has been smoke tested locally.
5. Audit logging is preserved for admin, connector, SIEM, or remediation actions.

## Normal work areas

- Connector and findings work: `packages/shared/src/connectors.ts`, `apps/api/src/routes/integrations.ts`, `workers/ingestion-worker.ts`, `apps/web/components/connectors/connectors-page.tsx`
- SIEM work: `packages/shared/src/siem.ts`, `apps/api/src/routes/siem.ts`, `workers/siem-dispatcher.ts`, `apps/web/components/connectors/siem-section.tsx`
- Agent work: `packages/shared/src/a2a.ts`, `apps/api/src/routes/agents.ts`, `apps/mcp/src/server.ts`
- Tenant/admin work: `apps/api/src/routes/admin.ts`, `apps/web/components/admin/admin-page.tsx`

## What this repo does not give you yet

- No automated unit or integration test suite
- No CI configuration in the current checkout
- No contributor metadata or CODEOWNERS because `.git` is missing

Go next to [Development workflow](development-workflow.md), [Testing](testing.md), and [Patterns and conventions](patterns-and-conventions.md).

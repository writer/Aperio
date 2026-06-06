# Lore

Aperio has evolved from a tenant-scoped SSPM prototype into a Go/ConnectRPC API with a Next.js console, Prisma/Postgres state, TypeScript workers, and an MCP broker.

The oldest visible product layer is still the SSPM core: connectors, findings, dashboard metrics, admin settings, SIEM destinations, and remediation. Those workflows now enter through `internal/bootstrap` and the web console in `apps/web`.

The detection layer lives mostly in `workers/ingestion-worker.ts`, where queued SaaS events become findings, OAuth app grants, assets, and SIEM delivery rows. The SIEM layer lives in `workers/siem-dispatcher.ts` and `packages/shared/src/siem.ts`.

The latest orchestration layer is the A2A/MCP model. `packages/shared/src/a2a.ts`, `apps/mcp/src/server.ts`, the Go compatibility handlers, and the `Agent*` tables in Prisma let agents create tasks, exchange messages, and propose human-approved actions.

Recent migration work removed the legacy Express API tree. The remaining Node runtime is intentional: web, workers, MCP, tests, scripts, and npm tooling.

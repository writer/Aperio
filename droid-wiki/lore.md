# Lore

Aperio has evolved from a tenant-scoped SSPM prototype into Go-owned API, worker, and MCP runtimes with a Next.js console and Prisma/Postgres state.

The oldest visible product layer is still the SSPM core: connectors, findings, dashboard metrics, admin settings, SIEM destinations, and remediation. Those workflows now enter through `internal/bootstrap` and the web console in `apps/web`.

The detection layer lives mostly in `internal/ingestionworker`, where queued SaaS events become findings, OAuth app grants, assets, and SIEM delivery rows. The SIEM layer lives in `internal/siemdispatcher` and `packages/shared/src/siem.ts`.

The latest orchestration layer is the A2A/MCP model. `packages/shared/src/a2a.ts`, `internal/mcpbroker`, the Go compatibility handlers, and the `Agent*` tables in Prisma let agents create tasks, exchange messages, and propose human-approved actions.

Recent migration work removed the legacy Express API tree and TypeScript backend/worker/MCP runtimes. The remaining Node/TypeScript runtime is intentional: frontend, generated contracts, tests, scripts, Prisma, and npm tooling.

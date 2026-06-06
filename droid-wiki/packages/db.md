# DB

Active contributors: unavailable in this checkout because git history is missing.

The `db` package defines the persistent model for tenants, integrations, findings, SIEM delivery, and agent workflows. It is the structural center of the repo because both the API and the MCP broker write through it.

## Directory layout

```text
packages/db/
├── prisma/
│   └── schema.prisma
└── src/
    └── client.ts
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `packages/db/prisma/schema.prisma` | Prisma enums and models for the full product state |
| `packages/db/src/client.ts` | Shared Prisma client singleton with development caching |

## How it works

`packages/db/prisma/schema.prisma` models four broad domains:

1. tenant identity and roles
2. connector integrations, ingested events, and findings
3. SIEM destinations and durable deliveries
4. agents, tasks, messages, and proposals

The client in `packages/db/src/client.ts` is cached on `globalThis` outside production so local hot reloads do not create a new Prisma client on every import.

## Key source files

| File | Purpose |
| --- | --- |
| `packages/db/prisma/schema.prisma` | Defines `Organization`, `IntegrationConnection`, `SecurityFinding`, `SiemDestination`, `SiemDelivery`, `AgentTask`, and related enums |
| `packages/db/src/client.ts` | Exports `prisma` for apps and workers |
| `scripts/seed.ts` | Shows how the Prisma model is expected to be populated for demo data |

## Integration points

- Used by the Go API through SQL/Prisma-compatible tables and by TypeScript workers through Prisma
- Imported by `apps/mcp/src/server.ts`
- Imported by `workers/ingestion-worker.ts` and `workers/siem-dispatcher.ts`

## Entry points for modification

Start in `packages/db/prisma/schema.prisma` for any persistent feature change. Then regenerate the client and fix any route, worker, or UI type errors that the new schema creates.

For the schema-level entities, go to [Data models](../reference/data-models.md). For the shared application contracts that sit on top of the schema, go to [Shared](shared.md).

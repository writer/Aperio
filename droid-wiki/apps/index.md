# Apps

Active contributors: unavailable in this checkout because git history is missing.

Aperio has three runnable apps under `apps/`: the REST API, the web console, and the MCP broker. Together they cover operator workflows, machine-to-machine workflows, and the persistence layer behind both.

## Directory layout

```text
apps/
├── api/
│   └── src/
│       ├── middleware/
│       ├── remediation/
│       ├── routes/
│       └── server.ts
├── mcp/
│   └── src/server.ts
└── web/
    ├── app/
    ├── components/
    └── lib/
```

## App summary

| App | Entry point | Purpose |
| --- | --- | --- |
| API | `apps/api/src/server.ts` | Tenant-scoped REST backend |
| Web | `apps/web/app/page.tsx` | Operator console |
| MCP broker | `apps/mcp/src/server.ts` | JSON-RPC tool surface for agent workflows |

## How they fit together

- The web app calls the REST API through `apps/web/lib/api.ts`.
- The API and MCP broker both persist to the same Prisma schema through `packages/db/src/client.ts`.
- The API starts the SIEM dispatcher in `workers/siem-dispatcher.ts` and enqueues ingestion work into `workers/ingestion-worker.ts`.

## Entry points for modification

Start with the app that owns the user or machine surface you want to change. If the change crosses apps, follow the contract back into `packages/shared/src` before you edit route or component code.

- [API](api.md)
- [Web](web.md)
- [MCP broker](mcp.md)
- [Features](../features/index.md)

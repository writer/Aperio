# Apps

Aperio has three app-style entry points plus background workers:

```text
apps/
├── web/   Next.js operator console
└── mcp/   stdio MCP broker
cmd/
└── aperio/ Go API entrypoint
workers/   ingestion and SIEM processors
```

| Surface | Entry point | Purpose |
| --- | --- | --- |
| Go API | `cmd/aperio/main.go` | Tenant-scoped HTTP API, ConnectRPC, compatibility dispatch |
| Web console | `apps/web/app/layout.tsx` | Operator UI for findings, connectors, SIEM, admin, and shadow IT |
| MCP broker | `apps/mcp/src/server.ts` | JSON-RPC tool surface for agent workflows |
| Workers | `workers/*.ts` | Durable ingestion and SIEM outbox processing |

The web console calls the Go API through generated ConnectRPC clients in `packages/connect/src` and the typed facade in `apps/web/lib/api.ts`.

For details, see:

- [Go API](api.md)
- [Web console](web.md)
- [MCP broker](mcp.md)

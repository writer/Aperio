# Apps

Aperio has a Next.js app plus Go runtime entry points for API, workers, and MCP:

```text
apps/
└── web/                 Next.js operator console
cmd/
├── aperio/              Go API entrypoint
├── ingestion-worker/    Go ingestion worker entrypoint
├── siem-dispatcher/     Go SIEM dispatcher entrypoint
└── mcp-broker/          Go stdio MCP broker entrypoint
```

| Surface | Entry point | Purpose |
| --- | --- | --- |
| Go API | `cmd/aperio/main.go` | Tenant-scoped HTTP API, ConnectRPC, compatibility dispatch |
| Web console | `apps/web/app/layout.tsx` | Operator UI for findings, connectors, SIEM, admin, and shadow IT |
| MCP broker | `cmd/mcp-broker`, `internal/mcpbroker` | JSON-RPC tool surface for agent workflows |
| Workers | `cmd/ingestion-worker`, `cmd/siem-dispatcher` | Durable ingestion and SIEM outbox processing |

The web console calls the Go API through generated ConnectRPC clients in `packages/connect/src` and the typed facade in `apps/web/lib/api.ts`.

For details, see:

- [Go API](api.md)
- [Web console](web.md)
- [MCP broker](mcp.md)

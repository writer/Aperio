# Tooling

| Tool | Used for |
| --- | --- |
| Go | API server, ConnectRPC handlers, protobuf validation |
| Node/npm | Web app, TypeScript workers, MCP broker, scripts, tests |
| Next.js | Operator console |
| Prisma | Schema, migrations, generated client |
| Buf | Protobuf linting and generated code |
| tsx | TypeScript workers, scripts, and tests |

Key scripts:

```json
{
  "dev:connect": "go run ./cmd/aperio",
  "dev:web": "next dev apps/web -p 3000",
  "worker:ingestion": "tsx workers/ingestion-worker.ts",
  "worker:siem": "tsx workers/siem-dispatcher.ts",
  "mcp:broker": "tsx apps/mcp/src/server.ts",
  "test:go": "go test ./...",
  "proto:lint": "go run github.com/bufbuild/buf/cmd/buf@v1.59.0 lint"
}
```

The legacy Express server script and dependencies have been removed.

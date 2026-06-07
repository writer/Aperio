# Tooling

| Tool | Used for |
| --- | --- |
| Go | API server, ConnectRPC handlers, protobuf validation |
| Node/npm | Web app, generated TypeScript contracts, local scripts, tests |
| Next.js | Operator console |
| Prisma | Schema, migrations, generated client |
| Buf | Protobuf linting and generated code |
| tsx | Local TypeScript scripts and tests |

Key scripts:

```json
{
  "dev:connect": "go run ./cmd/aperio",
  "dev:web": "next dev apps/web -p 3000",
  "worker:ingestion": "go run ./cmd/ingestion-worker",
  "worker:siem": "go run ./cmd/siem-dispatcher",
  "mcp:broker": "go run ./cmd/mcp-broker",
  "test:go": "go test ./...",
  "proto:lint": "go run github.com/bufbuild/buf/cmd/buf@v1.59.0 lint"
}
```

The legacy Express server script and dependencies have been removed.

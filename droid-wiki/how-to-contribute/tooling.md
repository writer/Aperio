# Tooling

| Tool | Used for |
| --- | --- |
| Go | API server, ConnectRPC handlers, ingestion worker, SIEM dispatcher, MCP broker, protobuf validation |
| Node/npm | Web app, generated TypeScript contracts, local scripts, tests, Prisma tooling |
| Next.js | Operator console |
| Prisma | Schema, migrations, generated client |
| Buf | Protobuf linting and generated code |
| tsx | Local TypeScript scripts and tests |

Representative package scripts:

```json
{
  "dev:connect": "go run ./cmd/aperio",
  "dev:web": "next dev apps/web -p 3000",
  "worker:ingestion": "DATABASE_URL=\"$(node scripts/dev-config.mjs go-database-url)\" node scripts/dev-env.mjs go run ./cmd/ingestion-worker",
  "worker:siem": "DATABASE_URL=\"$(node scripts/dev-config.mjs go-database-url)\" node scripts/dev-env.mjs go run ./cmd/siem-dispatcher",
  "mcp:broker": "DATABASE_URL=\"$(node scripts/dev-config.mjs go-database-url)\" node scripts/dev-env.mjs go run ./cmd/mcp-broker",
  "verify": "aggregate final gate: generation, typecheck, guardrails, tests, build, smokes, audit, leak check",
  "test:go": "go test ./...",
  "proto:lint": "go run github.com/bufbuild/buf/cmd/buf@v1.59.0 lint"
}
```

The worker and MCP scripts use the local env loader plus `go-database-url` so Go pgx clients receive a DSN without Prisma-only query parameters.

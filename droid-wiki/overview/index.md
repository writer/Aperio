# Overview

Aperio is a multi-tenant SaaS security posture management prototype. It combines a Go/ConnectRPC API, a Next.js console, Prisma-backed Postgres storage, TypeScript background workers, and a stdio MCP broker for agent workflows.

Key runtime pieces:

- `cmd/aperio/main.go` starts the Go API on `APERIO_CONNECT_ADDR`.
- `internal/bootstrap` owns API wiring, auth/session handling, CORS, readiness, typed RPCs, and the `/api/v1/*` compatibility dispatch used by the web console.
- `apps/web` contains the Next.js operator console.
- `workers/ingestion-worker.ts` evaluates queued SaaS events and writes findings/assets.
- `workers/siem-dispatcher.ts` drains SIEM delivery rows.
- `apps/mcp/src/server.ts` exposes agent and SIEM workflows over stdio JSON-RPC.

```text
aperio/
├── cmd/aperio/       Go API entrypoint
├── internal/         Go API bootstrap, config, telemetry
├── apps/web/         Next.js console
├── apps/mcp/         stdio MCP broker
├── workers/          ingestion and SIEM workers
├── packages/         Prisma, shared schemas, security, Connect client
├── proto/            protobuf contracts
└── gen/              generated Go and TypeScript contract code
```

Typical data flow:

1. A tenant connects a SaaS app through the web console and Go API compatibility endpoints.
2. Provider events are queued in Postgres for `workers/ingestion-worker.ts`.
3. The worker evaluates detections, creates findings/assets, and enqueues SIEM deliveries.
4. `workers/siem-dispatcher.ts` ships canonical envelopes to configured SIEM destinations.
5. Agent clients use `apps/mcp/src/server.ts` for task/proposal workflows against the same Prisma-backed data model.

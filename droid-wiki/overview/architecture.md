# Architecture

Aperio has four active runtime surfaces: the Go/ConnectRPC API, the Next.js console, the MCP broker, and TypeScript background workers. Shared schemas live in `packages/shared/src`, persistent state lives in `packages/db/prisma/schema.prisma`, and secret handling lives in `packages/security/src/crypto.ts`.

```mermaid
flowchart LR
  UI[Next.js web app\napps/web] -->|ConnectRPC / CallApi| API[Go API\ncmd/aperio + internal/bootstrap]
  API -->|Prisma/Postgres| DB[(Postgres)]
  Worker[Ingestion worker\nworkers/ingestion-worker.ts] --> DB
  SIEM[SIEM dispatcher\nworkers/siem-dispatcher.ts] --> DB
  SIEM --> Destinations[Splunk / Panther / Elastic / Datadog / Webhook / JSONL]
  MCP[MCP broker\napps/mcp/src/server.ts] --> DB
```

## API boundary

The Go API exposes typed ConnectRPC methods from `proto/aperio/v1/api.proto`. The web console also sends REST-shaped `/api/v1/*` requests through the `CallApi` RPC in `apps/web/lib/api.ts`; those routes are compatibility handlers in `internal/bootstrap/compat_api.go` until each workflow graduates to typed RPCs.

## Ingestion and SIEM flow

```mermaid
sequenceDiagram
  participant UI as Operator UI
  participant API as Go API
  participant DB as Postgres
  participant Worker as ingestion-worker
  participant SIEM as siem-dispatcher

  UI->>API: Connect/force-sync provider
  API->>DB: Store connector / enqueue ingestion job
  Worker->>DB: Lease ingestion job and write findings/assets
  Worker->>DB: Create SIEM delivery rows
  SIEM->>DB: Lease delivery rows
  SIEM-->>SIEM: Adapt canonical envelope
  SIEM->>DB: Mark delivered or retry/dead-letter
```

## Security model

- Sessions are stored in `user_sessions` and carried by the `aperio_session` HttpOnly cookie.
- The Go API validates cookie token hashes directly against Postgres.
- `APERIO_WEB_ORIGIN` controls credentialed browser CORS.
- Tenant scoping is enforced in Go API queries and worker leases by `organization_id`.
- Credentials are encrypted with AES-256-GCM helpers in `packages/security`.

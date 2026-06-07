# Dependencies

Aperio is now a Go API, Go worker, and Go MCP runtime with a TypeScript web/tooling layer. The Node dependency set supports the web app, generated contracts, Prisma tooling, tests, validation scripts, and build tooling.

## Runtime and framework dependencies

| Dependency | Used by | Purpose |
| --- | --- | --- |
| Go `net/http` | `cmd/aperio`, `internal/bootstrap` | HTTP server runtime |
| `connectrpc.com/connect` | Go API | ConnectRPC handlers |
| `@connectrpc/connect`, `@connectrpc/connect-web` | `packages/connect`, `apps/web` | Browser ConnectRPC client |
| `next`, `react`, `react-dom` | `apps/web` | Operator console |
| `@prisma/client`, `prisma` | scripts and generated local tooling | Database client generation and migrations |
| `zod` | shared TypeScript schemas | Runtime validation for TS surfaces |
| `nats` | validation/event-bus tooling | Optional event publication in local tests |
| `tsx`, `typescript` | tests and scripts | TypeScript execution and checking |

## Runtime boundary

Browser CORS and HTTP hardening live in the Go API and deployment edge configuration. Node dependencies are intentionally scoped to the web console, generated contracts, tests, Prisma, and local tooling.

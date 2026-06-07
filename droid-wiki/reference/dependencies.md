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

## Removed runtime dependencies

The legacy Express API dependencies (`express`, `cors`, `helmet`, `compression`) are no longer present. Browser CORS and HTTP hardening live in the Go API and deployment edge configuration.

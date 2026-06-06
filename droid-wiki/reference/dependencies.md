# Dependencies

Aperio is now a Go API plus TypeScript web/workers/tooling project. The Node dependency set supports the web app, workers, MCP broker, Prisma, tests, and build tooling; the API server itself is Go/ConnectRPC.

## Runtime and framework dependencies

| Dependency | Used by | Purpose |
| --- | --- | --- |
| Go `net/http` | `cmd/aperio`, `internal/bootstrap` | HTTP server runtime |
| `connectrpc.com/connect` | Go API | ConnectRPC handlers |
| `@connectrpc/connect`, `@connectrpc/connect-web` | `packages/connect`, `apps/web` | Browser ConnectRPC client |
| `next`, `react`, `react-dom` | `apps/web` | Operator console |
| `@prisma/client`, `prisma` | API, workers, MCP, scripts | Database client and migrations |
| `zod` | shared TypeScript schemas | Runtime validation for TS surfaces |
| `nats` | workers/event bus | Optional event publication |
| `tsx`, `typescript` | workers, tests, scripts | TypeScript execution and checking |

## Removed runtime dependencies

The legacy Express API dependencies (`express`, `cors`, `helmet`, `compression`) are no longer present. Browser CORS and HTTP hardening live in the Go API and deployment edge configuration.

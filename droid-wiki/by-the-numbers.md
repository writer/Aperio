# By the numbers

This page is a high-level snapshot, not a generated report from the current commit.

## Current shape

| Area | Main paths |
| --- | --- |
| Go API | `cmd/aperio`, `internal`, `proto`, `gen` |
| Web console | `apps/web` |
| MCP broker | `apps/mcp` |
| Workers | `workers` |
| Shared packages | `packages/connect`, `packages/db`, `packages/security`, `packages/shared` |
| Tests | `internal/bootstrap/app_test.go`, `tests/*.test.ts` |

The largest maintenance areas are the web console, integration/SIEM catalogs, ingestion worker, SIEM dispatcher, and Go compatibility handlers.

## Migration note

The legacy Express API source tree has been removed. Node remains for Next.js, TypeScript workers, MCP, tests, scripts, and npm tooling.

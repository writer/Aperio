# Features

| Feature | Main implementation |
| --- | --- |
| Connectors and integrations | `internal/bootstrap/compat_api.go`, `packages/shared/src/connectors.ts`, `workers/ingestion-worker.ts`, `apps/web/components/connectors/connectors-page.tsx` |
| Findings and remediation | `internal/bootstrap/compat_api.go`, `workers/ingestion-worker.ts`, `apps/web/components/findings` |
| SIEM delivery | `internal/bootstrap/compat_api.go`, `packages/shared/src/siem.ts`, `workers/siem-dispatcher.ts`, `apps/web/components/connectors/siem-page.tsx` |
| Admin and governance | `internal/bootstrap/compat_api.go`, `apps/web/components/admin` and settings pages |
| Agent orchestration | `packages/shared/src/a2a.ts`, `internal/bootstrap/compat_api.go`, `apps/mcp/src/server.ts` |

The API is Go/ConnectRPC. TypeScript remains for the web console, MCP broker, workers, shared catalogs, and tooling.

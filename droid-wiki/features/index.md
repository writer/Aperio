# Features

| Feature | Main implementation |
| --- | --- |
| Connectors and integrations | `internal/bootstrap/compat_api.go`, `packages/shared/src/connectors.ts`, `internal/ingestionworker`, `apps/web/components/connectors/connectors-page.tsx` |
| Findings and remediation | `internal/bootstrap/compat_api.go`, `internal/ingestionworker`, `apps/web/components/findings` |
| SIEM delivery | `internal/bootstrap/compat_api.go`, `packages/shared/src/siem.ts`, `internal/siemdispatcher`, `apps/web/components/connectors/siem-page.tsx` |
| Admin and governance | `internal/bootstrap/compat_api.go`, `apps/web/components/admin` and settings pages |
| Agent orchestration | `packages/shared/src/a2a.ts`, `internal/bootstrap/compat_api.go`, `internal/mcpbroker` |

The API, ingestion worker, SIEM dispatcher, and MCP broker are Go-owned. TypeScript remains for the web console, generated contracts, shared catalogs, tests, Prisma, and local tooling.

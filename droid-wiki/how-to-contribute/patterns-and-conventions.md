# Patterns and conventions

## API changes

Prefer typed ConnectRPC methods for new workflows:

```mermaid
flowchart LR
  Proto[proto/aperio/v1/api.proto] --> Generate[Buf generate]
  Generate --> Go[internal/bootstrap handler]
  Generate --> TS[packages/connect client]
  TS --> Web[apps/web/lib/api.ts]
```

Use `CallApi` compatibility handlers only when preserving an existing `/api/v1/*` browser contract during migration.

## Tenant scoping

Every API handler, worker lease, and MCP tool must scope data by organization. Never trust IDs from the request body without checking they belong to the authenticated organization.

## Validation

| Area | Pattern |
| --- | --- |
| Go API | Parse/validate inputs, enforce role, scope SQL by organization, serialize stable response shapes |
| TypeScript workers | Validate payloads before processing, mark retries/dead letters explicitly |
| Web | Keep API calls behind `apps/web/lib/api.ts` |
| MCP | Validate tool inputs and map errors to JSON-RPC responses |

## Secrets

Use shared AES-GCM envelopes for credentials. If Go writes a secret that a TypeScript worker reads, add a cross-runtime test or fixture proving compatibility.

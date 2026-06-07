# Connectors and integrations

Connectors let a tenant attach SaaS providers, store encrypted credentials, configure checks, and enqueue ingestion work.

## Main files

| File | Purpose |
| --- | --- |
| `internal/bootstrap/compat_api.go` | Connector catalog, create/update, OAuth, checks, force-sync compatibility handlers |
| `packages/shared/src/connectors.ts` | TypeScript connector catalog and UI-facing metadata |
| `apps/web/components/connectors/connectors-page.tsx` | Connector UI |
| `internal/ingestionworker` | Provider event processing and finding generation |
| `packages/db/prisma/schema.prisma` | `IntegrationConnection`, `IngestionJob`, `IngestedEvent`, findings/assets |

## Flow

```mermaid
flowchart LR
  UI[Connectors page] --> API[Go CallApi compatibility]
  API --> DB[(IntegrationConnection / IngestionJob)]
  Worker[Go ingestion worker] --> DB
  Worker --> Findings[SecurityFinding / SecurityAsset]
```

A connector definition drives UI labels, required fields, scopes, and check defaults. Go compatibility handlers persist tenant-scoped connections and queue work; the ingestion worker consumes queued events and writes normalized findings.

## Runtime ownership note

The API and ingestion worker runtimes are Go-owned. TypeScript remains for the connector catalog metadata consumed by the frontend and for validation fixtures/tests, so keep catalog semantics, encryption envelopes, and queue contracts aligned across those allowed TypeScript surfaces and the Go worker.

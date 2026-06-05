# Connectors and integrations

Active contributors: unavailable in this checkout because git history is missing.

This feature owns the provider catalog, credential collection, integration records, and per-connector detection toggles. It is the first thing most operators touch because every finding starts with a connected SaaS app.

## Directory layout

```text
packages/shared/src/connectors.ts
apps/api/src/routes/integrations.ts
apps/web/components/connectors/
├── connectors-page.tsx
└── provider-icon.tsx
workers/ingestion-worker.ts
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `packages/shared/src/connectors.ts` | Provider catalog, credential fields, scopes, remediation actions, finding checks |
| `apps/api/src/routes/integrations.ts` | Catalog endpoint, connect/disconnect, check state endpoints |
| `apps/web/components/connectors/connectors-page.tsx` | Connector catalog UI and modal flow |
| `workers/ingestion-worker.ts` | Consumes integration settings, especially disabled checks |

## How it works

A connector definition from `packages/shared/src/connectors.ts` drives both the UI form and the backend behavior. The route in `apps/api/src/routes/integrations.ts` encrypts the credentials, stores the effective scopes for the selected mode, and initializes `disabledChecks` from the catalog defaults.

```mermaid
flowchart LR
  Catalog[Connector catalog] --> UI[Connector modal]
  UI --> API[/api/v1/integrations]
  API --> DB[IntegrationConnection]
  DB --> Worker[ingestion-worker]
  Worker --> Findings[SecurityFinding]
```

## Providers in the catalog

The current catalog includes GitHub, Slack, Google Workspace, 1Password, Okta, Microsoft 365, and Atlassian. Detection logic in `workers/ingestion-worker.ts` is only implemented for GitHub, Slack, and Google Workspace in this checkout, so catalog breadth is wider than rule breadth.

## Integration points

- Depends on the provider enum in `packages/shared/src/types.ts`
- Stores encrypted credentials through `packages/security/src/crypto.ts`
- Feeds findings into `workers/ingestion-worker.ts`
- Exposes state in the dashboard, apps page, and per-app drilldown views

## Entry points for modification

Add a provider in `packages/shared/src/connectors.ts` first. Then update any worker rule logic, route behavior, and UI rendering that depends on the new provider. If the provider also needs remediation or SIEM behavior, follow the links into those feature pages.

Go next to [Findings and remediation](findings-and-remediation.md) and [Shared](../packages/shared.md).

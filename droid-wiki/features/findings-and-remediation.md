# Findings and remediation

Active contributors: unavailable in this checkout because git history is missing.

This feature turns provider events into security findings, shows them in the console, and optionally applies provider write actions to resolve them. It is the main operator loop in the product.

## Directory layout

```text
apps/api/src/routes/
├── dashboard.ts
├── findings.ts
└── remediations.ts
apps/api/src/remediation/executor.ts
workers/ingestion-worker.ts
apps/web/components/
├── dashboard/dashboard-page.tsx
└── apps/app-findings-page.tsx
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `workers/ingestion-worker.ts` | Evaluates inbound events into findings |
| `apps/api/src/routes/findings.ts` | Lists and resolves findings |
| `apps/api/src/routes/remediations.ts` | Executes remediation actions against providers |
| `apps/api/src/remediation/executor.ts` | Provider action handlers and stubs |
| `apps/web/components/dashboard/dashboard-page.tsx` | Dashboard table and remediation modal |
| `apps/web/components/apps/app-findings-page.tsx` | Per-integration findings drilldown |

## How it works

The ingestion worker stores an `IngestedEvent`, evaluates rule functions, computes a dedupe key, and upserts `SecurityFinding` rows. The dashboard and app pages read those findings back through `apps/web/lib/api.ts`. If an integration is in `REMEDIATION` mode, the remediation route decrypts the provider token, runs a handler, resolves the finding on success, and writes an audit log.

```mermaid
flowchart LR
  Event[Ingested event] --> Eval[Rule evaluation]
  Eval --> Finding[SecurityFinding upsert]
  Finding --> Dashboard[Dashboard and app pages]
  Dashboard --> Remediate[/POST /findings/:id/remediate]
  Remediate --> Exec[remediation/executor.ts]
  Exec --> Resolve[Mark finding resolved]
```

## Current rule coverage

`workers/ingestion-worker.ts` implements finding rules for:

- public GitHub repositories
- Slack MFA disablement
- Google Workspace external sharing

The rest of the connector catalog exists, but equivalent rule logic is not visible in this checkout yet.

## Integration points

- Depends on connector catalogs in `packages/shared/src/connectors.ts`
- Writes to `SecurityFinding` and `TenantAuditLog` in `packages/db/prisma/schema.prisma`
- Can enqueue canonical finding payloads into the SIEM outbox in `workers/siem-dispatcher.ts`

## Entry points for modification

Add or change detection in `workers/ingestion-worker.ts`. Add or change response shape in `apps/api/src/routes/findings.ts`. Add or change provider write behavior in `apps/api/src/remediation/executor.ts` and `apps/api/src/routes/remediations.ts`.

For the app-level views, go to [Web](../apps/web.md). For outbound finding delivery, go to [SIEM delivery](siem-delivery.md).

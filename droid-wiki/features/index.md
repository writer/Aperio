# Features

Active contributors: unavailable in this checkout because git history is missing.

The repo is best understood as five product capabilities layered on one shared tenant model: connectors and event intake, findings and remediation, SIEM fanout, tenant administration, and agent orchestration. Each feature spans more than one directory, which is why this section exists alongside [Apps](../apps/index.md) and [Packages](../packages/index.md).

## Feature map

| Feature | Main code paths |
| --- | --- |
| Connectors and integrations | `packages/shared/src/connectors.ts`, `apps/api/src/routes/integrations.ts`, `apps/web/components/connectors/connectors-page.tsx` |
| Findings and remediation | `apps/api/src/routes/findings.ts`, `apps/api/src/routes/remediations.ts`, `workers/ingestion-worker.ts`, `apps/web/components/dashboard/dashboard-page.tsx` |
| SIEM delivery | `packages/shared/src/siem.ts`, `apps/api/src/routes/siem.ts`, `workers/siem-dispatcher.ts`, `apps/web/components/connectors/siem-section.tsx` |
| Admin and governance | `apps/api/src/routes/admin.ts`, `apps/web/components/admin/admin-page.tsx` |
| Agent orchestration | `packages/shared/src/a2a.ts`, `apps/api/src/routes/agents.ts`, `apps/mcp/src/server.ts` |

## Entry points for modification

Choose a feature page first when the change crosses apps or packages. These pages tell you where the end-to-end workflow begins, which shared files control it, and which UI surface exposes it.

- [Connectors and integrations](connectors-and-integrations.md)
- [Findings and remediation](findings-and-remediation.md)
- [SIEM delivery](siem-delivery.md)
- [Admin and governance](admin-and-governance.md)
- [Agent orchestration](agent-orchestration.md)

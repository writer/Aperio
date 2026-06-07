# Shared

Active contributors: unavailable in this checkout because git history is missing.

The `shared` package is the contract layer of the repo. It keeps the UI, API, workers, and MCP broker aligned by exporting shared enums, Zod schemas, connector catalogs, SIEM catalogs, and A2A payload definitions.

## Directory layout

```text
packages/shared/src/
├── a2a.ts
├── connectors.ts
├── siem.ts
└── types.ts
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `packages/shared/src/types.ts` | Provider enums, severity enums, findings query schema, ingestion payload schema |
| `packages/shared/src/connectors.ts` | Connector catalog, credential field definitions, remediation actions, finding checks |
| `packages/shared/src/siem.ts` | SIEM destination catalog and create payload validation |
| `packages/shared/src/a2a.ts` | Agent, task, message, proposal, and SIEM enqueue schemas |

## How it works

The package avoids handwritten interface duplication by exporting Zod schemas and inferring TypeScript types from them. That pattern shows up in the API routes and in `apps/web/lib/api.ts`, which expects the same payload shapes.

## Key source files

| File | Purpose |
| --- | --- |
| `packages/shared/src/types.ts` | Shared query and event schemas |
| `packages/shared/src/connectors.ts` | Catalog for GitHub, Slack, Google Workspace, 1Password, Okta, Microsoft 365, and Atlassian |
| `packages/shared/src/siem.ts` | Catalog for Splunk, Panther, Panopticon, Elastic, Datadog, webhook, and JSON file destinations |
| `packages/shared/src/a2a.ts` | Shared schemas for the agent orchestration model |

## Integration points

- Used by the frontend, generated-contract tests, local validation tooling, and web-facing compatibility schemas
- Reflected into `apps/web/lib/api.ts` and UI components
- Used by `internal/mcpbroker` for tool input validation
- Referenced by `internal/ingestionworker` and `internal/siemdispatcher`

## Entry points for modification

If you are adding a provider, a SIEM type, or a shared query field, start here before you touch route handlers or UI forms. This package is also the fastest place to look when the frontend and backend disagree about payload shape.

For product-level behavior built on these catalogs, go to [Connectors and integrations](../features/connectors-and-integrations.md) and [SIEM delivery](../features/siem-delivery.md).

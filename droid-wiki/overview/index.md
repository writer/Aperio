# Aperio overview

Aperio is a small multi-tenant SaaS security posture management prototype. It combines a tenant-scoped Express API, a Next.js console, Prisma-backed storage, background workers, and a stdio MCP broker for agent workflows. The code is organized to ingest SaaS audit events, turn them into security findings, let admins manage connectors and SIEM destinations, and expose agent-oriented task APIs.

## What this repo contains

- `apps/api/src/server.ts` starts the REST API that serves dashboard, findings, integrations, SIEM, admin, and agent routes.
- `apps/web/app/page.tsx` and related pages render the operator console for the dashboard, connectors, apps, and admin views.
- `apps/mcp/src/server.ts` exposes the same agent and SIEM workflow model over JSON-RPC for MCP clients.
- `workers/ingestion-worker.ts` and `workers/siem-dispatcher.ts` handle event-to-finding processing and durable SIEM fanout.
- `packages/db/prisma/schema.prisma`, `packages/shared/src/connectors.ts`, `packages/shared/src/siem.ts`, and `packages/shared/src/a2a.ts` define the shared contracts that tie the repo together.

## Repo map

```text
aperio/
├── apps/
│   ├── api/          Express API
│   ├── mcp/          stdio MCP broker
│   └── web/          Next.js operator console
├── packages/
│   ├── db/           Prisma schema and client
│   ├── security/     AES-256-GCM helpers
│   └── shared/       Zod schemas and catalogs
├── workers/          Ingestion and SIEM background logic
├── scripts/seed.ts   Demo tenant seed data
├── docker-compose.yml
└── package.json
```

## Main workflows

1. A tenant connects a SaaS app through `apps/api/src/routes/integrations.ts` and the UI in `apps/web/components/connectors/connectors-page.tsx`.
2. Events arrive at `apps/api/src/routes/ingestion.ts`, then `workers/ingestion-worker.ts` stores them and creates `SecurityFinding` records.
3. Findings appear in `apps/web/components/dashboard/dashboard-page.tsx` and `apps/web/components/apps/app-findings-page.tsx`, where operators can inspect or remediate them.
4. If SIEM destinations exist, `workers/siem-dispatcher.ts` drains the durable outbox and forwards canonical payloads to Splunk, Panther, Panopticon, Elastic, Datadog, webhooks, or JSONL files.
5. Agent clients can use `apps/api/src/routes/agents.ts` or `apps/mcp/src/server.ts` to register agents, create tasks, exchange messages, and propose remediations.

## What is missing in this checkout

This working copy has no `.git` directory, no `README.md`, no CI configuration, and no automated test suite. The wiki therefore leans on source files and runtime scripts rather than repository history or contributor metadata.

## Quick links

- [Architecture](architecture.md)
- [Getting started](getting-started.md)
- [Glossary](glossary.md)
- [Apps](../apps/index.md)
- [Features](../features/index.md)
- [Packages](../packages/index.md)

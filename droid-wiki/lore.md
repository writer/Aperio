# Lore

This page is narrower than it would be in a normal git-backed repo. The checkout used to generate this snapshot had no `.git` directory, so commit timestamps, tags, and contributor history are unavailable. The timeline below is inferred from the current file set and file modification dates in this local copy.

## Era: core SSPM console and API (May 2026)

The oldest visible layer in this checkout is the tenant-scoped SSPM core: integrations, findings, dashboard metrics, admin settings, and remediation. You can see that baseline in `apps/api/src/routes/dashboard.ts`, `apps/api/src/routes/findings.ts`, `apps/api/src/routes/integrations.ts`, `apps/api/src/routes/remediations.ts`, `apps/web/components/dashboard/dashboard-page.tsx`, and `apps/web/components/admin/admin-page.tsx`.

Key signs of this era:

- Multi-tenant entities such as `Organization`, `User`, `Role`, `IntegrationConnection`, and `SecurityFinding` are foundational in `packages/db/prisma/schema.prisma`.
- The demo seed script in `scripts/seed.ts` focuses on GitHub, Slack, and Google Workspace findings, which looks like the earliest supported detection slice.
- Remediation handlers in `apps/api/src/remediation/executor.ts` are real for Okta and Slack and stubbed for the rest, which suggests the repo started with a small write-capable path and grew detection breadth first.

## Era: connector and governance expansion (late May 2026)

The next visible expansion is the broader operator console. The repo now includes a richer connector catalog in `packages/shared/src/connectors.ts`, more provider entries such as 1Password and Atlassian, per-connector check toggles in `apps/api/src/routes/integrations.ts`, and a fuller admin area in `apps/api/src/routes/admin.ts`.

What changed in this phase:

- The UI gained dedicated pages for connectors, apps, and admin through `apps/web/app/connectors/page.tsx`, `apps/web/app/apps/page.tsx`, and `apps/web/app/admin/page.tsx`.
- Tenant governance became a first-class concern with `TenantAuditLog` and organization-level settings in `packages/db/prisma/schema.prisma`.
- Findings gained a more explicit app-centered drilldown through `apps/web/components/apps/apps-page.tsx` and `apps/web/components/apps/app-findings-page.tsx`.

## Era: durable SIEM delivery (late May 2026)

A later layer is the SIEM system. `packages/shared/src/siem.ts`, `apps/api/src/routes/siem.ts`, and `workers/siem-dispatcher.ts` show a shift from simple local handling toward catalog-driven outbound integrations and a durable outbox.

The visible milestones are:

- `SiemDestination` and `SiemDelivery` in `packages/db/prisma/schema.prisma`
- Canonical envelopes like `aperio.finding.v1` in `workers/siem-dispatcher.ts`
- Adapters for Splunk, Panther, Panopticon, Elastic, Datadog, generic webhooks, and JSONL file sinks
- UI support in `apps/web/components/connectors/siem-section.tsx`

## Era: agent orchestration and MCP (late May 2026)

The most recent-looking subsystem is the A2A and MCP layer. `packages/shared/src/a2a.ts`, `apps/api/src/routes/agents.ts`, `apps/mcp/src/server.ts`, and the `Agent*` tables in `packages/db/prisma/schema.prisma` add a second orchestration model next to the normal UI and REST surfaces.

What stands out:

- Agents, tasks, messages, and proposals are tenant-scoped and auditable.
- Proposals can point at findings and require approval before execution.
- The MCP broker mirrors core task and SIEM actions over stdio JSON-RPC rather than HTTP.

## Longest-standing features in this checkout

Because git history is missing, “longest-standing” here means “most foundational in the schema and route structure” rather than “oldest by commit date.” Those features are:

- Tenant identity and RBAC in `packages/db/prisma/schema.prisma`
- Connector registration and encrypted credential storage in `apps/api/src/routes/integrations.ts`
- Finding storage and dashboard aggregation in `apps/api/src/routes/findings.ts` and `apps/api/src/routes/dashboard.ts`

## Deprecated or removed features

No clearly removed subsystems are visible in this checkout. There are also no `@deprecated` annotations or obvious archive directories. That does not mean nothing was removed. It only means the current working tree does not preserve that history.

## What this lore page cannot answer

Without git metadata, this page cannot tell you:

- who introduced each subsystem
- when exact rewrites landed
- which branches carried migrations
- how fast the repo grew over time

If the repo is reconnected to git, this page should be regenerated. For the current architecture, go to [Architecture](overview/architecture.md). For the current feature map, go to [Features](features/index.md).

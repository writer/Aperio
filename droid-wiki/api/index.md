# API surface

Aperio exposes two API styles in this checkout: a tenant-scoped REST API under `/api/v1/*` and a stdio JSON-RPC MCP broker. The REST API is the primary surface for the web console, while the MCP broker mirrors a narrower set of agent-oriented actions.

## REST route groups

| Route group | Main file | Purpose |
| --- | --- | --- |
| `/api/v1/dashboard` | `apps/api/src/routes/dashboard.ts` | Dashboard aggregates |
| `/api/v1/findings` | `apps/api/src/routes/findings.ts`, `apps/api/src/routes/remediations.ts` | Findings list, resolve, remediate |
| `/api/v1/ingestion` | `apps/api/src/routes/ingestion.ts` | SaaS event intake |
| `/api/v1/integrations` | `apps/api/src/routes/integrations.ts` | Connector catalog and integration lifecycle |
| `/api/v1/siem` | `apps/api/src/routes/siem.ts` | SIEM destination catalog and CRUD/test |
| `/api/v1/admin` | `apps/api/src/routes/admin.ts` | Tenant settings, members, audit logs |
| `/api/v1/agents` | `apps/api/src/routes/agents.ts` | Agents, tasks, messages, proposals |

## Shared REST rules

- Every mounted route under `/api/v1` passes through `requireAuth` and `requireTenant` in `apps/api/src/middleware/security.ts`.
- Write routes often also pass through `requireRole(...)`.
- Dates are serialized to ISO strings before they leave route handlers.

## MCP tool groups

`apps/mcp/src/server.ts` exposes these tool families:

- `aperio.register_agent`
- `aperio.create_task`
- `aperio.send_message`
- `aperio.list_tasks`
- `aperio.propose_remediation`
- `aperio.enqueue_siem_payload`

## Key source files

| File | Purpose |
| --- | --- |
| `apps/api/src/server.ts` | REST server boot and route mounting |
| `apps/api/src/middleware/security.ts` | Auth, tenant scoping, role enforcement |
| `apps/api/src/routes/*.ts` | Domain route groups |
| `apps/mcp/src/server.ts` | MCP broker and tool dispatch |
| `apps/web/lib/api.ts` | Web client wrapper around REST endpoints |

## Entry points for modification

If you are adding an operator-facing HTTP workflow, add it to the relevant route file under `apps/api/src/routes/`. If you are adding an agent-facing tool, start in `apps/mcp/src/server.ts` and decide whether a REST equivalent also belongs in `apps/api/src/routes/agents.ts`.

For the runtime hosts behind these APIs, go to [API](../apps/api.md) and [MCP broker](../apps/mcp.md).

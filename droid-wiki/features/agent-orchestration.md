# Agent orchestration

Aperio stores agent tasks, messages, and proposals in Prisma-backed tables. Agent workflows are exposed through the Go API compatibility surface and the stdio MCP broker.

## Main files

| File | Purpose |
| --- | --- |
| `packages/shared/src/a2a.ts` | Shared A2A schemas |
| `internal/bootstrap/compat_api.go` | Agent task/message/proposal compatibility handlers |
| `internal/mcpbroker` | MCP JSON-RPC tools for agent clients |
| `packages/db/prisma/schema.prisma` | Agent, task, message, proposal tables |

Proposals are approval-gated before provider-side writes. Keep MCP tools and Go API compatibility behavior aligned when changing agent contracts.

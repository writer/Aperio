# MCP broker

Active contributors: unavailable in this checkout because git history is missing.

The MCP broker is a stdio JSON-RPC server that exposes agent and SIEM operations to external agent clients. It is separate from the Go API, but it is important because it turns the database-backed A2A model into a tool-based control surface.

## Directory layout

```text
cmd/mcp-broker/
└── main.go
internal/mcpbroker/
├── server.go
├── catalog.go
└── tools.go
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `cmd/mcp-broker` | Go stdio MCP process entrypoint |
| `internal/mcpbroker` | JSON-RPC framing, tool catalog, Prisma-backed tool execution |
| `packages/shared/src/a2a.ts` | Shared schemas for agent registration, tasks, messages, proposals |
| `internal/siemdispatcher` | SIEM enqueue helper used by the broker |

## How it works

`internal/mcpbroker` reads framed JSON-RPC messages from stdin, validates them, then responds with `initialize`, `tools/list`, and `tools/call` behavior. The tool handlers write directly to Prisma-backed agent and finding tables.

```mermaid
sequenceDiagram
  participant Client
  participant Broker as internal/mcpbroker
  participant DB as Prisma/Postgres

  Client->>Broker: initialize
  Broker-->>Client: serverInfo + capabilities
  Client->>Broker: tools/call
  Broker->>DB: create agent/task/message/proposal
  Broker-->>Client: tool result
```

## Integration points

- Shares the same data model as the Go API through `packages/db/prisma/schema.prisma`
- Reuses the same A2A schemas as the Go API compatibility handlers
- Can enqueue SIEM payloads through `internal/siemdispatcher`

## Entry points for modification

If you add a new MCP tool, update the `tools` catalog and `callTool` switch in `internal/mcpbroker`, then decide whether the payload schema belongs in `packages/shared/src/a2a.ts` or `packages/shared/src/siem.ts`. Keep broker behavior aligned with the Go API agent model so the two surfaces do not drift.

For the REST version of the same workflows, go to [Agent orchestration](../features/agent-orchestration.md) and [API surface](../api/index.md).

# How to contribute

Focus changes around the current runtime boundaries:

- API contracts: `proto/aperio/v1/api.proto`
- Go API implementation: `internal/bootstrap`
- Browser API facade: `apps/web/lib/api.ts` and `packages/connect/src`
- Workers: `internal/ingestionworker` and `internal/siemdispatcher`
- MCP broker: `internal/mcpbroker`
- Shared data: `packages/db/prisma/schema.prisma`

Security expectations:

- Preserve tenant scoping on every query and queue lease.
- Require owner/admin roles for mutations that change tenant settings, integrations, SIEM destinations, or remediation state.
- Use shared credential encryption envelopes for secrets that Go workers and allowed TypeScript tooling/tests must decrypt.
- Prefer typed ConnectRPC methods for new API work; use compatibility handlers only when preserving an existing web contract.

# Testing

Use targeted checks while iterating and the full validator set before merging.

## Core commands

```bash
npm run typecheck
npm run test:api
npm run test:go
npm run db:validate
npm run build:web
npm run leak:check
npm run proto:lint
```

`npm run test:api` now covers TypeScript package/contract tests, not an Express server. Go API behavior is covered by `npm run test:go`.

## Areas to cover

- ConnectRPC handlers and compatibility dispatch in `internal/bootstrap`.
- Web API facade behavior in `apps/web/lib/api.ts`.
- Connector lifecycle and force-sync queue writes.
- Ingestion worker rule evaluation and finding dedupe.
- SIEM dispatcher adapter behavior and retry/dead-letter handling.
- MCP broker tool schemas and tenant scoping.

For integration features, include contract tests when Go writes data that allowed TypeScript frontend, generated-client, test, Prisma, or tooling surfaces later consume, especially encrypted credentials and queue payloads.

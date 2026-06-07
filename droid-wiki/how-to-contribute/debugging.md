# Debugging

## API process

The API runtime is Go. Start it with:

```bash
npm run dev:connect
```

Health and readiness:

- `http://localhost:4100/healthz`
- `http://localhost:4100/readyz`

If a web call fails, check `apps/web/lib/api.ts` to see whether it uses a typed RPC or the `CallApi` compatibility path, then inspect `internal/bootstrap/app.go` or `internal/bootstrap/compat_api.go`.

## Common areas

| Symptom | Start here |
| --- | --- |
| Auth/session issue | `internal/bootstrap/compat_api.go`, `user_sessions` rows |
| CORS failure | `APERIO_WEB_ORIGIN`, Go CORS handling in `internal/bootstrap` |
| Connector save/force-sync issue | `internal/bootstrap/compat_api.go`, `IntegrationConnection`, `IngestionJob` |
| Ingestion did not create findings | `internal/ingestionworker`, ingestion job status, event payload |
| SIEM delivery failed | `internal/siemdispatcher`, `SiemDelivery`, destination credentials |
| MCP tool failure | `internal/mcpbroker` |

## Generated code

If protobuf-generated files drift, run:

```bash
go run github.com/bufbuild/buf/cmd/buf@v1.59.0 generate
git diff -- gen packages/connect/src/gen
```

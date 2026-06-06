# Go API

The product API is the Go service rooted at `cmd/aperio/main.go` and `internal/bootstrap`. It serves ConnectRPC procedures, health/readiness endpoints, browser CORS, cookie-backed auth, and the `/api/v1/*` compatibility surface used by the web console.

## Layout

```text
cmd/aperio/main.go              process entrypoint
internal/config/config.go       environment parsing
internal/bootstrap/app.go       service wiring and typed RPC handlers
internal/bootstrap/compat_api.go REST-shaped compatibility dispatch
internal/telemetry              logging and wide-event helpers
proto/aperio/v1/api.proto       public protobuf service contract
gen/aperio/v1                   generated Go protobuf code
```

## Responsibilities

| Area | Files |
| --- | --- |
| Server boot | `cmd/aperio/main.go` |
| Config | `internal/config/config.go` |
| ConnectRPC service | `internal/bootstrap/app.go` |
| REST-shaped compatibility | `internal/bootstrap/compat_api.go` |
| Contracts | `proto/aperio/v1/api.proto`, `packages/connect/src/gen` |
| Tests | `internal/bootstrap/app_test.go` |

## Request model

Native clients call ConnectRPC procedure paths. The web app calls `apps/web/lib/api.ts`, which uses generated Connect clients for typed RPCs and `CallApi` for compatibility paths. `CallApi` preserves the existing JSON response shapes without requiring a Node API runtime.

## Auth and tenancy

The API validates `aperio_session` cookies against `user_sessions`, enforces role checks for mutations, scopes database access by organization, and reflects only the configured `APERIO_WEB_ORIGIN` for credentialed browser calls.

## Development

Run the API locally with:

```bash
npm run dev:connect
```

Run Go validation with:

```bash
npm run test:go
npm run proto:lint
```

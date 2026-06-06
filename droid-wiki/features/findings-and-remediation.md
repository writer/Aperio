# Findings and remediation

Findings are tenant-scoped security issues created by the ingestion worker and read or mutated through the Go API.

## Main files

| File | Purpose |
| --- | --- |
| `workers/ingestion-worker.ts` | Detection evaluation, dedupe, auto-resolution, SIEM delivery enqueue |
| `internal/bootstrap/app.go` | Typed findings read RPCs |
| `internal/bootstrap/compat_api.go` | Remaining findings mutations, exports, remediation compatibility handlers |
| `apps/web/components/findings` | Findings list/detail UI |
| `packages/shared/src/risk.ts` | Shared risk scoring helpers |

## Flow

1. Provider events are written to ingestion queues/tables.
2. `workers/ingestion-worker.ts` leases jobs, evaluates provider checks, and writes `SecurityFinding` rows.
3. The worker enqueues `SiemDelivery` rows for enabled destinations.
4. The Go API exposes finding reads and compatibility mutations to the web console.

Remediation is human-approval oriented. Compatibility handlers update finding state today; provider-side write actions should be added behind explicit role checks and audit logs.

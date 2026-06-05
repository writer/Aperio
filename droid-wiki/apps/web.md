# Web

Active contributors: unavailable in this checkout because git history is missing.

The web app is a Next.js App Router console for security operators. It renders the dashboard, app-level findings views, connector and SIEM management, and tenant administration. Most of its data fetching goes through the typed helper layer in `apps/web/lib/api.ts`.

## Directory layout

```text
apps/web/
├── app/
│   ├── page.tsx
│   ├── apps/
│   ├── connectors/
│   └── admin/
├── components/
│   ├── admin/
│   ├── apps/
│   ├── connectors/
│   ├── dashboard/
│   └── ui/
└── lib/
    ├── api.ts
    └── utils.ts
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `apps/web/app/page.tsx` | Dashboard route entry |
| `apps/web/app/apps/page.tsx` | App findings summary route |
| `apps/web/app/apps/[integrationId]/page.tsx` | Per-integration findings route |
| `apps/web/app/connectors/page.tsx` | Connectors and SIEM route |
| `apps/web/app/admin/page.tsx` | Tenant admin route |
| `apps/web/components/dashboard/dashboard-page.tsx` | Metrics, findings table, remediation modal |
| `apps/web/components/connectors/connectors-page.tsx` | Connector catalog, connect/disconnect, check toggles |
| `apps/web/components/connectors/siem-section.tsx` | SIEM destination CRUD and test UI |
| `apps/web/components/admin/admin-page.tsx` | Settings, members, audit logs |
| `apps/web/lib/api.ts` | Typed HTTP client for `/api/v1/*` |

## How it works

The UI is mostly client components. Each major page uses `useEffect` and `useState` to call helpers from `apps/web/lib/api.ts`, then renders tables, badges, dialogs, and cards from `apps/web/components/ui/*.tsx`.

```mermaid
flowchart LR
  Page[Route component] --> View[Feature component]
  View --> Client[apps/web/lib/api.ts]
  Client --> API[/api/v1/*]
  API --> Client
  Client --> View
```

## Integration points

- Consumes REST endpoints from `apps/api/src/routes/*.ts`
- Mirrors connector, SIEM, and A2A contracts that originate in `packages/shared/src/*.ts`
- Depends on provider metadata from `apps/web/components/connectors/provider-icon.tsx`
- Uses demo fallback data in `apps/web/components/dashboard/dashboard-page.tsx` when the API is unavailable

## Entry points for modification

For a new page, start in `apps/web/app/` and then create or update the matching feature component under `apps/web/components/`. For an existing workflow, start in `apps/web/lib/api.ts` so you can see which backend route powers the screen.

For app-specific findings UX, go to [Findings and remediation](../features/findings-and-remediation.md). For the backing API routes, go to [API](api.md).

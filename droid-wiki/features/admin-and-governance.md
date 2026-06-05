# Admin and governance

Active contributors: unavailable in this checkout because git history is missing.

This feature covers tenant settings, tenant membership, role changes, and the audit trail that explains privileged actions. It is the part of the repo that turns the prototype into a multi-tenant admin console instead of a single-user demo.

## Directory layout

```text
apps/api/src/routes/admin.ts
apps/web/components/admin/admin-page.tsx
packages/db/prisma/schema.prisma
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `apps/api/src/routes/admin.ts` | Tenant settings, member list/create/update, audit log endpoints |
| `apps/web/components/admin/admin-page.tsx` | Settings form, member management, audit log table |
| `packages/db/prisma/schema.prisma` | `Organization`, `Role`, `User`, `TenantAuditLog` models |
| `apps/api/src/middleware/security.ts` | Role gating and tenant scoping |

## How it works

The admin route file parses settings and member payloads with Zod, reads or updates tenant-scoped Prisma models, and writes `TenantAuditLog` rows for each privileged change. The admin UI loads settings, members, and logs in parallel and refreshes the audit list after successful writes.

## Settings owned here

`apps/api/src/routes/admin.ts` exposes organization-level settings such as:

- notification email
- data retention days
- critical risk threshold
- default SLA hours
- auto-resolve for low severity
- SSO-only enforcement
- webhook alert URL

## Integration points

- Reuses the same role names as `apps/api/src/middleware/security.ts`
- Writes audit entries that also show up for connectors, SIEM changes, remediations, and proposal decisions
- Shapes the user and role data later used by finding resolution and proposal approval

## Entry points for modification

Start in `apps/api/src/routes/admin.ts` if the change affects the stored tenant model or audit trail. Start in `apps/web/components/admin/admin-page.tsx` if the data already exists and the change is presentational.

For the underlying tenant entities, go to [Data models](../reference/data-models.md). For the security model around roles and tenant scoping, go to [Security](../security.md).

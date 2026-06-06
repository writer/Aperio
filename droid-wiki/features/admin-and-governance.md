# Admin and governance

Admin workflows manage tenant settings, members, roles, audit logs, session policy, and organization-level controls.

## Main files

| File | Purpose |
| --- | --- |
| `internal/bootstrap/compat_api.go` | Admin/settings/member/audit compatibility handlers and role gates |
| `apps/web/components/settings` | Organization and personal settings UI |
| `apps/web/app/admin/page.tsx` | Admin entry point |
| `packages/db/prisma/schema.prisma` | Organization, membership, audit, and session tables |

Admin mutations should require owner/admin roles, scope all queries by organization, and write audit log rows for security-relevant changes.

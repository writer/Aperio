# Packages

Active contributors: unavailable in this checkout because git history is missing.

The `packages/` workspace holds the code that the apps and workers share. These packages are small, but they define the data model, encryption rules, and validation contracts that most of the repo depends on.

## Directory layout

```text
packages/
├── db/
│   ├── prisma/schema.prisma
│   └── src/client.ts
├── security/
│   └── src/
└── shared/
    └── src/
```

## Package summary

| Package | Core files | Responsibility |
| --- | --- | --- |
| `db` | `packages/db/prisma/schema.prisma`, `packages/db/src/client.ts` | Prisma schema and client singleton |
| `shared` | `packages/shared/src/types.ts`, `packages/shared/src/connectors.ts`, `packages/shared/src/siem.ts`, `packages/shared/src/a2a.ts` | Shared enums, Zod schemas, and catalogs |
| `security` | `packages/security/src/crypto.ts` | Encryption and decryption helpers |

## Entry points for modification

Change a package first if the same shape or rule will be used in more than one app. That is especially true for connector catalogs, SIEM fields, and agent payloads.

- [DB](db.md)
- [Shared](shared.md)
- [Security package](security.md)

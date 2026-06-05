# Dependencies

This page summarizes the important third-party libraries visible in `package.json` and how they map onto the codebase.

## Runtime libraries

| Dependency | Where it shows up | Why it matters |
| --- | --- | --- |
| `express` | `apps/api/src/server.ts` | REST API framework |
| `cors` | `apps/api/src/server.ts` | Browser origin control |
| `helmet` | `apps/api/src/server.ts` | Basic HTTP hardening |
| `compression` | `apps/api/src/server.ts` | Response compression |
| `@prisma/client` | API, MCP, workers | Database client |
| `zod` | `packages/shared/src/*.ts`, route files | Runtime validation |
| `next` / `react` / `react-dom` | `apps/web` | Operator console runtime |
| `lucide-react` | `apps/web/components/**/*.tsx` | UI icons |
| `tailwindcss` | `apps/web` | Styling system |
| `tsx` | root scripts | TypeScript execution in development |

## Database and tooling libraries

| Dependency | Where it shows up | Why it matters |
| --- | --- | --- |
| `prisma` | root scripts, `packages/db/prisma/schema.prisma` | Schema validation and client generation |
| `typescript` | `tsconfig.json` | Type checking |
| `autoprefixer` / `postcss` | `apps/web` | CSS build support |

## Native or platform dependencies

| Dependency | Source | Why it matters |
| --- | --- | --- |
| PostgreSQL | `docker-compose.yml`, `DATABASE_URL` | Main backing store |
| Node.js | root scripts | Runs all apps and workers |

## Not present in this checkout

A few common repo-level tools are notably absent from the visible config:

- ESLint
- Prettier
- Jest / Vitest
- Playwright / Cypress
- end-to-end browser testing

That absence explains why the repo leans heavily on type checking, Prisma validation, API tests, CI, and manual smoke tests.

For scripts built on these dependencies, go to [Tooling](../how-to-contribute/tooling.md). For the data layer they support, go to [DB](../packages/db.md).

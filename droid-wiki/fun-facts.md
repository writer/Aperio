# Fun facts

This repo does not have much archaeological data because the git history is missing, but the current working tree still has a few interesting patterns.

## The biggest files are all operator surfaces

The two largest files are `apps/web/components/connectors/connectors-page.tsx` and `apps/web/components/admin/admin-page.tsx`, both above 840 lines. The console pages carry a lot of local state, form handling, and table rendering.

## The connector catalog is one of the largest code files

`packages/shared/src/connectors.ts` is over 630 lines. That file is not just a list of providers. It defines credential fields, remediation actions, default scopes, and detection checks, which makes it one of the main control points in the repo.

## There are zero TODO, FIXME, or HACK comments

A search across `apps/`, `packages/`, `workers/`, and `scripts/` found no `TODO`, `FIXME`, or `HACK` markers. That is unusual for a fast-moving app prototype.

## There are no test files in this checkout

The working tree has 46 source files and 0 test files. The repo relies on `npm run typecheck`, `npm run build:web`, `npm run db:validate`, and local smoke tests instead.

## The API client exports a lot

`apps/web/lib/api.ts` has the highest export count in the repo. It is effectively the typed boundary between the web console and the Go/ConnectRPC API.

For a fuller statistical snapshot, go to [By the numbers](by-the-numbers.md). For the biggest surfaces in context, go to [Web](apps/web.md).

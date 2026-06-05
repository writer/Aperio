# Getting started

This repo runs as a local TypeScript monorepo with one shared `package.json` at `package.json`. The shortest path to a working environment is: start Postgres with `docker-compose.yml`, copy values from `.env.example`, generate the Prisma client, seed demo data, then run the API and web app.

## Prerequisites

- Node.js 20+ with npm
- Docker for `docker-compose.yml`
- A valid `APERIO_ENCRYPTION_KEY` and `APERIO_AUTH_SECRET` in `.env`
- PostgreSQL reachable through `DATABASE_URL`

## Environment variables

`.env.example` defines the expected runtime configuration:

- `DATABASE_URL`
- `APERIO_ENCRYPTION_KEY`
- `APERIO_AUTH_SECRET`
- `APERIO_WEB_ORIGIN`
- `NEXT_PUBLIC_API_BASE_URL`
- `DEMO_ORGANIZATION_ID`
- `DEMO_USER_ID`

## Install and bootstrap

```bash
npm install
cp .env.example .env
```

If you want the bundled local database:

```bash
docker compose up -d
```

## Database setup

Generate the Prisma client and validate the schema:

```bash
npm run db:generate
npm run db:validate
```

The repo often uses direct Prisma commands with the schema at `packages/db/prisma/schema.prisma`:

```bash
npx prisma db push --schema packages/db/prisma/schema.prisma
```

To seed the demo tenant and three sample findings:

```bash
npx tsx scripts/seed.ts
```

## Run the apps

API:

```bash
npm run dev:api
```

Web console:

```bash
npm run dev:web
```

Optional processes:

```bash
npm run worker:ingestion
npm run worker:siem
npm run mcp:broker
```

In practice the API process already starts the SIEM dispatcher in `apps/api/src/server.ts`, so `npm run worker:siem` is mainly useful when you want the dispatcher as a separate process.

## Validation commands

This repo has no dedicated test suite in the current checkout. The main checks are:

```bash
npm run typecheck
npm run build:web
npm run db:validate
```

## First pages to open

- Dashboard: `http://localhost:3000/`
- Apps: `http://localhost:3000/apps`
- Connectors: `http://localhost:3000/connectors`
- Admin: `http://localhost:3000/admin`
- API health: `http://localhost:4000/healthz`

For common failure modes, see [Debugging](../how-to-contribute/debugging.md). For configuration details, see [Configuration](../reference/configuration.md).

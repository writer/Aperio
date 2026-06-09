import { PrismaClient } from "@prisma/client";

// Pure-ESM Prisma client for callers invoked directly by Node (no tsx, no
// bundler), e.g. the executive-report-cli.mjs subprocess that the Go
// service spawns via `exec.Command("node", ...)`. Plain Node does not honor
// the tsconfig "paths" alias `@aperio/db`, so .mjs callers must import
// this file by relative path instead.
//
// The .ts sibling client.ts remains the canonical entry for TS callers
// (tsx, Next, tsc) so type information is preserved end-to-end; both
// modules construct the same singleton against the same DATABASE_URL.

const globalForPrisma = globalThis;

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "warn", "error"]
        : ["warn", "error"]
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

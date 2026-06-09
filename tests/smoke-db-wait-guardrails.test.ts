import { readFileSync } from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

// The smoke-e2e harness was failing with
//   Error: P1001: Can't reach database server at `127.0.0.1:5433`
// even though `make db-up` had already returned successfully. Root cause:
// docker-published Postgres briefly accepts on the host port during the
// image's init phase, then closes that listener and rebinds on the
// permanent socket. The old TCP-only wait in scripts/dev-config.mjs
// returned on the FIRST connect success, racing into the gap where
// Postgres is unreachable again. Two defenses below; both must stay in
// place because callers reach the wait via either route.

test("Makefile uses docker compose --wait so healthchecks gate up", () => {
  const makefile = readRepoFile("Makefile");
  for (const target of ["db-up", "nats-up"]) {
    const block = makefile.match(new RegExp(`^${target}:[\\s\\S]*?(?=^\\.PHONY|\\Z)`, "m"));
    assert.ok(block, `expected Makefile target ${target}`);
    assert.match(
      block![0],
      /up -d --wait/,
      `${target} must use 'docker compose up -d --wait' so docker waits for the container healthcheck (pg_isready / nats healthz) before returning`
    );
  }
});

test("dev-config.mjs wait requires consecutive TCP successes", () => {
  const source = readRepoFile("scripts/dev-config.mjs");
  // The Postgres init-phase race means a single connect success is not a
  // valid signal that the service is ready. Require N consecutive successes
  // so the brief flap window cannot satisfy the wait. The wait function is
  // also reachable from scripts/dev.mjs (via `node scripts/dev-config.mjs
  // wait ...`) and from CI smoke runs, so this is the single source of
  // truth.
  assert.match(
    source,
    /const\s+REQUIRED_CONSECUTIVE\s*=\s*[3-9]/,
    "must require at least 3 consecutive TCP-connect successes before declaring ready"
  );
  assert.match(
    source,
    /consecutive\s*\+=\s*1/,
    "the loop must increment a consecutive counter on success"
  );
  assert.match(
    source,
    /else\s*\{\s*consecutive\s*=\s*0/,
    "the loop must reset the consecutive counter on failure so a single flap doesn't get credit"
  );
});

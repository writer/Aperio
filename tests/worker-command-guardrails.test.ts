import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function makeTarget(makefile: string, target: string) {
  const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = makefile.match(new RegExp(`^${escapedTarget}:.*(?:\\n\\t.*)*`, "m"));
  assert.ok(match, `expected Makefile target ${target}`);
  return match[0];
}

function packageScripts() {
  const parsed = JSON.parse(readRepoFile("package.json")) as {
    scripts: Record<string, string>;
  };
  return parsed.scripts;
}

test("unsuffixed npm worker commands run Go defaults", () => {
  const scripts = packageScripts();

  assert.match(scripts["worker:ingestion"], /go run \.\/cmd\/ingestion-worker/);
  assert.match(scripts["worker:siem"], /go run \.\/cmd\/siem-dispatcher/);
  assert.doesNotMatch(scripts["worker:ingestion"], /\btsx\b|workers\/ingestion-worker\.ts/);
  assert.doesNotMatch(scripts["worker:siem"], /\btsx\b|workers\/siem-dispatcher\.ts/);
  assert.equal(scripts["worker:ingestion:go"], "npm run worker:ingestion --");
  assert.equal(scripts["worker:siem:go"], "npm run worker:siem --");
});

test("npm Go worker commands load .env and a pgx-safe database URL", () => {
  const scripts = packageScripts();
  const goWorkerScripts = Object.entries(scripts)
    .filter(([, command]) => /go run \.\/cmd\/(?:ingestion-worker|siem-dispatcher)/.test(command))
    .map(([name]) => name)
    .sort();

  assert.deepEqual(goWorkerScripts, ["worker:ingestion", "worker:siem"]);
  for (const name of goWorkerScripts) {
    const command = scripts[name];
    assert.match(command, /DATABASE_URL="?\$\(node scripts\/dev-config\.mjs go-database-url\)"?/);
    assert.match(command, /node scripts\/dev-env\.mjs go run \.\/cmd\/(?:ingestion-worker|siem-dispatcher)/);
    assert.doesNotMatch(command, /\btsx\b/);
  }
});

test("unsuffixed npm MCP command runs the Go stdio broker", () => {
  const scripts = packageScripts();
  const command = scripts["mcp:broker"];

  assert.match(command, /go run \.\/cmd\/mcp-broker/);
  assert.match(command, /DATABASE_URL="?\$\(node scripts\/dev-config\.mjs go-database-url\)"?/);
  assert.match(command, /node scripts\/dev-env\.mjs go run \.\/cmd\/mcp-broker/);
  assert.doesNotMatch(command, /\btsx\b|\bts-node\b|apps\/mcp\/src\/server\.ts/);
});

test("Make worker targets run Go defaults with strict aliases", () => {
  const makefile = readRepoFile("Makefile");

  const ingestion = makeTarget(makefile, "worker-ingestion");
  assert.match(ingestion, /## Run the Go ingestion worker/);
  assert.match(ingestion, /go run \.\/cmd\/ingestion-worker/);
  assert.match(ingestion, /\$\(GO_WORKER_ARGS\)/);
  assert.doesNotMatch(ingestion, /npx tsx workers\/ingestion-worker\.ts/);

  const siem = makeTarget(makefile, "worker-siem");
  assert.match(siem, /## Run the Go SIEM dispatcher worker/);
  assert.match(siem, /go run \.\/cmd\/siem-dispatcher/);
  assert.match(siem, /\$\(GO_WORKER_ARGS\)/);
  assert.doesNotMatch(siem, /npx tsx workers\/siem-dispatcher\.ts/);

  const goIngestion = makeTarget(makefile, "worker-ingestion-go");
  assert.match(goIngestion, /worker-ingestion-go: worker-ingestion ## Alias for the Go ingestion worker/);
  assert.doesNotMatch(goIngestion, /npx tsx|go run/);

  const goSiem = makeTarget(makefile, "worker-siem-go");
  assert.match(goSiem, /worker-siem-go: worker-siem ## Alias for the Go SIEM dispatcher worker/);
  assert.doesNotMatch(goSiem, /npx tsx|go run/);
});

test("Make MCP target runs the Go stdio broker", () => {
  const makefile = readRepoFile("Makefile");
  const mcp = makeTarget(makefile, "mcp");

  assert.match(mcp, /## Run the Go stdio MCP broker/);
  assert.match(mcp, /DATABASE_URL="\$+\(node \$\(DEV_CONFIG\) go-database-url\)"/);
  assert.match(mcp, /go run \.\/cmd\/mcp-broker/);
  assert.doesNotMatch(mcp, /\bnpx\s+tsx\b|\btsx\b|apps\/mcp\/src\/server\.ts/);
});

test("Go worker entrypoints expose one-shot smoke flags", () => {
  const ingestionMain = readRepoFile("cmd/ingestion-worker/main.go");
  assert.match(ingestionMain, /flag\.Bool\("once", false, "drain once and exit"\)/);
  assert.match(ingestionMain, /flag\.Int\("limit", 25, "maximum jobs to claim per drain"\)/);

  const siemMain = readRepoFile("cmd/siem-dispatcher/main.go");
  assert.match(siemMain, /flag\.Bool\("once", false, "drain once and exit"\)/);
  assert.match(siemMain, /flag\.Int\("limit", 25, "maximum deliveries to claim per drain"\)/);
  assert.match(siemMain, /flag\.String\("organization", "", "optional organization scope for local validation"\)/);
});

test("bounded worker smoke uses unsuffixed Go default commands", () => {
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");

  assert.match(scripts["smoke:workers:go"], /npm run worker:ingestion -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /npm run worker:siem -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /npm run smoke:siem:adapters/);
  assert.match(makeTarget(makefile, "smoke-workers-go"), /npm run worker:ingestion -- -once -limit 1/);
  assert.match(makeTarget(makefile, "smoke-workers-go"), /npm run worker:siem -- -once -limit 1/);
  assert.match(makeTarget(makefile, "smoke-workers-go"), /npm run smoke:siem:adapters/);
});

test("TypeScript tests no longer import deleted worker runtimes as oracles", () => {
  const testFiles = readdirSync(path.join(repoRoot, "tests"))
    .filter((file) => file.endsWith(".test.ts") && file !== "worker-command-guardrails.test.ts")
    .map((file) => ({
      file,
      imports: [
        ...readRepoFile(path.join("tests", file)).matchAll(
          /^\s*import(?:\s+type)?(?:[\s\S]*?)\s+from\s+["']([^"']+)["'];?/gm
        )
      ].map((match) => match[1])
    }));

  assert.equal(
    testFiles.some(({ imports }) => imports.includes("../workers/ingestion-worker")),
    false,
    "deleted ingestion worker must not remain a hidden TypeScript oracle"
  );
  assert.equal(
    testFiles.some(({ imports }) => imports.includes("../workers/siem-dispatcher")),
    false,
    "deleted SIEM dispatcher must not remain a hidden TypeScript oracle"
  );
  assert.equal(
    testFiles.some(({ imports }) => imports.includes("../apps/mcp/src/server")),
    false,
    "deleted MCP broker must not remain a hidden TypeScript oracle"
  );
});

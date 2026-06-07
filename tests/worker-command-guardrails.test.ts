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

test("unsuffixed npm ingestion command runs Go while SIEM remains TypeScript parity", () => {
  const scripts = packageScripts();

  assert.match(scripts["worker:ingestion"], /go run \.\/cmd\/ingestion-worker/);
  assert.equal(scripts["worker:siem"], "tsx workers/siem-dispatcher.ts");
  assert.doesNotMatch(scripts["worker:ingestion"], /\btsx\b|workers\/ingestion-worker\.ts/);
  assert.doesNotMatch(scripts["worker:siem"], /go run|cmd\/siem-dispatcher/);
  assert.equal(scripts["worker:ingestion:go"], "npm run worker:ingestion --");
});

test("npm Go worker commands load .env and a pgx-safe database URL", () => {
  const scripts = packageScripts();
  const goWorkerScripts = Object.entries(scripts)
    .filter(([, command]) => /go run \.\/cmd\/(?:ingestion-worker|siem-dispatcher)/.test(command))
    .map(([name]) => name)
    .sort();

  assert.deepEqual(goWorkerScripts, ["worker:ingestion", "worker:siem:go"]);
  for (const name of goWorkerScripts) {
    const command = scripts[name];
    assert.match(command, /DATABASE_URL="?\$\(node scripts\/dev-config\.mjs go-database-url\)"?/);
    assert.match(command, /node scripts\/dev-env\.mjs go run \.\/cmd\/(?:ingestion-worker|siem-dispatcher)/);
    assert.doesNotMatch(command, /\btsx\b/);
  }
});

test("Make ingestion target runs Go while SIEM keeps TypeScript default and explicit Go transition", () => {
  const makefile = readRepoFile("Makefile");

  const ingestion = makeTarget(makefile, "worker-ingestion");
  assert.match(ingestion, /## Run the Go ingestion worker/);
  assert.match(ingestion, /go run \.\/cmd\/ingestion-worker/);
  assert.match(ingestion, /\$\(GO_WORKER_ARGS\)/);
  assert.doesNotMatch(ingestion, /npx tsx workers\/ingestion-worker\.ts/);

  const siem = makeTarget(makefile, "worker-siem");
  assert.match(siem, /## Run the TypeScript parity\/reference SIEM dispatcher worker/);
  assert.match(siem, /npx tsx workers\/siem-dispatcher\.ts/);
  assert.doesNotMatch(siem, /go run \.\/cmd\/siem-dispatcher/);

  const goIngestion = makeTarget(makefile, "worker-ingestion-go");
  assert.match(goIngestion, /worker-ingestion-go: worker-ingestion ## Alias for the Go ingestion worker/);
  assert.doesNotMatch(goIngestion, /npx tsx|go run/);

  const goSiem = makeTarget(makefile, "worker-siem-go");
  assert.match(goSiem, /## Run the explicit Go transition SIEM dispatcher worker/);
  assert.match(goSiem, /\$\(LOAD_ENV\) DATABASE_URL="\$+\(node \$\(DEV_CONFIG\) go-database-url\)" go run \.\/cmd\/siem-dispatcher/);
  assert.match(goSiem, /\$\(GO_WORKER_ARGS\)/);
});

test("Go worker entrypoints expose one-shot smoke flags", () => {
  const ingestionMain = readRepoFile("cmd/ingestion-worker/main.go");
  assert.match(ingestionMain, /flag\.Bool\("once", false, "drain once and exit"\)/);
  assert.match(ingestionMain, /flag\.Int\("limit", 25, "maximum jobs to claim per drain"\)/);

  const siemMain = readRepoFile("cmd/siem-dispatcher/main.go");
  assert.match(siemMain, /flag\.Bool\("once", false, "drain once and exit"\)/);
  assert.match(siemMain, /flag\.Int\("limit", 25, "maximum deliveries to claim per drain"\)/);
});

test("bounded worker smoke uses the Go ingestion default command", () => {
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");

  assert.match(scripts["smoke:workers:go"], /npm run worker:ingestion -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /npm run worker:siem:go -- -once -limit 1/);
  assert.match(makeTarget(makefile, "smoke-workers-go"), /npm run worker:ingestion -- -once -limit 1/);
});

test("TypeScript tests no longer import the deleted ingestion runtime as an oracle", () => {
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
  assert.ok(
    testFiles.some(({ imports }) => imports.includes("../workers/siem-dispatcher")),
    "expected at least one TypeScript test to import the SIEM dispatcher"
  );
});

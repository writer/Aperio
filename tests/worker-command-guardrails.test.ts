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

test("unsuffixed npm worker commands stay on the TypeScript parity runtime", () => {
  const scripts = packageScripts();

  assert.equal(scripts["worker:ingestion"], "tsx workers/ingestion-worker.ts");
  assert.equal(scripts["worker:siem"], "tsx workers/siem-dispatcher.ts");
  assert.doesNotMatch(scripts["worker:ingestion"], /go run|cmd\/ingestion-worker/);
  assert.doesNotMatch(scripts["worker:siem"], /go run|cmd\/siem-dispatcher/);
});

test("explicit npm Go worker commands load .env and a pgx-safe database URL", () => {
  const scripts = packageScripts();
  const goWorkerScripts = Object.entries(scripts)
    .filter(([, command]) => /go run \.\/cmd\/(?:ingestion-worker|siem-dispatcher)/.test(command))
    .map(([name]) => name)
    .sort();

  assert.deepEqual(goWorkerScripts, ["worker:ingestion:go", "worker:siem:go"]);
  for (const name of goWorkerScripts) {
    const command = scripts[name];
    assert.match(command, /DATABASE_URL="?\$\(node scripts\/dev-config\.mjs go-database-url\)"?/);
    assert.match(command, /node scripts\/dev-env\.mjs go run \.\/cmd\/(?:ingestion-worker|siem-dispatcher)/);
    assert.doesNotMatch(command, /\btsx\b/);
  }
});

test("Make worker targets keep TypeScript defaults and explicit Go transition commands", () => {
  const makefile = readRepoFile("Makefile");

  const ingestion = makeTarget(makefile, "worker-ingestion");
  assert.match(ingestion, /## Run the TypeScript parity\/reference ingestion worker/);
  assert.match(ingestion, /npx tsx workers\/ingestion-worker\.ts/);
  assert.doesNotMatch(ingestion, /go run \.\/cmd\/ingestion-worker/);

  const siem = makeTarget(makefile, "worker-siem");
  assert.match(siem, /## Run the TypeScript parity\/reference SIEM dispatcher worker/);
  assert.match(siem, /npx tsx workers\/siem-dispatcher\.ts/);
  assert.doesNotMatch(siem, /go run \.\/cmd\/siem-dispatcher/);

  const goIngestion = makeTarget(makefile, "worker-ingestion-go");
  assert.match(goIngestion, /## Run the explicit Go transition ingestion worker/);
  assert.match(goIngestion, /\$\(LOAD_ENV\) DATABASE_URL="\$+\(node \$\(DEV_CONFIG\) go-database-url\)" go run \.\/cmd\/ingestion-worker/);
  assert.match(goIngestion, /\$\(GO_WORKER_ARGS\)/);

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

test("README worker copy names TypeScript defaults and explicit Go transition smokes", () => {
  const readme = readRepoFile("README.md");

  assert.match(readme, /unsuffixed worker commands run the TypeScript parity\/reference workers/);
  assert.match(readme, /npm run worker:ingestion:go -- -once -limit 1/);
  assert.match(readme, /npm run worker:siem:go -- -once -limit 1/);
  assert.match(readme, /not full replacements until a parity matrix proves cutover/);
});

test("TypeScript worker tests still import the reference worker modules", () => {
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

  assert.ok(
    testFiles.some(({ imports }) => imports.includes("../workers/ingestion-worker")),
    "expected at least one TypeScript test to import the ingestion worker"
  );
  assert.ok(
    testFiles.some(({ imports }) => imports.includes("../workers/siem-dispatcher")),
    "expected at least one TypeScript test to import the SIEM dispatcher"
  );
});

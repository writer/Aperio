import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL, fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

async function loadSmokeHarness() {
  return import(pathToFileURL(path.join(repoRoot, "scripts/smoke-e2e.mjs")).href);
}

test("local E2E smoke command is registered as the authoritative harness", () => {
  const packageJson = JSON.parse(readRepoFile("package.json")) as {
    scripts: Record<string, string>;
  };
  const makefile = readRepoFile("Makefile");

  assert.equal(packageJson.scripts["smoke:e2e"], "node scripts/smoke-e2e.mjs");
  assert.match(makefile, /^\.PHONY: .*smoke-e2e/m);
  assert.match(makefile, /^smoke-e2e: require-env ## Run the local Go API \+ TypeScript FE E2E smoke harness/m);
  assert.match(makefile, /\bnpm run smoke:e2e\b/);
});

test("smoke harness exports the canonical localhost route matrix and report sections", async () => {
  const smoke = await loadSmokeHarness();

  assert.equal(smoke.WEB_ORIGIN, "http://localhost:3000");
  assert.equal(smoke.API_ORIGIN, "http://127.0.0.1:4100");
  assert.deepEqual(smoke.EXPECTED_PORTS, {
    postgres: 5433,
    nats: 4222,
    natsMonitor: 8222,
    api: 4100,
    web: 3000
  });

  const routes = smoke.CANONICAL_ROUTES.map((route: { path: string }) => route.path);
  assert.deepEqual(routes, [
    "/",
    "/findings",
    "/findings/fnd_demo_public_repo",
    "/connectors",
    "/siem-connectors",
    "/apps",
    "/apps/int_demo_github",
    "/shadow-it",
    "/shadow-it/oauth-apps",
    "/security",
    "/security/privileged-identities",
    "/settings",
    "/settings/organization"
  ]);
  assert.ok(
    smoke.CANONICAL_ROUTES.every(
      (route: { url: string; expectedText: string }) =>
        route.url.startsWith("http://localhost:3000/") || route.url === "http://localhost:3000"
    ),
    "browser route validation must use localhost:3000"
  );
  assert.equal(
    smoke.CANONICAL_ROUTES.some((route: { url: string }) => route.url.includes("127.0.0.1:3000")),
    false
  );

  const report = smoke.createInitialReport();
  for (const section of smoke.REQUIRED_REPORT_SECTIONS) {
    assert.ok(section in report, `report should include ${section}`);
  }
  assert.deepEqual(smoke.REQUIRED_REPORT_SECTIONS, [
    "serviceStatus",
    "health",
    "browser",
    "routes",
    "safeMutations",
    "workerSmokes",
    "redaction",
    "cleanup"
  ]);
});

test("worker smoke commands are bounded Go transition smokes", async () => {
  const smoke = await loadSmokeHarness();

  assert.deepEqual(
    smoke.WORKER_SMOKE_COMMANDS.map((entry: { command: string; args: string[] }) => ({
      command: entry.command,
      args: entry.args
    })),
    [
      {
        command: "npm",
        args: ["run", "worker:ingestion:go", "--", "-once", "-limit", "1"]
      },
      {
        command: "npm",
        args: ["run", "worker:siem:go", "--", "-once", "-limit", "1"]
      }
    ]
  );
});

test("smoke evidence redaction masks cookies, bearer tokens, passwords, and DSNs", async () => {
  const smoke = await loadSmokeHarness();
  const raw = [
    "Cookie: aperio_session=s3cr3t-cookie; other=value",
    "Authorization: Bearer secret-token",
    "password=DemoPass1234",
    "postgres://aperio:aperio@127.0.0.1:5433/aperio?sslmode=disable"
  ].join("\n");
  const redacted = smoke.redactEvidence(raw);

  assert.doesNotMatch(redacted, /s3cr3t-cookie/);
  assert.doesNotMatch(redacted, /secret-token/);
  assert.doesNotMatch(redacted, /DemoPass1234/);
  assert.doesNotMatch(redacted, /aperio:aperio@/);
  assert.match(redacted, /\[REDACTED_COOKIE\]/);
  assert.match(redacted, /\[REDACTED_BEARER\]/);
  assert.match(redacted, /password=\[REDACTED\]/);
  assert.match(redacted, /postgres:\/\/\[REDACTED_DSN\]@127\.0\.0\.1:5433/);
});

test("seed data includes E2E-critical shadow IT grants and local SIEM destination", () => {
  const seed = readRepoFile("scripts/seed.ts");

  assert.match(seed, /shadow-it/);
  assert.match(seed, /oauthAppGrant\.upsert/);
  assert.match(seed, /grant_demo_vendor_analytics_morgan/);
  assert.match(seed, /grant_demo_ci_deploy_breakglass/);
  assert.match(seed, /siemDestination\.upsert/);
  assert.match(seed, /siem_demo_json_file/);
  assert.match(seed, /JSON_FILE/);
});

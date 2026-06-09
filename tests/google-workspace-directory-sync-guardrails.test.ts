import { readFileSync } from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(rel: string) {
  return readFileSync(path.join(repoRoot, rel), "utf8");
}

// Until this PR, saas_identities was populated only by scripts/seed.ts; live
// Google Workspace tenants always saw 0 privileged identities / 0 active
// accounts / 0% MFA coverage on the Security Graph and the report. These
// guardrails pin that the directory-sync producer remains wired end-to-end
// (binary + npm script + Makefile + dev.mjs auto-start) so future refactors
// cannot silently regress the identity surface back to empty.

test("google-workspace-directory-sync binary upserts saas_identities", () => {
  const sync = readRepoFile("internal/googleworkspacedirectorysync/sync.go");
  assert.match(
    sync,
    /INSERT INTO saas_identities[\s\S]*?ON CONFLICT \(organization_id, provider, external_id\)/,
    "upsert must be keyed on (organization_id, provider, external_id) to converge across renames"
  );
  assert.match(
    sync,
    /'GOOGLE_WORKSPACE'::"SaaSProvider"/,
    "provider must be cast to the SaaSProvider enum so Postgres accepts the insert"
  );
  assert.match(
    sync,
    /admin\.googleapis\.com\/admin\/directory\/v1\/users/,
    "must call the Directory API users endpoint"
  );
  assert.match(
    sync,
    /customer=my_customer/,
    "must scope to my_customer so the request implicitly targets the tenant the access token belongs to"
  );
});

test("dead-letter fix: MapEventType returns empty for unknown events", () => {
  const eventType = readRepoFile("internal/googleworkspacepoller/event_type.go");
  // The fix is a single return-path change; pin the absence of the old
  // uppercased-passthrough so a careless edit cannot re-introduce the
  // 84%-dead-letter regression.
  assert.doesNotMatch(
    eventType,
    /return\s+strings\.ToUpper\(eventName\)/,
    "MapEventType must NOT uppercase-passthrough unknown events; they belong nowhere on the ingestion queue"
  );
  const poller = readRepoFile("internal/googleworkspacepoller/poller.go");
  assert.match(
    poller,
    /if\s+mapped\s*==\s*""\s*\{\s*[\s\S]*?return\s+nil\s*\}/,
    "enqueueEvent must skip the insert when MapEventType returned an empty string"
  );
});

test("directory sync wired into package.json and Makefile", () => {
  const pkg = JSON.parse(readRepoFile("package.json"));
  assert.ok(pkg.scripts["worker:google-directory"], "package.json must expose worker:google-directory");
  assert.ok(pkg.scripts["worker:google-directory:go"], "package.json must expose the :go alias");
  assert.match(
    pkg.scripts["worker:google-directory"],
    /go run \.\/cmd\/google-workspace-directory-sync/,
    "worker:google-directory must run the Go binary"
  );
  const makefile = readRepoFile("Makefile");
  assert.match(
    makefile,
    /^worker-google-directory:\s+require-env/m,
    "Makefile must expose a worker-google-directory target"
  );
  assert.match(
    makefile,
    /^worker-google-directory-go:\s+worker-google-directory/m,
    "Makefile must expose the worker-google-directory-go alias"
  );
});

test("directory sync auto-started by dev.mjs", () => {
  const dev = readRepoFile("scripts/dev.mjs");
  assert.match(
    dev,
    /startWorker\("google-directory",\s*"\.\/cmd\/google-workspace-directory-sync"\)/,
    "scripts/dev.mjs must auto-start the directory sync alongside the other workers"
  );
});

test("directory sync owned in migration matrix", () => {
  const matrix = JSON.parse(readRepoFile("tests/fixtures/migration-ownership/migration-matrix.json"));
  const entry = matrix.entries.find((e: { id: string }) => e.id === "cmd-google-workspace-directory-sync-go-default");
  assert.ok(entry, "migration matrix must declare ownership for the directory sync");
  for (const cover of [
    "repo-file:cmd/google-workspace-directory-sync/*.go",
    "repo-file:internal/googleworkspacedirectorysync/*.go",
    "package-script:worker:google-directory",
    "make-target:worker-google-directory"
  ]) {
    assert.ok(
      entry.covers.includes(cover),
      `matrix entry must cover ${cover} so new repo files do not slip out of ownership`
    );
  }
});

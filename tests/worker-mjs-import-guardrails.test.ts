import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

// .mjs files in workers/ are invoked directly by the Go service via
// exec.Command("node", "workers/<file>.mjs", ...). Plain `node` does NOT
// honor the tsconfig "paths" aliases (@aperio/db, @aperio/shared, etc.),
// so any such import in a .mjs worker silently breaks the entire flow at
// runtime with ERR_MODULE_NOT_FOUND. The previous regression took out
// executive-report creation end-to-end because three workers reached for
// @aperio/db. This guardrail pins the contract for the entire workers/
// .mjs surface so it cannot regress again.
const TSCONFIG_PATH_ALIASES = ["@aperio/db", "@aperio/connect", "@aperio/security", "@aperio/shared", "@/"];

test("workers/*.mjs imports never use tsconfig path aliases", () => {
  const workerDir = path.join(repoRoot, "workers");
  const mjsFiles = readdirSync(workerDir).filter((file) => file.endsWith(".mjs"));
  assert.ok(mjsFiles.length > 0, "expected at least one .mjs worker so the guardrail is meaningful");
  const offenders: string[] = [];
  for (const file of mjsFiles) {
    const source = readRepoFile(path.join("workers", file));
    for (const alias of TSCONFIG_PATH_ALIASES) {
      const importRegex = new RegExp(
        `\\bfrom\\s+["']${alias.replace(/[.*+?^${}()|[\\\\]/g, "\\$&")}[^"']*["']`
      );
      if (importRegex.test(source)) {
        offenders.push(`${file} imports tsconfig-only alias "${alias}"`);
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `Plain Node cannot resolve tsconfig "paths" aliases. Use a relative import or a real npm/workspace package. Offenders:\n${offenders.join("\n")}`
  );
});

test("@aperio/db has a pure-ESM sibling for plain-Node callers", () => {
  // The CLI subprocess that the Go service spawns runs with plain `node`,
  // not tsx. It needs a .mjs entry point next to the .ts one so the
  // singleton can be imported by relative path without crossing a
  // tsconfig "paths" alias.
  const source = readRepoFile("packages/db/src/client.mjs");
  assert.match(source, /from\s+["']@prisma\/client["']/);
  assert.match(source, /export\s+const\s+prisma/);
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type IngestionRuleState =
  | "typescript-reference"
  | "go-parity"
  | "go-default"
  | "removable";

type IngestionRuleMatrix = {
  version: number;
  source: string;
  rules: Array<{
    ruleId: string;
    provider: string;
    state: IngestionRuleState;
    typescriptEventAliases: string[];
    typescriptPayloadPredicates: string[];
    goClaimedEventTypes: string[];
    fixtures: string[];
    tests: string[];
    cutoverBlockers: string[];
    goDefaultBlocked: boolean;
  }>;
};

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson<T>(relativePath: string): T {
  return JSON.parse(readRepoFile(relativePath)) as T;
}

function sorted(values: Iterable<string>) {
  return [...values].sort((a, b) => a.localeCompare(b));
}

function uniqueMatches(source: string, pattern: RegExp) {
  return sorted(new Set([...source.matchAll(pattern)].map((match) => match[1])));
}

function sectionForRule(source: string, ruleId: string) {
  const start = source.indexOf(`disabled.has("${ruleId}")`);
  assert.notEqual(start, -1, `missing disabled-check gate for ${ruleId}`);
  const end = source.indexOf(`ruleId: "${ruleId}"`, start);
  assert.notEqual(end, -1, `missing finding rule ID for ${ruleId}`);
  return source.slice(start, end);
}

function providerForRule(source: string, ruleId: string) {
  const section = sectionForRule(source, ruleId);
  const provider = section.match(/payload\.provider === "([^"]+)"/)?.[1];
  assert.ok(provider, `missing provider predicate for ${ruleId}`);
  return provider;
}

function aliasesForRule(source: string, ruleId: string) {
  return [...sectionForRule(source, ruleId).matchAll(/normalizedEvent === "([^"]+)"/g)].map(
    (match) => match[1]
  );
}

function goClaimAllowlistPairs(source: string) {
  const pairs = new Set<string>();
  for (const match of source.matchAll(/provider = '([^']+)'\s+AND event_type = '([^']+)'/g)) {
    pairs.add(`${match[1]}:${match[2]}`);
  }
  for (const match of source.matchAll(/provider = '([^']+)'\s+AND event_type IN \(([^)]+)\)/g)) {
    const provider = match[1];
    for (const eventType of match[2].matchAll(/'([^']+)'/g)) {
      pairs.add(`${provider}:${eventType[1]}`);
    }
  }
  return sorted(pairs);
}

test("ingestion rule ownership matrix exactly matches TypeScript rule IDs and aliases", () => {
  const matrix = readJson<IngestionRuleMatrix>(
    "tests/fixtures/worker-parity/ingestion-rule-matrix.json"
  );
  const source = readRepoFile("workers/ingestion-worker.ts");
  const disabledRuleIds = uniqueMatches(source, /disabled\.has\("([^"]+)"\)/g);
  const findingRuleIds = uniqueMatches(source, /ruleId: "([^"]+)"/g);
  const matrixRuleIds = sorted(matrix.rules.map((rule) => rule.ruleId));

  assert.deepEqual(disabledRuleIds, findingRuleIds, "every detector rule must have a disabled-check gate");
  assert.deepEqual(matrixRuleIds, findingRuleIds, "matrix must enumerate every TypeScript detector rule");

  const seenProviders = new Set<string>();
  for (const rule of matrix.rules) {
    seenProviders.add(rule.provider);
    assert.equal(rule.provider, providerForRule(source, rule.ruleId), `${rule.ruleId} provider drift`);
    assert.deepEqual(
      rule.typescriptEventAliases,
      aliasesForRule(source, rule.ruleId),
      `${rule.ruleId} normalized event alias drift`
    );
    assert.ok(rule.goDefaultBlocked, `${rule.ruleId} should not be Go-default while blockers remain`);
    assert.notEqual(rule.state, "go-default", `${rule.ruleId} cannot be Go-default in this slice`);
    assert.notEqual(rule.state, "removable", `${rule.ruleId} cannot be removable in this slice`);
    assert.ok(rule.cutoverBlockers.length > 0, `${rule.ruleId} needs explicit cutover blockers`);
  }
  assert.deepEqual(sorted(seenProviders), ["GITHUB", "GOOGLE_WORKSPACE", "OKTA", "SLACK"]);
});

test("Go ingestion claim allowlist matches only matrix-backed parity slices", () => {
  const matrix = readJson<IngestionRuleMatrix>(
    "tests/fixtures/worker-parity/ingestion-rule-matrix.json"
  );
  const goSource = readRepoFile("internal/ingestionworker/worker.go");

  const matrixClaimPairs = sorted(
    matrix.rules.flatMap((rule) =>
      rule.goClaimedEventTypes.map((eventType) => `${rule.provider}:${eventType}`)
    )
  );
  assert.deepEqual(goClaimAllowlistPairs(goSource), matrixClaimPairs);

  for (const rule of matrix.rules) {
    if (rule.goClaimedEventTypes.length === 0) {
      assert.equal(rule.state, "typescript-reference", `${rule.ruleId} has no Go claims and should stay fallback`);
      assert.deepEqual(rule.fixtures, [], `${rule.ruleId} should not cite Go fixtures before parity`);
      continue;
    }

    assert.equal(rule.state, "go-parity", `${rule.ruleId} claimed slices must be go-parity only`);
    assert.ok(
      rule.fixtures.every((fixture) => fixture.startsWith("tests/fixtures/worker-parity/")),
      `${rule.ruleId} must use shared worker-parity fixtures`
    );
    assert.ok(rule.tests.some((testPath) => testPath.startsWith("tests/") && testPath.endsWith(".test.ts")));
    assert.ok(rule.tests.includes("internal/ingestionworker/worker_test.go"));
    assert.ok(rule.tests.includes("internal/ingestionworker/worker_db_test.go"));
  }
});

test("TypeScript ingestion remains the unsuffixed reference runtime", () => {
  const packageJson = readJson<{ scripts: Record<string, string> }>("package.json");
  const makefile = readRepoFile("Makefile");

  assert.equal(packageJson.scripts["worker:ingestion"], "tsx workers/ingestion-worker.ts");
  assert.match(packageJson.scripts["worker:ingestion:go"], /go run \.\/cmd\/ingestion-worker/);
  assert.match(makefile, /worker-ingestion: require-env[\s\S]*npx tsx workers\/ingestion-worker\.ts/);
  assert.match(makefile, /worker-ingestion-go: require-env[\s\S]*go run \.\/cmd\/ingestion-worker/);
});

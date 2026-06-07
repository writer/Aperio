import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { siemCatalog, type SiemKindKey } from "../packages/shared/src/siem";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type SiemAdapterState =
  | "typescript-reference"
  | "go-parity"
  | "go-default"
  | "removable";

type SiemAdapterMatrix = {
  version: number;
  source: string;
  adapters: Array<{
    kind: SiemKindKey;
    state: SiemAdapterState;
    owner: string;
    prismaKind: boolean;
    sharedCatalog: boolean;
    goCatalog: boolean;
    typescriptDispatcher: boolean;
    goDispatcher: boolean;
    goClaimed: boolean;
    defaultStreams: string[];
    requiredFields: string[];
    fixtures: string[];
    tests: string[];
    cutoverBlockers: string[];
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

function prismaSiemKinds() {
  const source = readRepoFile("packages/db/prisma/schema.prisma");
  const match = source.match(/enum\s+SiemKind\s*{(?<body>[^}]+)}/);
  assert.ok(match?.groups?.body, "Prisma SiemKind enum must exist");
  return sorted(
    match.groups.body
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => /^[A-Z_]+$/.test(line))
  );
}

function goClaimedKinds(source: string) {
  const claimClauses = [...source.matchAll(/dst\.kind\s+IN\s+\(([^)]+)\)/g)];
  assert.ok(claimClauses.length >= 2, "Go claim and retire queries must include adapter allowlists");
  const parsed = claimClauses.map((match) =>
    sorted([...match[1].matchAll(/'([A-Z_]+)'/g)].map((kind) => kind[1]))
  );
  for (const kinds of parsed) {
    assert.deepEqual(kinds, parsed[0], "Go claim/retire allowlists must stay in sync");
  }
  return parsed[0];
}

test("SIEM adapter ownership matrix covers every declared destination kind", () => {
  const matrix = readJson<SiemAdapterMatrix>(
    "tests/fixtures/worker-parity/siem-adapter-matrix.json"
  );
  const matrixKinds = sorted(matrix.adapters.map((adapter) => adapter.kind));
  const sharedKinds = sorted(siemCatalog.map((definition) => definition.kind));
  const goCatalogKinds = uniqueMatches(readRepoFile("internal/bootstrap/catalog.go"), /Kind:\s*"([A-Z_]+)"/g);
  const tsDispatcherKinds = uniqueMatches(readRepoFile("workers/siem-dispatcher.ts"), /case\s+"([A-Z_]+)":/g);
  const goDispatcherSource = readRepoFile("internal/siemdispatcher/dispatcher.go");
  const goDispatcherKinds = uniqueMatches(goDispatcherSource, /case\s+"([A-Z_]+)":/g);

  assert.deepEqual(matrixKinds, prismaSiemKinds(), "matrix must match Prisma SiemKind enum");
  assert.deepEqual(matrixKinds, sharedKinds, "matrix must match TypeScript shared SIEM catalog");
  assert.deepEqual(matrixKinds, goCatalogKinds, "matrix must match Go SIEM catalog");
  assert.deepEqual(matrixKinds, tsDispatcherKinds, "matrix must match TypeScript dispatcher send paths");
  assert.deepEqual(
    sorted(matrix.adapters.filter((adapter) => adapter.goDispatcher).map((adapter) => adapter.kind)),
    goDispatcherKinds,
    "matrix Go dispatcher state must match implemented Go send paths"
  );
  assert.deepEqual(
    sorted(matrix.adapters.filter((adapter) => adapter.goClaimed).map((adapter) => adapter.kind)),
    goClaimedKinds(goDispatcherSource),
    "matrix Go claim state must match Go dispatcher claim allowlist"
  );
});

test("SIEM adapter matrix preserves TypeScript fallback and blocks premature cutover", () => {
  const matrix = readJson<SiemAdapterMatrix>(
    "tests/fixtures/worker-parity/siem-adapter-matrix.json"
  );

  for (const adapter of matrix.adapters) {
    assert.equal(adapter.prismaKind, true, `${adapter.kind} must be present in Prisma`);
    assert.equal(adapter.sharedCatalog, true, `${adapter.kind} must be present in TS shared catalog`);
    assert.equal(adapter.goCatalog, true, `${adapter.kind} must be present in Go catalog`);
    assert.equal(adapter.typescriptDispatcher, true, `${adapter.kind} must have a TS reference path`);
    assert.notEqual(adapter.state, "go-default", `${adapter.kind} cannot be Go-default in this slice`);
    assert.notEqual(adapter.state, "removable", `${adapter.kind} cannot be removable in this slice`);
    assert.ok(adapter.cutoverBlockers.length > 0, `${adapter.kind} needs explicit cutover blockers`);

    if (adapter.goClaimed) {
      assert.equal(adapter.state, "go-parity", `${adapter.kind} Go claims must remain go-parity`);
      assert.equal(adapter.goDispatcher, true, `${adapter.kind} claims require a Go send path`);
      assert.ok(
        adapter.fixtures.every((fixture) => fixture.startsWith("tests/fixtures/worker-parity/")),
        `${adapter.kind} Go parity must cite shared fixtures`
      );
      assert.ok(adapter.tests.includes("internal/siemdispatcher/dispatcher_test.go"));
      assert.ok(adapter.tests.includes("internal/siemdispatcher/dispatcher_db_test.go"));
    } else {
      assert.equal(
        adapter.state,
        "typescript-reference",
        `${adapter.kind} unclaimed adapters must remain TypeScript fallback`
      );
      assert.equal(adapter.goDispatcher, false, `${adapter.kind} must not advertise unclaimed Go support`);
    }
  }
});

test("SIEM adapter matrix mirrors shared catalog required fields and streams", () => {
  const matrix = readJson<SiemAdapterMatrix>(
    "tests/fixtures/worker-parity/siem-adapter-matrix.json"
  );
  const byKind = new Map(matrix.adapters.map((adapter) => [adapter.kind, adapter]));

  for (const definition of siemCatalog) {
    const adapter = byKind.get(definition.kind);
    assert.ok(adapter, `matrix missing ${definition.kind}`);
    assert.deepEqual(adapter.defaultStreams, definition.defaultStreams, `${definition.kind} streams drift`);
    assert.deepEqual(
      adapter.requiredFields,
      definition.fields.filter((field) => field.required).map((field) => field.key),
      `${definition.kind} required fields drift`
    );
  }
});

test("TypeScript SIEM dispatcher remains the unsuffixed reference runtime", () => {
  const packageJson = readJson<{ scripts: Record<string, string> }>("package.json");
  const makefile = readRepoFile("Makefile");

  assert.equal(packageJson.scripts["worker:siem"], "tsx workers/siem-dispatcher.ts");
  assert.match(packageJson.scripts["worker:siem:go"], /go run \.\/cmd\/siem-dispatcher/);
  assert.match(makefile, /worker-siem: require-env[\s\S]*npx tsx workers\/siem-dispatcher\.ts/);
  assert.match(makefile, /worker-siem-go: require-env[\s\S]*go run \.\/cmd\/siem-dispatcher/);
});

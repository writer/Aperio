import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";
import {
  assertLocalOnlyEndpoint,
  assertNoPlaintext,
  buildIngestionJobFixture,
  classifyRuntimeCommand,
  createLocalRequestCapture,
  decodeMcpFrames,
  encodeMcpFrame,
  makeTargetBlock,
  packageScripts,
  readJsonFixture,
  readRepoFile
} from "./local-cutover-harness";

type MatrixCutoverPlan = {
  status: string;
  defaultsFlippedInThisFeature: boolean;
  fixture: string;
  localHarness?: string;
  requiredEvidenceKinds?: string[];
  goDefaultRequires?: string[];
};

type MatrixWithCutoverPlan = {
  version: number;
  finalCutoverPlan: MatrixCutoverPlan;
};

type FinalCutoverPlan = {
  version: number;
  status: string;
  defaultsFlippedInThisFeature: boolean;
  requiredEvidenceKinds: string[];
  surfaces: Array<{
    id: string;
    surface: string;
    currentState: string;
    currentCommand?: string;
    currentCommandContains?: string;
    targetState: string;
    targetCommandContains?: string;
    blockedBy: string[];
    requiredEvidence: string[];
  }>;
};

type FoundationHarnessFixture = {
  credentialEnvelope: {
    goWrittenEnvelope: string;
    expectedPlaintext: string;
  };
  ingestion: {
    job: Parameters<typeof buildIngestionJobFixture>[0];
    expectedFindingRuleId: string;
    noProductionProviders: string[];
  };
  siem: {
    captureEndpoint: string;
    request: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body: Record<string, unknown>;
    };
    noProductionDestinations: string[];
  };
  mcp: {
    requests: Array<{
      name: string;
      message: Record<string, unknown>;
    }>;
    approvedTools: Array<{
      name: string;
      required: string[];
    }>;
  };
  commandOwnership: {
    currentDefaults: Record<string, string>;
    strictAliasContains: Record<string, string>;
  };
};

type SiemAdapterMatrixFixture = {
  adapters: Array<{
    kind: string;
    goClaimed: boolean;
  }>;
};

type SiemLocalAdapterHarnessFixture = {
  designNote: string;
  noProductionDestinations: string[];
  networkHarness: {
    endpointSafetyNegativeTests: string[];
  };
  adapters: Array<{
    kind: string;
    harness: string;
    endpointUrl?: string;
    filePath?: string;
  }>;
};

function loadFinalPlan() {
  return readJsonFixture<FinalCutoverPlan>(
    "tests/fixtures/migration-ownership/final-cutover-plan.json"
  );
}

function loadHarnessFixture() {
  return readJsonFixture<FoundationHarnessFixture>(
    "tests/fixtures/worker-parity/foundation-local-harness.json"
  );
}

function sectionForTool(source: string, toolName: string) {
  const escapedToolName = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const start = source.search(new RegExp(`\\bName:\\s+"${escapedToolName}"`));
  assert.notEqual(start, -1, `missing MCP tool ${toolName}`);
  const remaining = source.slice(start + 1);
  const nextTool = remaining.search(/\n\s+\{\n\s+Name:\s+"aperio\./);
  if (nextTool === -1) {
    return source.slice(start, source.indexOf("];", start));
  }
  return source.slice(start, start + 1 + nextTool);
}

test("final ownership matrices expose enforced Go-default cutover evidence", () => {
  const finalPlan = loadFinalPlan();
  assert.equal(finalPlan.version, 1);
  assert.equal(finalPlan.status, "final-go-default-enforced");
  assert.equal(finalPlan.defaultsFlippedInThisFeature, true);

  const matrixFixtures = [
    "tests/fixtures/migration-ownership/migration-matrix.json",
    "tests/fixtures/worker-parity/ingestion-rule-matrix.json",
    "tests/fixtures/worker-parity/siem-adapter-matrix.json"
  ];
  for (const fixturePath of matrixFixtures) {
    const matrix = readJsonFixture<MatrixWithCutoverPlan>(fixturePath);
    assert.equal(matrix.version, 1, `${fixturePath} version drift`);
    if (fixturePath.includes("ingestion-rule-matrix")) {
      assert.equal(matrix.finalCutoverPlan.defaultsFlippedInThisFeature, true);
      assert.equal(matrix.finalCutoverPlan.status, "ingestion-go-default-enforced");
    } else if (fixturePath.includes("siem-adapter-matrix")) {
      assert.equal(matrix.finalCutoverPlan.defaultsFlippedInThisFeature, true);
      assert.equal(matrix.finalCutoverPlan.status, "siem-go-default-enforced");
    } else if (fixturePath.includes("migration-matrix")) {
      assert.equal(matrix.finalCutoverPlan.defaultsFlippedInThisFeature, true);
      assert.equal(matrix.finalCutoverPlan.status, "final-go-default-enforced");
    } else {
      assert.equal(matrix.finalCutoverPlan.defaultsFlippedInThisFeature, false);
      assert.equal(matrix.finalCutoverPlan.status, "final-go-default-enforced");
    }
    assert.equal(
      matrix.finalCutoverPlan.fixture,
      "tests/fixtures/migration-ownership/final-cutover-plan.json"
    );
  }

  const requiredSurfaceIds = [
    "npm-worker-ingestion-default",
    "npm-worker-siem-default",
    "npm-mcp-broker-default",
    "make-worker-ingestion-default",
    "make-worker-siem-default",
    "make-mcp-default",
    "typescript-ingestion-runtime-deletion",
    "typescript-siem-runtime-deletion",
    "typescript-mcp-runtime-deletion",
    "suffixed-go-worker-command-cleanup"
  ];
  assert.deepEqual(
    finalPlan.surfaces.map((surface) => surface.id).sort(),
    requiredSurfaceIds.sort()
  );

  for (const surface of finalPlan.surfaces) {
    if (surface.currentState === surface.targetState || surface.currentState === "removed") {
      assert.deepEqual(surface.blockedBy, [], `${surface.id} must not retain blockers after cutover`);
    } else {
      assert.ok(surface.blockedBy.length > 0, `${surface.id} must name current blockers`);
    }
    assert.ok(surface.requiredEvidence.length > 0, `${surface.id} must name evidence`);
    for (const evidence of surface.requiredEvidence) {
      assert.ok(
        finalPlan.requiredEvidenceKinds.includes(evidence),
        `${surface.id} cites unknown evidence kind ${evidence}`
      );
    }
    if (surface.targetState === "go-default" && surface.currentState !== "go-default") {
      assert.match(
        surface.targetCommandContains ?? "",
        /go run \.\/cmd\//,
        `${surface.id} needs a concrete Go target command placeholder`
      );
    }
  }
});

test("current command ownership records Go worker and MCP defaults", () => {
  const fixture = loadHarnessFixture();
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");

  assert.equal(
    scripts["worker:ingestion"],
    fixture.commandOwnership.currentDefaults["package-script:worker:ingestion"]
  );
  assert.equal(
    scripts["worker:siem"],
    fixture.commandOwnership.currentDefaults["package-script:worker:siem"]
  );
  assert.equal(
    scripts["mcp:broker"],
    fixture.commandOwnership.currentDefaults["package-script:mcp:broker"]
  );
  assert.equal(
    classifyRuntimeCommand(scripts["worker:ingestion"]),
    "go-ingestion"
  );
  assert.equal(
    classifyRuntimeCommand(scripts["worker:siem"]),
    "go-siem"
  );
  assert.equal(classifyRuntimeCommand(scripts["mcp:broker"]), "go-mcp");
  assert.doesNotMatch(scripts["mcp:broker"], /\btsx\b|apps\/mcp\/src\/server\.ts/);

  for (const [script, expected] of Object.entries(
    fixture.commandOwnership.strictAliasContains
  ).filter(([surface]) => surface.startsWith("package-script:"))) {
    const scriptName = script.replace("package-script:", "");
    assert.match(scripts[scriptName], new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(classifyRuntimeCommand(scripts[scriptName]), /^go-/);
  }

  const makeDefaults = {
    "make-target:worker-ingestion": makeTargetBlock(makefile, "worker-ingestion"),
    "make-target:worker-siem": makeTargetBlock(makefile, "worker-siem"),
    "make-target:mcp": makeTargetBlock(makefile, "mcp")
  };
  for (const [surface, expected] of Object.entries(fixture.commandOwnership.currentDefaults).filter(
    ([surface]) => surface.startsWith("make-target:")
  )) {
    assert.match(makeDefaults[surface as keyof typeof makeDefaults], new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("local ingestion, SIEM, and MCP harness helpers are deterministic and secret-free", () => {
  const fixture = loadHarnessFixture();

  const ingestionJob = buildIngestionJobFixture(fixture.ingestion.job);
  assert.equal(ingestionJob.provider, "GITHUB");
  assert.equal(ingestionJob.eventType, "PUBLIC_REPOSITORY_CREATED");
  assert.equal(ingestionJob.occurredAtDate.toISOString(), fixture.ingestion.job.occurredAt);
  for (const productionHost of fixture.ingestion.noProductionProviders) {
    assert.doesNotMatch(JSON.stringify(ingestionJob), new RegExp(productionHost, "i"));
  }

  assertLocalOnlyEndpoint(fixture.siem.captureEndpoint);
  const capture = createLocalRequestCapture(fixture.siem.captureEndpoint);
  capture.record(fixture.siem.request);
  assert.equal(capture.requests.length, 1);
  assert.deepEqual(capture.requests[0]?.body, fixture.siem.request.body);
  for (const productionHost of fixture.siem.noProductionDestinations) {
    assert.doesNotMatch(JSON.stringify(capture.requests), new RegExp(productionHost, "i"));
  }
  assertNoPlaintext(capture.requests, [fixture.credentialEnvelope.expectedPlaintext]);

  for (const request of fixture.mcp.requests) {
    const frame = encodeMcpFrame(request.message);
    assert.match(frame, /^Content-Length: \d+\r\n\r\n/);
    const decoded = decodeMcpFrames(frame);
    assert.deepEqual(decoded.messages, [request.message], request.name);
    assert.equal(decoded.remaining, "");
  }
});

test("SIEM local adapter harness covers every Go-owned adapter without production endpoints", () => {
  const matrix = readJsonFixture<SiemAdapterMatrixFixture>(
    "tests/fixtures/worker-parity/siem-adapter-matrix.json"
  );
  const harness = readJsonFixture<SiemLocalAdapterHarnessFixture>(
    "tests/fixtures/worker-parity/siem-local-adapter-harness.json"
  );

  assert.match(harness.designNote, /endpoint-safety/i);
  assert.ok(
    harness.networkHarness.endpointSafetyNegativeTests.length >= 3,
    "harness must cite endpoint-safety negative coverage"
  );
  assert.deepEqual(
    harness.adapters.map((adapter) => adapter.kind).sort(),
    matrix.adapters.filter((adapter) => adapter.goClaimed).map((adapter) => adapter.kind).sort()
  );

  for (const adapter of harness.adapters) {
    if (adapter.endpointUrl) {
      assertLocalOnlyEndpoint(adapter.endpointUrl);
    } else {
      assert.equal(adapter.harness, "temp-export-root-jsonl");
      assert.ok(adapter.filePath?.endsWith(".jsonl"));
    }
    for (const productionHost of harness.noProductionDestinations) {
      assert.doesNotMatch(JSON.stringify(adapter), new RegExp(productionHost, "i"));
    }
  }
});

test("MCP tool catalog and Go broker default are characterized locally", () => {
  const fixture = loadHarnessFixture();
  const catalog = readRepoFile("internal/mcpbroker/catalog.go");
  const server = readRepoFile("internal/mcpbroker/server.go");
  const main = readRepoFile("cmd/mcp-broker/main.go");
  const scripts = packageScripts();

  assert.equal(classifyRuntimeCommand(scripts["mcp:broker"]), "go-mcp");
  assert.match(scripts["mcp:broker"], /go run \.\/cmd\/mcp-broker/);
  assert.doesNotMatch(scripts["mcp:broker"], /\btsx\b|apps\/mcp\/src\/server\.ts/);
  assert.equal(existsSync("apps/mcp/src/server.ts"), false);
  assert.match(server, /fmt\.Sprintf\("Content-Length: %d\\r\\n\\r\\n"/);
  assert.doesNotMatch(server, /console\.log/);
  assert.match(main, /log\.SetOutput\(os\.Stderr\)/);

  for (const tool of fixture.mcp.approvedTools) {
    const section = sectionForTool(catalog, tool.name);
    for (const requiredField of tool.required) {
      assert.match(
        section,
        new RegExp(`"${requiredField}"`),
        `${tool.name} must keep required field ${requiredField}`
      );
    }
  }

  assert.match(
    readRepoFile("internal/mcpbroker/tools.go"),
    /INSERT INTO siem_deliveries/,
    "Go MCP broker should enqueue SIEM payload rows without draining them"
  );
  assert.doesNotMatch(
    `${scripts["mcp:broker"]}\n${readRepoFile("Makefile")}`,
    /apps\/mcp\/src\/server\.ts|workers\/siem-dispatcher/
  );
});

import assert from "node:assert/strict";
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
    explicitGoTransitionContains: Record<string, string>;
  };
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
  const start = source.indexOf(`name: "${toolName}"`);
  assert.notEqual(start, -1, `missing MCP tool ${toolName}`);
  const remaining = source.slice(start + 1);
  const nextTool = remaining.search(/\n\s+\{\n\s+name: "aperio\./);
  if (nextTool === -1) {
    return source.slice(start, source.indexOf("];", start));
  }
  return source.slice(start, start + 1 + nextTool);
}

test("final ownership matrices expose non-enforcing cutover placeholders", () => {
  const finalPlan = loadFinalPlan();
  assert.equal(finalPlan.version, 1);
  assert.equal(finalPlan.status, "planned-not-enforced");
  assert.equal(finalPlan.defaultsFlippedInThisFeature, false);

  const matrixFixtures = [
    "tests/fixtures/migration-ownership/migration-matrix.json",
    "tests/fixtures/worker-parity/ingestion-rule-matrix.json",
    "tests/fixtures/worker-parity/siem-adapter-matrix.json"
  ];
  for (const fixturePath of matrixFixtures) {
    const matrix = readJsonFixture<MatrixWithCutoverPlan>(fixturePath);
    assert.equal(matrix.version, 1, `${fixturePath} version drift`);
    assert.equal(
      matrix.finalCutoverPlan.defaultsFlippedInThisFeature,
      false,
      `${fixturePath} must not flip defaults in the foundation harness feature`
    );
    assert.equal(matrix.finalCutoverPlan.status, "planned-not-enforced");
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
    assert.ok(surface.blockedBy.length > 0, `${surface.id} must name current blockers`);
    assert.ok(surface.requiredEvidence.length > 0, `${surface.id} must name evidence`);
    for (const evidence of surface.requiredEvidence) {
      assert.ok(
        finalPlan.requiredEvidenceKinds.includes(evidence),
        `${surface.id} cites unknown evidence kind ${evidence}`
      );
    }
    if (surface.targetState === "go-default") {
      assert.match(
        surface.targetCommandContains ?? "",
        /go run \.\/cmd\//,
        `${surface.id} needs a concrete Go target command placeholder`
      );
    }
  }
});

test("current command ownership is characterized without flipping worker or MCP defaults", () => {
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
    "typescript-ingestion-reference"
  );
  assert.equal(
    classifyRuntimeCommand(scripts["worker:siem"]),
    "typescript-siem-reference"
  );
  assert.equal(classifyRuntimeCommand(scripts["mcp:broker"]), "typescript-mcp-reference");

  for (const [script, expected] of Object.entries(
    fixture.commandOwnership.explicitGoTransitionContains
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

test("MCP tool catalog and current TypeScript broker behavior are characterized locally", () => {
  const fixture = loadHarnessFixture();
  const source = readRepoFile("apps/mcp/src/server.ts");
  const scripts = packageScripts();

  assert.equal(scripts["mcp:broker"], "tsx apps/mcp/src/server.ts");
  assert.match(source, /Content-Length: \$\{Buffer\.byteLength\(body, "utf8"\)\}\\r\\n\\r\\n/);
  assert.doesNotMatch(source, /console\.log/);

  for (const tool of fixture.mcp.approvedTools) {
    const section = sectionForTool(source, tool.name);
    for (const requiredField of tool.required) {
      assert.match(
        section,
        new RegExp(`"${requiredField}"`),
        `${tool.name} must keep required field ${requiredField}`
      );
    }
  }

  assert.match(
    source,
    /void drainSiemDeliveries\(\)\.catch\(\(\) => undefined\)/,
    "foundation characterization records that the current TypeScript MCP broker still opportunistically drains the TypeScript SIEM helper"
  );
});

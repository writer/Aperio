import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildEnvelope, stableDeliveryKey } from "../workers/siem-dispatcher";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type SiemParityFixture = {
  destinationId: string;
  stream: "FINDINGS";
  payload: Parameters<typeof stableDeliveryKey>[0];
  expectedDeliveryKey: string;
  reopenedSourceEventId: string;
  reopenedOccurredAt: string;
};

type SiemDedupeCasesFixture = {
  cases: Array<{
    name: string;
    destinationId: string;
    stream: "FINDINGS" | "EVENTS" | "AUDIT_LOGS";
    payload: Parameters<typeof stableDeliveryKey>[0];
    expectedDeliveryKey: string;
  }>;
};

type SiemEnvelopeCasesFixture = {
  cases: Array<{
    name: string;
    destinationId: string;
    organizationId: string;
    payload: Parameters<typeof buildEnvelope>[1];
    expectedEnvelope: ReturnType<typeof buildEnvelope>;
  }>;
};

function readJson<T>(relativePath: string): T {
  return JSON.parse(
    readFileSync(path.join(repoRoot, relativePath), "utf8")
  ) as T;
}

function readFixture(): SiemParityFixture {
  return readJson<SiemParityFixture>(
    "tests/fixtures/worker-parity/siem-finding-delivery.json"
  );
}

test("SIEM finding dedupe key includes finding occurrence", () => {
  const fixture = readFixture();
  const basePayload = fixture.payload;

  const first = stableDeliveryKey(basePayload, fixture.destinationId, fixture.stream);
  const reopened = stableDeliveryKey(
    {
      ...basePayload,
      occurredAt: fixture.reopenedOccurredAt,
      record: {
        ...basePayload.record,
        sourceEventId: fixture.reopenedSourceEventId
      }
    },
    fixture.destinationId,
    fixture.stream
  );

  assert.equal(first, fixture.expectedDeliveryKey);
  assert.notEqual(first, reopened);
  assert.equal(first, stableDeliveryKey(basePayload, fixture.destinationId, fixture.stream));
});

test("SIEM dedupe key shared cases cover stream, tenant, destination, and fallback identity", () => {
  const fixture = readJson<SiemDedupeCasesFixture>(
    "tests/fixtures/worker-parity/siem-dedupe-cases.json"
  );
  const seen = new Set<string>();

  for (const testCase of fixture.cases) {
    const actual = stableDeliveryKey(
      testCase.payload,
      testCase.destinationId,
      testCase.stream
    );
    assert.equal(actual, testCase.expectedDeliveryKey, testCase.name);
    assert.equal(seen.has(actual), false, `${testCase.name} should have a distinct key`);
    seen.add(actual);
  }
});

test("SIEM canonical envelope shared cases match TypeScript reference shape", () => {
  const fixture = readJson<SiemEnvelopeCasesFixture>(
    "tests/fixtures/worker-parity/siem-envelope-cases.json"
  );

  for (const testCase of fixture.cases) {
    assert.deepEqual(
      buildEnvelope(
        { id: testCase.destinationId, organizationId: testCase.organizationId },
        testCase.payload
      ),
      testCase.expectedEnvelope,
      testCase.name
    );
  }
});

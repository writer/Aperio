import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
type SiemEnvelopeKind = "finding" | "event" | "audit_log";
type SiemPayload = {
  kind: SiemEnvelopeKind;
  organizationId: string;
  occurredAt: string;
  record: Record<string, unknown>;
};
type SiemEnvelope = {
  schema_version: string;
  source: "aperio";
  producer: "aperio.sspm";
  destination_id: string;
  organization_id: string;
  kind: SiemEnvelopeKind;
  occurred_at: string;
  record: Record<string, unknown>;
};

type SiemParityFixture = {
  destinationId: string;
  stream: "FINDINGS";
  payload: SiemPayload;
  expectedDeliveryKey: string;
  reopenedSourceEventId: string;
  reopenedOccurredAt: string;
};

type SiemDedupeCasesFixture = {
  cases: Array<{
    name: string;
    destinationId: string;
    stream: "FINDINGS" | "EVENTS" | "AUDIT_LOGS";
    payload: SiemPayload;
    expectedDeliveryKey: string;
  }>;
};

type SiemEnvelopeCasesFixture = {
  cases: Array<{
    name: string;
    destinationId: string;
    organizationId: string;
    payload: SiemPayload;
    expectedEnvelope: SiemEnvelope;
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

function stringValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

function stableDeliveryKeyFromContract(
  payload: SiemPayload,
  destinationId: string,
  stream: "FINDINGS" | "EVENTS" | "AUDIT_LOGS"
) {
  const record = payload.record ?? {};
  const stableRecordId =
    stringValue(record.findingId) ??
    stringValue(record.id) ??
    stringValue(record.dedupeKey) ??
    stringValue(record.sourceEventId) ??
    JSON.stringify(record);
  const findingOccurrence =
    payload.kind === "finding"
      ? (stringValue(record.sourceEventId) ??
        stringValue(record.detectedAt) ??
        payload.occurredAt)
      : undefined;
  return createHash("sha256")
    .update(
      JSON.stringify({
        organizationId: payload.organizationId,
        destinationId,
        stream,
        kind: payload.kind,
        stableRecordId,
        ...(findingOccurrence
          ? {
              findingOccurrence,
              findingStatus: stringValue(record.status)
            }
          : {})
      })
    )
    .digest("hex");
}

function schemaVersion(kind: SiemEnvelopeKind) {
  if (kind === "finding") return "aperio.finding.v1";
  if (kind === "event") return "aperio.event.v1";
  return "aperio.audit_log.v1";
}

function buildEnvelopeFromContract(
  destination: { id: string; organizationId: string },
  payload: SiemPayload
): SiemEnvelope {
  return {
    schema_version: schemaVersion(payload.kind),
    source: "aperio",
    producer: "aperio.sspm",
    destination_id: destination.id,
    organization_id: payload.organizationId,
    kind: payload.kind,
    occurred_at: payload.occurredAt,
    record: payload.record
  };
}

test("SIEM finding dedupe key includes finding occurrence", () => {
  const fixture = readFixture();
  const basePayload = fixture.payload;

  const first = stableDeliveryKeyFromContract(basePayload, fixture.destinationId, fixture.stream);
  const reopened = stableDeliveryKeyFromContract(
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
  assert.equal(first, stableDeliveryKeyFromContract(basePayload, fixture.destinationId, fixture.stream));
});

test("SIEM dedupe key shared cases cover stream, tenant, destination, and fallback identity", () => {
  const fixture = readJson<SiemDedupeCasesFixture>(
    "tests/fixtures/worker-parity/siem-dedupe-cases.json"
  );
  const seen = new Set<string>();

  for (const testCase of fixture.cases) {
    const actual = stableDeliveryKeyFromContract(
      testCase.payload,
      testCase.destinationId,
      testCase.stream
    );
    assert.equal(actual, testCase.expectedDeliveryKey, testCase.name);
    assert.equal(seen.has(actual), false, `${testCase.name} should have a distinct key`);
    seen.add(actual);
  }
});

test("SIEM canonical envelope shared cases match the documented contract", () => {
  const fixture = readJson<SiemEnvelopeCasesFixture>(
    "tests/fixtures/worker-parity/siem-envelope-cases.json"
  );

  for (const testCase of fixture.cases) {
    assert.deepEqual(
      buildEnvelopeFromContract(
        { id: testCase.destinationId, organizationId: testCase.organizationId },
        testCase.payload
      ),
      testCase.expectedEnvelope,
      testCase.name
    );
  }
});

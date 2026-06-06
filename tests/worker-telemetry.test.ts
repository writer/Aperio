import assert from "node:assert/strict";
import test from "node:test";
import {
  emitWideEvent,
  setTelemetrySink
} from "../workers/telemetry";
import { siemDeliveryWideEvent } from "../workers/siem-dispatcher";
import { ingestionJobWideEvent } from "../workers/ingestion-worker";

test("emitWideEvent writes one schema-compliant line and drops empty fields", () => {
  const lines: string[] = [];
  const restore = setTelemetrySink((line) => lines.push(line));
  try {
    emitWideEvent({
      name: "unit.test",
      service: "tester",
      organizationId: "org_1",
      dimensions: { kept: "yes", blank: "", missing: undefined },
      measurements: { count: 3, nan: Number.NaN }
    });
  } finally {
    restore();
  }

  assert.equal(lines.length, 1);
  const event = JSON.parse(lines[0]) as Record<string, unknown>;
  assert.equal(event.kind, "wide_event");
  assert.equal(event.event_name, "unit.test");
  assert.equal(event.service, "tester");
  assert.equal(event.organization_id, "org_1");
  assert.equal(typeof event.occurred_at, "string");
  assert.equal(event.kept, "yes");
  assert.equal(event.count, 3);
  assert.ok(!("blank" in event), "empty string dimension should be dropped");
  assert.ok(!("missing" in event), "undefined dimension should be dropped");
  assert.ok(!("nan" in event), "non-finite measurement should be dropped");
});

test("emitWideEvent omits organization_id when blank", () => {
  const lines: string[] = [];
  const restore = setTelemetrySink((line) => lines.push(line));
  try {
    emitWideEvent({ name: "no.org", service: "tester", organizationId: "   " });
  } finally {
    restore();
  }
  const event = JSON.parse(lines[0]) as Record<string, unknown>;
  assert.ok(!("organization_id" in event));
});

test("siemDeliveryWideEvent classifies outcome and omits a null destination id", () => {
  const base = {
    organizationId: "org_1",
    destinationId: null,
    stream: "FINDINGS",
    maxAttempts: 5,
    destinationKind: "SPLUNK_HEC",
    payloadKind: "finding",
    finalized: true,
    durationMs: 12
  };

  const delivered = siemDeliveryWideEvent({ ...base, attempts: 0, ok: true });
  assert.equal(delivered.dimensions?.outcome, "delivered");
  assert.equal(delivered.measurements?.attempt, 1);

  const retry = siemDeliveryWideEvent({ ...base, attempts: 1, ok: false });
  assert.equal(retry.dimensions?.outcome, "failed");

  const exhausted = siemDeliveryWideEvent({ ...base, attempts: 4, ok: false });
  assert.equal(exhausted.dimensions?.outcome, "dead_letter");

  const permanent = siemDeliveryWideEvent({
    ...base,
    attempts: 0,
    ok: false,
    permanent: true
  });
  assert.equal(permanent.dimensions?.outcome, "dead_letter");

  const lostLease = siemDeliveryWideEvent({
    ...base,
    attempts: 0,
    ok: true,
    finalized: false
  });
  assert.equal(lostLease.dimensions?.outcome, "lost_lease");

  // A null destination id must be dropped by the emitter rather than serialized.
  const lines: string[] = [];
  const restore = setTelemetrySink((line) => lines.push(line));
  try {
    emitWideEvent(delivered);
  } finally {
    restore();
  }
  const event = JSON.parse(lines[0]) as Record<string, unknown>;
  assert.equal(event.event_name, "siem.delivery.process");
  assert.equal(event.destination_kind, "SPLUNK_HEC");
  assert.ok(!("destination_id" in event));
});

test("ingestionJobWideEvent maps outcome, provider, and error kind", () => {
  const success = ingestionJobWideEvent({
    organizationId: "org_1",
    provider: "SLACK",
    eventType: "member_joined",
    attempts: 0,
    maxAttempts: 3,
    outcome: "succeeded",
    durationMs: 7
  });
  assert.equal(success.name, "ingestion.job.process");
  assert.equal(success.service, "ingestion-worker");
  assert.equal(success.dimensions?.outcome, "succeeded");
  assert.equal(success.dimensions?.provider, "SLACK");
  assert.equal(success.dimensions?.event_type, "member_joined");
  assert.equal(success.measurements?.attempt, 1);
  assert.equal(success.dimensions?.error_kind, undefined);

  const dead = ingestionJobWideEvent({
    organizationId: "org_1",
    provider: "GITHUB",
    eventType: "repository",
    attempts: 2,
    maxAttempts: 3,
    outcome: "dead_letter",
    durationMs: 9,
    errorName: "TypeError"
  });
  assert.equal(dead.dimensions?.outcome, "dead_letter");
  assert.equal(dead.dimensions?.error_kind, "TypeError");
  assert.equal(dead.measurements?.attempt, 3);

  const lostLease = ingestionJobWideEvent({
    organizationId: "org_1",
    provider: "GITHUB",
    eventType: "repository",
    attempts: 0,
    maxAttempts: 3,
    outcome: "lost_lease",
    durationMs: 5,
    errorName: "Error"
  });
  assert.equal(lostLease.dimensions?.outcome, "lost_lease");
  assert.equal(lostLease.dimensions?.error_kind, "Error");
});

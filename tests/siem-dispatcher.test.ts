import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { stableDeliveryKey } from "../workers/siem-dispatcher";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type SiemParityFixture = {
  destinationId: string;
  stream: "FINDINGS";
  payload: Parameters<typeof stableDeliveryKey>[0];
  expectedDeliveryKey: string;
  reopenedSourceEventId: string;
  reopenedOccurredAt: string;
};

function readFixture(): SiemParityFixture {
  return JSON.parse(
    readFileSync(
      path.join(repoRoot, "tests/fixtures/worker-parity/siem-finding-delivery.json"),
      "utf8"
    )
  ) as SiemParityFixture;
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

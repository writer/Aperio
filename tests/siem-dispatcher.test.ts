import assert from "node:assert/strict";
import test from "node:test";
import { stableDeliveryKey } from "../workers/siem-dispatcher";

test("SIEM finding dedupe key includes finding occurrence", () => {
  const basePayload = {
    kind: "finding" as const,
    organizationId: "org_1",
    occurredAt: "2026-06-06T00:00:00.000Z",
    record: {
      dedupeKey: "stable-finding",
      status: "OPEN"
    }
  };

  const first = stableDeliveryKey(basePayload, "dst_1", "FINDINGS");
  const reopened = stableDeliveryKey(
    {
      ...basePayload,
      occurredAt: "2026-06-06T01:00:00.000Z"
    },
    "dst_1",
    "FINDINGS"
  );

  assert.notEqual(first, reopened);
  assert.equal(first, stableDeliveryKey(basePayload, "dst_1", "FINDINGS"));
});

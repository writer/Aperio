import assert from "node:assert/strict";
import test from "node:test";
import { buildCerebroClaims, type SiemPayload } from "../workers/siem-dispatcher";

test("maps Aperio findings into Writer/Cerebro claims", () => {
  const payload: SiemPayload = {
    kind: "finding",
    organizationId: "org_cerebro",
    occurredAt: "2026-06-05T20:00:00.000Z",
    record: {
      schemaVersion: "aperio.finding.v1",
      ruleId: "github.public_repository_created",
      title: "Public GitHub repository created",
      description: "Repository visibility changed to public.",
      severity: "CRITICAL",
      riskScore: 95,
      target: "writer/public-demo",
      provider: "GITHUB",
      integrationId: "int_github",
      sourceEventId: "evt_123",
      source: "github.audit",
      eventType: "repository.publicized",
      dedupeKey: "dedupe-123"
    }
  };

  const claims = buildCerebroClaims(
    {
      organizationId: "org_cerebro",
      index: "writer-aperio-sspm"
    },
    payload
  );

  const findingExists = claims.find(
    (claim) =>
      claim.claim_type === "existence" &&
      claim.subject_ref.entity_type === "finding"
  );
  assert.ok(findingExists);
  assert.equal(findingExists.source_event_id, "evt_123");
  assert.equal(findingExists.attributes?.ruleId, "github.public_repository_created");

  assert.ok(
    claims.some(
      (claim) =>
        claim.claim_type === "relation" &&
        claim.predicate === "affects" &&
        claim.object_ref?.entity_type === "asset"
    )
  );
  assert.ok(
    claims.some(
      (claim) =>
        claim.claim_type === "attribute" &&
        claim.predicate === "severity" &&
        claim.object_value === "CRITICAL"
    )
  );
  assert.ok(
    claims.some(
      (claim) =>
        claim.claim_type === "attribute" &&
        claim.predicate === "riskScore" &&
        claim.object_value === "95"
    )
  );
});

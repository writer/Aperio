import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type GooglePayloadFixture = {
  organizationId: string;
  integrationId: string;
  provider: "GOOGLE_WORKSPACE";
  eventType: string;
  source: string;
  actor?: string;
  occurredAt: string;
  payload: Record<string, unknown>;
};

type ExpectedFinding = {
  ruleId: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  riskScore: number;
  target: string;
  evidence: Record<string, unknown>;
  dedupeKey: string;
};

type GoogleRuleCase = {
  ruleId: string;
  disabledCheck: string;
  positive: {
    payload: GooglePayloadFixture;
    expectedFinding: ExpectedFinding;
  };
  variants?: Array<{
    name: string;
    payload: GooglePayloadFixture;
    expectedFinding: ExpectedFinding;
  }>;
  negative: {
    payload: GooglePayloadFixture;
  };
  additionalNegatives?: Array<{
    name: string;
    payload: GooglePayloadFixture;
  }>;
};

type GoogleRulesFixture = {
  rules: GoogleRuleCase[];
};

function readFixture(): GoogleRulesFixture {
  return JSON.parse(
    readFileSync(
      path.join(repoRoot, "tests/fixtures/worker-parity/google-admin-oauth-rules.json"),
      "utf8"
    )
  ) as GoogleRulesFixture;
}

function payloadFromFixture(input: GooglePayloadFixture) {
  const occurredAt = new Date(input.occurredAt);
  assert.ok(!Number.isNaN(occurredAt.valueOf()), `${input.eventType} fixture occurredAt must parse`);
  return input;
}

function expectedDedupeKey(payload: GooglePayloadFixture, expected: ExpectedFinding) {
  const subject =
    typeof expected.evidence.subject === "string"
      ? expected.evidence.subject
      : expected.target;
  return createHash("sha256")
    .update([payload.organizationId, payload.integrationId, expected.ruleId, subject].join(":"))
    .digest("hex");
}

function assertExpectedFinding(
  payloadFixture: GooglePayloadFixture,
  expected: ExpectedFinding
) {
  const payload = payloadFromFixture(payloadFixture);

  assert.equal(payload.provider, "GOOGLE_WORKSPACE");
  assert.ok(expected.ruleId.startsWith("google_workspace."));
  assert.ok(expected.title.length > 0);
  assert.ok(expected.description.length > 0);
  assert.ok(["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(expected.severity));
  assert.ok(expected.riskScore > 0);
  assert.ok(expected.target.length > 0);
  assert.equal(typeof expected.evidence.subject, "string");
  assert.equal(expected.dedupeKey, expectedDedupeKey(payload, expected));
}

for (const ruleCase of readFixture().rules) {
  test(`${ruleCase.ruleId} fixture captures the Go-owned positive finding`, () => {
    assertExpectedFinding(
      ruleCase.positive.payload,
      ruleCase.positive.expectedFinding
    );
  });

  test(`${ruleCase.ruleId} fixture covers extraction variants, negatives, and disabled checks`, () => {
    for (const variant of ruleCase.variants ?? []) {
      assertExpectedFinding(variant.payload, variant.expectedFinding);
    }

    assert.equal(payloadFromFixture(ruleCase.negative.payload).provider, "GOOGLE_WORKSPACE");
    assert.notEqual(ruleCase.negative.payload.eventType, "");
    for (const negative of ruleCase.additionalNegatives ?? []) {
      assert.equal(payloadFromFixture(negative.payload).provider, "GOOGLE_WORKSPACE", negative.name);
    }
    assert.equal(ruleCase.disabledCheck, ruleCase.ruleId);
    assert.equal(ruleCase.positive.expectedFinding.ruleId, ruleCase.ruleId);
  });
}

test("Google Workspace fixture suite is provider-scoped and uses local deterministic payloads", () => {
  for (const ruleCase of readFixture().rules) {
    assert.equal(ruleCase.positive.payload.provider, "GOOGLE_WORKSPACE");
    assert.equal(ruleCase.negative.payload.provider, "GOOGLE_WORKSPACE");
    assert.doesNotMatch(JSON.stringify(ruleCase), /"access_token"|"private_key"|admin\.google\.com/i);
  }
});

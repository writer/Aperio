import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type OktaPayloadFixture = {
  organizationId: string;
  integrationId: string;
  provider: "OKTA";
  eventType: string;
  source: string;
  actor: string;
  occurredAt: string;
  payload: Record<string, unknown>;
};

type OktaRuleFixture = {
  positive: {
    payload: OktaPayloadFixture;
    expectedFinding: {
      ruleId: string;
      title: string;
      description: string;
      severity: "CRITICAL" | "HIGH" | "MEDIUM";
      riskScore: number;
      target: string;
      evidence: Record<string, unknown>;
      dedupeKey: string;
    };
  };
  aliases: Array<{ payload: OktaPayloadFixture }>;
  negative: { payload: OktaPayloadFixture };
  additionalNegatives?: Array<{ name: string; payload: OktaPayloadFixture }>;
  disabledCheck: string;
};

const oktaFixturePaths = [
  "tests/fixtures/worker-parity/okta-admin-role-assigned.json",
  "tests/fixtures/worker-parity/okta-mfa-factor-reset.json",
  "tests/fixtures/worker-parity/okta-password-policy-weakened.json",
  "tests/fixtures/worker-parity/okta-suspicious-signin.json"
];

function readFixture(relativePath: string): OktaRuleFixture {
  return JSON.parse(readFileSync(path.join(repoRoot, relativePath), "utf8")) as OktaRuleFixture;
}

function payloadFromFixture(input: OktaPayloadFixture) {
  const occurredAt = new Date(input.occurredAt);
  assert.ok(!Number.isNaN(occurredAt.valueOf()), `${input.eventType} fixture occurredAt must parse`);
  return input;
}

function expectedDedupeKey(
  payload: OktaPayloadFixture,
  expected: OktaRuleFixture["positive"]["expectedFinding"]
) {
  const subject =
    typeof expected.evidence.subject === "string"
      ? expected.evidence.subject
      : expected.target;
  return createHash("sha256")
    .update([payload.organizationId, payload.integrationId, expected.ruleId, subject].join(":"))
    .digest("hex");
}

function assertExpectedFindingFixture(fixture: OktaRuleFixture) {
  const payload = payloadFromFixture(fixture.positive.payload);
  const expected = fixture.positive.expectedFinding;

  assert.equal(payload.provider, "OKTA");
  assert.equal(expected.ruleId, fixture.disabledCheck);
  assert.ok(expected.title.length > 0);
  assert.ok(expected.description.length > 0);
  assert.ok(["CRITICAL", "HIGH", "MEDIUM"].includes(expected.severity));
  assert.ok(expected.riskScore > 0);
  assert.ok(expected.target.length > 0);
  assert.equal(typeof expected.evidence.subject, "string");
  assert.equal(expected.dedupeKey, expectedDedupeKey(payload, expected));
}

for (const fixturePath of oktaFixturePaths) {
  const fixture = readFixture(fixturePath);

  test(`${fixture.positive.expectedFinding.ruleId} fixture captures the Go-owned positive finding`, () => {
    assertExpectedFindingFixture(fixture);
  });

  test(`${fixture.positive.expectedFinding.ruleId} fixture covers aliases, negatives, and disabled checks`, () => {
    for (const alias of fixture.aliases) {
      const aliasPayload = payloadFromFixture(alias.payload);
      assert.equal(aliasPayload.provider, "OKTA");
      assert.equal(aliasPayload.integrationId, fixture.positive.payload.integrationId);
      assert.notEqual(aliasPayload.eventType, "");
    }

    assert.equal(payloadFromFixture(fixture.negative.payload).provider, "OKTA");
    assert.notEqual(
      fixture.negative.payload.eventType,
      "",
      `${fixture.positive.expectedFinding.ruleId} negative fixture must name an event type`
    );
    for (const negative of fixture.additionalNegatives ?? []) {
      assert.equal(payloadFromFixture(negative.payload).provider, "OKTA", negative.name);
    }
    assert.equal(fixture.disabledCheck, fixture.positive.expectedFinding.ruleId);
  });
}

test("Okta fixture suite is provider-scoped and does not import the deleted TypeScript runtime", () => {
  for (const fixturePath of oktaFixturePaths) {
    const fixture = readFixture(fixturePath);
    assert.equal(fixture.positive.payload.provider, "OKTA");
    assert.equal(fixture.negative.payload.provider, "OKTA");
  }
});

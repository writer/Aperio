import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dedupeKey, evaluateSecurityRules } from "../workers/ingestion-worker";

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
  return {
    ...input,
    occurredAt: new Date(input.occurredAt)
  };
}

function assertExpectedFinding(
  payloadFixture: GooglePayloadFixture,
  expected: ExpectedFinding
) {
  const payload = payloadFromFixture(payloadFixture);
  const findings = evaluateSecurityRules(payload);

  assert.equal(findings.length, 1);
  const [finding] = findings;
  assert.equal(finding.ruleId, expected.ruleId);
  assert.equal(finding.title, expected.title);
  assert.equal(finding.description, expected.description);
  assert.equal(finding.severity, expected.severity);
  assert.equal(finding.riskScore, expected.riskScore);
  assert.equal(finding.target, expected.target);
  assert.deepEqual(finding.evidence, expected.evidence);
  assert.equal(dedupeKey(payload, finding), expected.dedupeKey);
}

for (const ruleCase of readFixture().rules) {
  test(`${ruleCase.ruleId} matches the shared worker parity fixture`, () => {
    assertExpectedFinding(
      ruleCase.positive.payload,
      ruleCase.positive.expectedFinding
    );
  });

  test(`${ruleCase.ruleId} covers extraction variants, negatives, and disabled checks`, () => {
    for (const variant of ruleCase.variants ?? []) {
      assertExpectedFinding(variant.payload, variant.expectedFinding);
    }

    assert.equal(evaluateSecurityRules(payloadFromFixture(ruleCase.negative.payload)).length, 0);
    for (const negative of ruleCase.additionalNegatives ?? []) {
      assert.equal(
        evaluateSecurityRules(payloadFromFixture(negative.payload)).length,
        0,
        `${negative.name} should produce no finding`
      );
    }
    assert.equal(
      evaluateSecurityRules(payloadFromFixture(ruleCase.positive.payload), [
        ruleCase.disabledCheck
      ]).length,
      0
    );
  });
}

test("Google Workspace admin/OAuth rules do not match other providers", () => {
  const [externalSharing] = readFixture().rules;
  const findings = evaluateSecurityRules({
    ...payloadFromFixture(externalSharing.positive.payload),
    provider: "SLACK" as "GOOGLE_WORKSPACE",
    integrationId: "int_slack",
    source: "slack.audit"
  });

  assert.equal(findings.length, 0);
});

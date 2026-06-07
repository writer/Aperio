import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dedupeKey, evaluateSecurityRules } from "../workers/ingestion-worker";

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
  return {
    ...input,
    occurredAt: new Date(input.occurredAt)
  };
}

function oktaPayload(eventType: string, payload: Record<string, unknown>, provider = "OKTA") {
  return {
    organizationId: "org_1",
    integrationId: "int_okta",
    provider: provider as "OKTA",
    eventType,
    source: "okta.system_log",
    actor: "admin@example.com",
    occurredAt: new Date("2026-06-06T00:00:00.000Z"),
    payload
  };
}

for (const fixturePath of oktaFixturePaths) {
  const fixture = readFixture(fixturePath);

  test(`${fixture.positive.expectedFinding.ruleId} matches the shared worker parity fixture`, () => {
    const payload = payloadFromFixture(fixture.positive.payload);
    const findings = evaluateSecurityRules(payload);

    assert.equal(findings.length, 1);
    const [finding] = findings;
    assert.equal(finding.ruleId, fixture.positive.expectedFinding.ruleId);
    assert.equal(finding.title, fixture.positive.expectedFinding.title);
    assert.equal(finding.description, fixture.positive.expectedFinding.description);
    assert.equal(finding.severity, fixture.positive.expectedFinding.severity);
    assert.equal(finding.riskScore, fixture.positive.expectedFinding.riskScore);
    assert.equal(finding.target, fixture.positive.expectedFinding.target);
    assert.deepEqual(finding.evidence, fixture.positive.expectedFinding.evidence);
    assert.equal(dedupeKey(payload, finding), fixture.positive.expectedFinding.dedupeKey);
  });

  test(`${fixture.positive.expectedFinding.ruleId} covers aliases, negatives, and disabled checks`, () => {
    for (const alias of fixture.aliases) {
      const aliasFindings = evaluateSecurityRules(payloadFromFixture(alias.payload));
      assert.equal(aliasFindings.length, 1, `${alias.payload.eventType} should produce one finding`);
      assert.equal(aliasFindings[0].ruleId, fixture.positive.expectedFinding.ruleId);
    }

    assert.equal(evaluateSecurityRules(payloadFromFixture(fixture.negative.payload)).length, 0);
    for (const negative of fixture.additionalNegatives ?? []) {
      assert.equal(
        evaluateSecurityRules(payloadFromFixture(negative.payload)).length,
        0,
        `${negative.name} should produce no finding`
      );
    }
    assert.equal(
      evaluateSecurityRules(payloadFromFixture(fixture.positive.payload), [fixture.disabledCheck])
        .length,
      0
    );
  });
}

test("Okta rules do not match other providers", () => {
  const findings = evaluateSecurityRules({
    ...oktaPayload(
      "user.account.privilege.grant",
      {
        target: [{ alternateId: "new-admin@example.com", type: "User" }],
        debugContext: { debugData: { role: "SUPER_ADMIN" } }
      },
      "SLACK"
    ),
    integrationId: "int_slack",
    source: "slack.audit"
  } as Parameters<typeof evaluateSecurityRules>[0]);

  assert.equal(findings.length, 0);
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type SlackPayloadFixture = {
  organizationId: string;
  integrationId: string;
  provider: "SLACK";
  eventType: string;
  source: string;
  actor: string;
  occurredAt: string;
  payload: Record<string, unknown>;
};

type SlackParityFixture = {
  positive: {
    payload: SlackPayloadFixture;
    expectedFinding: {
      ruleId: string;
      title: string;
      description: string;
      severity: "CRITICAL";
      riskScore: number;
      target: string;
      evidence: Record<string, unknown>;
      dedupeKey: string;
    };
  };
  alias: {
    payload: SlackPayloadFixture;
  };
  negative: {
    payload: SlackPayloadFixture;
  };
  disabledCheck: string;
};

function readFixture(): SlackParityFixture {
  return JSON.parse(
    readFileSync(
      path.join(repoRoot, "tests/fixtures/worker-parity/slack-mfa-disabled.json"),
      "utf8"
    )
  ) as SlackParityFixture;
}

function expectedDedupeKey(
  payload: SlackPayloadFixture,
  expected: SlackParityFixture["positive"]["expectedFinding"]
) {
  const subject =
    typeof expected.evidence.subject === "string"
      ? expected.evidence.subject
      : expected.target;
  return createHash("sha256")
    .update([payload.organizationId, payload.integrationId, expected.ruleId, subject].join(":"))
    .digest("hex");
}

test("Slack MFA disabled fixture captures the Go-owned positive finding", () => {
  const fixture = readFixture();
  const { payload, expectedFinding } = fixture.positive;

  assert.equal(payload.provider, "SLACK");
  assert.equal(payload.eventType, "mfa.disabled");
  assert.equal(payload.payload.user?.["email"], "user@example.com");
  assert.equal(expectedFinding.ruleId, fixture.disabledCheck);
  assert.equal(expectedFinding.title, "Slack multi-factor authentication disabled");
  assert.equal(expectedFinding.severity, "CRITICAL");
  assert.equal(expectedFinding.riskScore, 90);
  assert.equal(expectedFinding.target, "user@example.com");
  assert.deepEqual(expectedFinding.evidence, {
    user: "user@example.com",
    subject: "user@example.com"
  });
  assert.equal(expectedFinding.dedupeKey, expectedDedupeKey(payload, expectedFinding));
});

test("Slack parity fixture covers alias, non-detection, and disabled-check metadata", () => {
  const fixture = readFixture();

  assert.equal(fixture.alias.payload.provider, "SLACK");
  assert.equal(fixture.alias.payload.eventType, "two-factor auth disabled");
  assert.equal(fixture.alias.payload.payload.user?.["email"], fixture.positive.expectedFinding.target);
  assert.equal(fixture.negative.payload.provider, "SLACK");
  assert.equal(fixture.negative.payload.eventType, "user_login");
  assert.equal(fixture.disabledCheck, fixture.positive.expectedFinding.ruleId);
});

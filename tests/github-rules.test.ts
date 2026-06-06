import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dedupeKey, evaluateSecurityRules } from "../workers/ingestion-worker";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type GitHubPayloadFixture = {
  organizationId: string;
  integrationId: string;
  provider: "GITHUB";
  eventType: string;
  source: string;
  actor: string;
  occurredAt: string;
  payload: Record<string, unknown>;
};

type GitHubParityFixture = {
  positive: {
    payload: GitHubPayloadFixture;
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
  negative: {
    payload: GitHubPayloadFixture;
  };
  disabledCheck: string;
};

function readFixture(): GitHubParityFixture {
  return JSON.parse(
    readFileSync(
      path.join(repoRoot, "tests/fixtures/worker-parity/github-public-repository.json"),
      "utf8"
    )
  ) as GitHubParityFixture;
}

function payloadFromFixture(input: GitHubParityFixture["positive"]["payload"]) {
  return {
    ...input,
    occurredAt: new Date(input.occurredAt)
  };
}

test("GitHub public repository rule matches the shared worker parity fixture", () => {
  const fixture = readFixture();
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

test("GitHub parity fixture covers private and disabled-check negatives", () => {
  const fixture = readFixture();

  assert.equal(evaluateSecurityRules(payloadFromFixture(fixture.negative.payload)).length, 0);
  assert.equal(
    evaluateSecurityRules(payloadFromFixture(fixture.positive.payload), [fixture.disabledCheck])
      .length,
    0
  );
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  aggregateRiskScore,
  calculateFindingRiskScore
} from "../packages/shared/src/risk-scoring";

test("increases finding risk for privileged external mailbox exposure", () => {
  const score = calculateFindingRiskScore({
    baseRiskScore: 78,
    severity: "HIGH",
    detectedAt: new Date(),
    evidence: {
      mailbox: "admin@example.com",
      forwardedTo: "archive@external.net",
      delegatedAdmin: true,
      delegateCount: 2,
      sendAsCount: 1
    }
  });

  assert.ok(score > 78);
  assert.ok(score <= 100);
});

test("aggregate risk score emphasizes critical and broad active risk", () => {
  const concentrated = aggregateRiskScore([
    {
      riskScore: 94,
      severity: "CRITICAL",
      status: "OPEN",
      detectedAt: new Date(),
      integration: { provider: "GOOGLE_WORKSPACE" }
    },
    {
      riskScore: 88,
      severity: "HIGH",
      status: "OPEN",
      detectedAt: new Date(),
      integration: { provider: "GITHUB" }
    }
  ]);
  const moderate = aggregateRiskScore([
    {
      riskScore: 52,
      severity: "MEDIUM",
      status: "OPEN",
      detectedAt: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000),
      integration: { provider: "GOOGLE_WORKSPACE" }
    }
  ]);

  assert.ok(concentrated > moderate);
  assert.ok(concentrated <= 100);
  assert.ok(moderate >= 0);
});

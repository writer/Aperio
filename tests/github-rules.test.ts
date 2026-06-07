import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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
  alias: {
    payload: GitHubPayloadFixture;
  };
  canonicalPrivateNegative: {
    payload: GitHubPayloadFixture;
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

function expectedDedupeKey(
  payload: GitHubPayloadFixture,
  expected: GitHubParityFixture["positive"]["expectedFinding"]
) {
  const subject =
    typeof expected.evidence.subject === "string"
      ? expected.evidence.subject
      : expected.target;
  return createHash("sha256")
    .update([payload.organizationId, payload.integrationId, expected.ruleId, subject].join(":"))
    .digest("hex");
}

test("GitHub public repository fixture captures the Go-owned positive finding", () => {
  const fixture = readFixture();
  const { payload, expectedFinding } = fixture.positive;

  assert.equal(payload.provider, "GITHUB");
  assert.equal(payload.payload.repository?.["visibility"], "public");
  assert.equal(payload.payload.repository?.["private"], false);
  assert.equal(expectedFinding.ruleId, fixture.disabledCheck);
  assert.equal(expectedFinding.title, "Public GitHub repository created");
  assert.equal(expectedFinding.severity, "CRITICAL");
  assert.equal(expectedFinding.riskScore, 95);
  assert.equal(expectedFinding.target, "writer/aperio");
  assert.deepEqual(expectedFinding.evidence, {
    repository: "writer/aperio",
    subject: "writer/aperio",
    visibility: "public"
  });
  assert.equal(expectedFinding.dedupeKey, expectedDedupeKey(payload, expectedFinding));
});

test("GitHub parity fixture covers alias, canonical private negative, and disabled-check metadata", () => {
  const fixture = readFixture();

  assert.equal(fixture.alias.payload.provider, "GITHUB");
  assert.equal(fixture.alias.payload.eventType, "PUBLIC_REPOSITORY_CREATED");
  assert.equal(fixture.alias.payload.payload.repository?.["full_name"], "writer/aperio");
  assert.equal(fixture.canonicalPrivateNegative.payload.provider, "GITHUB");
  assert.equal(fixture.canonicalPrivateNegative.payload.eventType, "PUBLIC_REPOSITORY_CREATED");
  assert.equal(fixture.canonicalPrivateNegative.payload.payload.repository?.["private"], true);
  assert.equal(fixture.canonicalPrivateNegative.payload.payload.repository?.["visibility"], "private");
  assert.equal(fixture.negative.payload.provider, "GITHUB");
  assert.equal(fixture.negative.payload.payload.repository?.["private"], true);
  assert.equal(fixture.negative.payload.payload.repository?.["visibility"], "private");
  assert.equal(fixture.disabledCheck, fixture.positive.expectedFinding.ruleId);
});

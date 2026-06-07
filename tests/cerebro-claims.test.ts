import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type CerebroClaimsFixture = {
  destination: {
    organizationId: string;
    endpointUrl: string;
    index: string;
  };
  payload: {
    kind: "finding";
    organizationId: string;
    occurredAt: string;
    record: Record<string, unknown>;
  };
  expected: {
    runtimeRequest: {
      method: string;
      url: string;
      headers: Record<string, string>;
    };
    claimRequest: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body: { runtime_id: string };
    };
    claimCount: number;
    sourceEventId: string;
    findingId: string;
    dedupeKey: string;
    findingURN: string;
  };
};

function readJson<T>(relativePath: string): T {
  return JSON.parse(
    readFileSync(path.join(repoRoot, relativePath), "utf8")
  ) as T;
}

test("Cerebro claim fixture preserves local request and claim mapping contract", () => {
  const fixture = readJson<CerebroClaimsFixture>(
    "tests/fixtures/worker-parity/siem-cerebro-claims.json"
  );

  assert.equal(fixture.payload.organizationId, fixture.destination.organizationId);
  assert.equal(fixture.payload.record.sourceEventId, fixture.expected.sourceEventId);
  assert.equal(fixture.payload.record.findingId, fixture.expected.findingId);
  assert.equal(fixture.payload.record.dedupeKey, fixture.expected.dedupeKey);
  assert.equal(fixture.expected.claimCount, 11);
  assert.equal(
    fixture.expected.findingURN,
    `urn:cerebro:${fixture.destination.organizationId}:runtime:${fixture.destination.index}:finding:${fixture.expected.dedupeKey}`
  );
  assert.equal(
    fixture.expected.runtimeRequest.url,
    `${fixture.destination.endpointUrl}/source-runtimes/${fixture.destination.index}`
  );
  assert.equal(
    fixture.expected.claimRequest.url,
    `${fixture.destination.endpointUrl}/source-runtimes/${fixture.destination.index}/claims`
  );
  assert.equal(fixture.expected.runtimeRequest.method, "GET");
  assert.equal(fixture.expected.claimRequest.method, "POST");
  assert.equal(fixture.expected.claimRequest.body.runtime_id, fixture.destination.index);
  assert.match(fixture.expected.runtimeRequest.headers.Authorization, /^Bearer /);
  assert.match(fixture.expected.claimRequest.headers.Authorization, /^Bearer /);
});

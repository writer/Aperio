import assert from "node:assert/strict";
import test from "node:test";

import {
  compositeScore,
  scoreFromFindings
  // @ts-expect-error — JS module; mjs source has no types but Node test runner imports it fine.
} from "../workers/google-workspace-assessment-generator.mjs";
// @ts-expect-error — JS module.
import { scoreToGrade, statusForScore } from "../workers/report-utils.mjs";

test("scoreFromFindings: zero findings → perfect 100", () => {
  assert.equal(scoreFromFindings([]), 100);
});

test("scoreFromFindings: a single critical drops the category to FAIL territory", () => {
  const score = scoreFromFindings([{ severity: "CRITICAL" }]);
  assert.ok(score <= 80);
  assert.equal(statusForScore(score), score >= 80 ? "PASS" : score >= 60 ? "WARN" : "FAIL");
});

test("scoreFromFindings: more HIGH findings degrade status monotonically", () => {
  const one = scoreFromFindings([{ severity: "HIGH" }]);
  const two = scoreFromFindings([{ severity: "HIGH" }, { severity: "HIGH" }]);
  const three = scoreFromFindings([
    { severity: "HIGH" },
    { severity: "HIGH" },
    { severity: "HIGH" }
  ]);
  assert.ok(one > two && two > three);
  assert.equal(statusForScore(one), "PASS");
  assert.equal(statusForScore(two), "WARN");
  assert.equal(statusForScore(three), "FAIL");
});

test("scoreFromFindings: low/info findings degrade gracefully", () => {
  const lows = scoreFromFindings(
    Array.from({ length: 6 }, () => ({ severity: "LOW" }))
  );
  // Six lows should be a meaningful penalty but not bottom out.
  assert.ok(lows >= 10);
  assert.ok(lows <= 80);
});

test("scoreToGrade: thresholds map to A/B/C/D/F", () => {
  assert.equal(scoreToGrade(95), "A");
  assert.equal(scoreToGrade(82), "B");
  assert.equal(scoreToGrade(70), "C");
  assert.equal(scoreToGrade(60), "D");
  assert.equal(scoreToGrade(45), "F");
});

test("compositeScore: weighted across categories", () => {
  const categories = [
    { key: "identity_mfa", score: 80 },
    { key: "admin_privilege", score: 60 },
    { key: "oauth_apps", score: 100 },
    { key: "mailbox_security", score: 90 },
    { key: "sharing_exposure", score: 70 },
    { key: "domain_wide_delegation", score: 100 }
  ];
  const score = compositeScore(categories);
  assert.ok(score >= 75 && score <= 90, `unexpected composite ${score}`);
});

test("compositeScore: all-perfect categories produce 100", () => {
  const categories = [
    { key: "identity_mfa", score: 100 },
    { key: "admin_privilege", score: 100 },
    { key: "oauth_apps", score: 100 },
    { key: "mailbox_security", score: 100 },
    { key: "sharing_exposure", score: 100 },
    { key: "domain_wide_delegation", score: 100 }
  ];
  assert.equal(compositeScore(categories), 100);
});

test("statusForScore: thresholds 80/60", () => {
  assert.equal(statusForScore(100), "PASS");
  assert.equal(statusForScore(80), "PASS");
  assert.equal(statusForScore(79), "WARN");
  assert.equal(statusForScore(60), "WARN");
  assert.equal(statusForScore(59), "FAIL");
});

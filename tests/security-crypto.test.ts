import assert from "node:assert/strict";
import test from "node:test";
import { decryptString } from "@aperio/security";

test("decrypts Go-written AES-GCM credential envelopes", (t) => {
  const previousKey = process.env.APERIO_ENCRYPTION_KEY;
  t.after(() => {
    if (previousKey === undefined) {
      delete process.env.APERIO_ENCRYPTION_KEY;
    } else {
      process.env.APERIO_ENCRYPTION_KEY = previousKey;
    }
  });

  process.env.APERIO_ENCRYPTION_KEY =
    "base64:" + Buffer.from("0123456789abcdef0123456789abcdef").toString("base64");
  const encrypted =
    "eyJ2ZXJzaW9uIjoxLCJhbGdvcml0aG0iOiJhZXMtMjU2LWdjbSIsIml2IjoiTVRJek5EVTJOemc1TURFeSIsInRhZyI6Im1sUjJUS1QyMmdsMHBOOTRNa0NYX3ciLCJjaXBoZXJ0ZXh0IjoiN1Qta25Jc0lRakVsOW1XQWRNSjNfUDJQaDE5X3RVellFaDgifQ";

  assert.equal(
    decryptString(encrypted, "org_demo:GITHUB:writer:access_token"),
    "demo-provider-token-GITHUB"
  );
  assert.throws(() => decryptString(encrypted, "wrong-aad"));
});

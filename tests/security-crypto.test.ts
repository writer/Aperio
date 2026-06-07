import assert from "node:assert/strict";
import test from "node:test";
import type { TestContext } from "node:test";
import { decryptString } from "@aperio/security";

const fixtureKey =
  "base64:" + Buffer.from("0123456789abcdef0123456789abcdef").toString("base64");
const fixtureAAD = "org_demo:GITHUB:writer:access_token";
const fixturePlaintext = "demo-provider-token-GITHUB";
const goWrittenEnvelope =
  "eyJ2ZXJzaW9uIjoxLCJhbGdvcml0aG0iOiJhZXMtMjU2LWdjbSIsIml2IjoiTVRJek5EVTJOemc1TURFeSIsInRhZyI6Im1sUjJUS1QyMmdsMHBOOTRNa0NYX3ciLCJjaXBoZXJ0ZXh0IjoiN1Qta25Jc0lRakVsOW1XQWRNSjNfUDJQaDE5X3RVellFaDgifQ";

function withEncryptionKey(t: TestContext) {
  const previousKey = process.env.APERIO_ENCRYPTION_KEY;
  t.after(() => {
    if (previousKey === undefined) {
      delete process.env.APERIO_ENCRYPTION_KEY;
    } else {
      process.env.APERIO_ENCRYPTION_KEY = previousKey;
    }
  });
  process.env.APERIO_ENCRYPTION_KEY = fixtureKey;
}

function tamperEnvelope(encrypted: string) {
  const envelope = JSON.parse(Buffer.from(encrypted, "base64url").toString("utf8")) as {
    tag: string;
  };
  envelope.tag = Buffer.alloc(16, 0).toString("base64url");
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

function thrownMessage(fn: () => unknown) {
  try {
    fn();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  assert.fail("expected function to throw");
}

test("decrypts Go-written AES-GCM credential envelopes", (t) => {
  withEncryptionKey(t);

  assert.equal(
    decryptString(goWrittenEnvelope, fixtureAAD),
    fixturePlaintext
  );
  assert.throws(() => decryptString(goWrittenEnvelope, "wrong-aad"));
});

test("credential envelopes fail closed for missing key, malformed data, wrong AAD, and tampering", (t) => {
  const previousKey = process.env.APERIO_ENCRYPTION_KEY;
  t.after(() => {
    if (previousKey === undefined) {
      delete process.env.APERIO_ENCRYPTION_KEY;
    } else {
      process.env.APERIO_ENCRYPTION_KEY = previousKey;
    }
  });

  delete process.env.APERIO_ENCRYPTION_KEY;
  const missingKeyMessage = thrownMessage(() => decryptString(goWrittenEnvelope, fixtureAAD));
  assert.match(missingKeyMessage, /APERIO_ENCRYPTION_KEY is required/);

  process.env.APERIO_ENCRYPTION_KEY = fixtureKey;
  const malformedMessage = thrownMessage(() => decryptString("not-a-valid-envelope", fixtureAAD));
  assert.match(malformedMessage, /Encrypted value is malformed/);

  const wrongAADMessage = thrownMessage(() =>
    decryptString(goWrittenEnvelope, "org_demo:GITHUB:writer:refresh_token")
  );
  assert.match(wrongAADMessage, /Encrypted value authentication failed/);

  const tamperedMessage = thrownMessage(() =>
    decryptString(tamperEnvelope(goWrittenEnvelope), fixtureAAD)
  );
  assert.match(tamperedMessage, /Encrypted value authentication failed/);

  for (const message of [
    missingKeyMessage,
    malformedMessage,
    wrongAADMessage,
    tamperedMessage
  ]) {
    assert.doesNotMatch(message, new RegExp(fixturePlaintext));
  }
});

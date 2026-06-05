import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { scanGoogleWorkspaceMailboxForwarding } from "../apps/api/src/routes/integrations";

test("returns disabled scan when service account config is absent", async () => {
  const originalClientEmail = process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL;
  const originalPrivateKey = process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY;

  delete process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL;
  delete process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY;

  try {
    const result = await scanGoogleWorkspaceMailboxForwarding({
      accessToken: "oauth-token",
      integrationId: "integration-1",
      organizationId: "org-1",
      externalAccountId: "example.com",
      googleMailboxScanClientEmail: null,
      encryptedGoogleMailboxScanPrivateKey: null
    });

    assert.equal(result.scanEnabled, false);
    assert.equal(result.scannedMailboxCount, 0);
    assert.deepEqual(result.payloads, []);
  } finally {
    if (originalClientEmail) {
      process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL = originalClientEmail;
    }
    if (originalPrivateKey) {
      process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY = originalPrivateKey;
    }
  }
});

test("scans mailbox forwarding settings when service account config is present", async () => {
  const originalClientEmail = process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL;
  const originalPrivateKey = process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY;
  const originalFetch = global.fetch;
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

  process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL =
    "forwarding-scanner@example.iam.gserviceaccount.com";
  process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();

  global.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url === "https://oauth2.googleapis.com/token") {
      const body = init?.body;
      const params =
        typeof body === "string"
          ? new URLSearchParams(body)
          : body instanceof URLSearchParams
            ? body
            : new URLSearchParams();
      const assertion = params.get("assertion");
      const payload = assertion?.split(".")[1];
      const claims = payload
        ? JSON.parse(Buffer.from(payload, "base64url").toString("utf8"))
        : {};
      const subject = typeof claims.sub === "string" ? claims.sub : "unknown@example.com";

      return new Response(JSON.stringify({ access_token: `service-token:${subject}` }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }

    if (url.startsWith("https://admin.googleapis.com/admin/directory/v1/users")) {
      return new Response(
        JSON.stringify({
          users: [
            { primaryEmail: "alice@example.com" },
            { primaryEmail: "bob@example.com" }
          ]
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }

    if (url === "https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding") {
      const authHeader = (init?.headers as Record<string, string> | undefined)?.authorization;
      const subject = authHeader?.replace("Bearer service-token:", "") ?? "";

      return new Response(
        JSON.stringify(
          subject === "alice@example.com"
            ? {
                enabled: true,
                emailAddress: "security-archive@example.net",
                disposition: "leaveInInbox"
              }
            : { enabled: false }
        ),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }

    if (url === "https://gmail.googleapis.com/gmail/v1/users/me/settings/delegates") {
      const authHeader = (init?.headers as Record<string, string> | undefined)?.authorization;
      const subject = authHeader?.replace("Bearer service-token:", "") ?? "";

      return new Response(
        JSON.stringify(
          subject === "alice@example.com"
            ? {
                delegates: [
                  {
                    delegateEmail: "delegate@example.com",
                    verificationStatus: "accepted"
                  }
                ]
              }
            : { delegates: [] }
        ),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }

    if (url === "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs") {
      const authHeader = (init?.headers as Record<string, string> | undefined)?.authorization;
      const subject = authHeader?.replace("Bearer service-token:", "") ?? "";

      return new Response(
        JSON.stringify(
          subject === "alice@example.com"
            ? {
                sendAs: [
                  { sendAsEmail: "alice@example.com", isPrimary: true },
                  { sendAsEmail: "exec@example.net", isPrimary: false, verificationStatus: "accepted" }
                ]
              }
            : {
                sendAs: [{ sendAsEmail: "bob@example.com", isPrimary: true }]
              }
        ),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }

    throw new Error(`Unexpected fetch request: ${url}`);
  };

  try {
    const result = await scanGoogleWorkspaceMailboxForwarding({
      accessToken: "oauth-token",
      integrationId: "integration-1",
      organizationId: "org-1",
      externalAccountId: "example.com",
      googleMailboxScanClientEmail: null,
      encryptedGoogleMailboxScanPrivateKey: null
    });

    assert.equal(result.scanEnabled, true);
    assert.equal(result.scannedMailboxCount, 2);
    assert.equal(result.payloads.length, 3);
    assert.equal(result.payloads[0]?.eventType, "EMAIL_FORWARDING_ENABLED");
    assert.equal(result.payloads[0]?.source, "google_workspace.settings.gmail");
    assert.equal(result.payloads[0]?.actor, "alice@example.com");
    assert.deepEqual(result.payloads[0]?.payload.parameters, {
      email: "alice@example.com",
      enabled: true,
      forwarding_address: "security-archive@example.net",
      forwarding_disposition: "leaveInInbox"
    });
    assert.equal(result.payloads[1]?.eventType, "MAILBOX_DELEGATION_GRANTED");
    assert.equal(result.payloads[2]?.eventType, "FORWARDING_DELEGATE_SEND_AS_COMBO");
  } finally {
    global.fetch = originalFetch;

    if (originalClientEmail) {
      process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL = originalClientEmail;
    } else {
      delete process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL;
    }

    if (originalPrivateKey) {
      process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY = originalPrivateKey;
    } else {
      delete process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY;
    }
  }
});

import assert from "node:assert/strict";
import test from "node:test";
import { scanGoogleWorkspaceAdminPosture } from "../apps/api/src/routes/integrations";

test("returns no admin posture findings when admins are healthy", async () => {
  const originalFetch = global.fetch;

  global.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url.startsWith("https://admin.googleapis.com/admin/directory/v1/users")) {
      return new Response(
        JSON.stringify({
          users: [
            {
              primaryEmail: "admin@example.com",
              isAdmin: true,
              isEnrolledIn2Sv: true,
              isEnforcedIn2Sv: true,
              recoveryEmail: "admin@example.com"
            },
            {
              primaryEmail: "member@example.com",
              isAdmin: false,
              isEnrolledIn2Sv: false,
              isEnforcedIn2Sv: false
            }
          ]
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }

    throw new Error(`Unexpected fetch request: ${url}`);
  };

  try {
    const result = await scanGoogleWorkspaceAdminPosture({
      accessToken: "oauth-token",
      integrationId: "integration-1",
      organizationId: "org-1",
      externalAccountId: "example.com"
    });

    assert.equal(result.scanEnabled, true);
    assert.equal(result.scannedAdminCount, 1);
    assert.deepEqual(result.payloads, []);
  } finally {
    global.fetch = originalFetch;
  }
});

test("flags admin posture gaps from current state", async () => {
  const originalFetch = global.fetch;

  global.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url.startsWith("https://admin.googleapis.com/admin/directory/v1/users")) {
      return new Response(
        JSON.stringify({
          users: [
            {
              primaryEmail: "owner@example.com",
              isAdmin: true,
              isEnrolledIn2Sv: false,
              isEnforcedIn2Sv: false,
              recoveryEmail: "owner@gmail.com"
            },
            {
              primaryEmail: "delegated@example.com",
              isDelegatedAdmin: true,
              isEnrolledIn2Sv: true,
              isEnforcedIn2Sv: false,
              recoveryEmail: "delegated@example.com"
            }
          ]
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }

    throw new Error(`Unexpected fetch request: ${url}`);
  };

  try {
    const result = await scanGoogleWorkspaceAdminPosture({
      accessToken: "oauth-token",
      integrationId: "integration-1",
      organizationId: "org-1",
      externalAccountId: "example.com"
    });

    assert.equal(result.scanEnabled, true);
    assert.equal(result.scannedAdminCount, 2);
    assert.deepEqual(
      result.payloads.map((payload) => ({
        actor: payload.actor,
        eventType: payload.eventType,
        parameters: payload.payload.parameters
      })),
      [
        {
          actor: "owner@example.com",
          eventType: "ADMIN_MFA_NOT_ENFORCED",
          parameters: {
            email: "owner@example.com",
            is_admin: true,
            is_delegated_admin: false,
            mfa_enrolled: false,
            mfa_enforced: false
          }
        },
        {
          actor: "owner@example.com",
          eventType: "ADMIN_EXTERNAL_RECOVERY_EMAIL",
          parameters: {
            email: "owner@example.com",
            recovery_email: "owner@gmail.com",
            recovery_phone: null,
            is_admin: true,
            is_delegated_admin: false
          }
        },
        {
          actor: "delegated@example.com",
          eventType: "ADMIN_MFA_NOT_ENFORCED",
          parameters: {
            email: "delegated@example.com",
            is_admin: false,
            is_delegated_admin: true,
            mfa_enrolled: true,
            mfa_enforced: false
          }
        }
      ]
    );
  } finally {
    global.fetch = originalFetch;
  }
});

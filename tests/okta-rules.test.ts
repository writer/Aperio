import assert from "node:assert/strict";
import test from "node:test";
import { evaluateSecurityRules } from "../workers/ingestion-worker";

function oktaPayload(eventType: string, payload: Record<string, unknown>) {
  return {
    organizationId: "org_1",
    integrationId: "int_okta",
    provider: "OKTA" as const,
    eventType,
    source: "okta.system_log",
    actor: "admin@example.com",
    occurredAt: new Date("2026-06-06T00:00:00.000Z"),
    payload
  };
}

test("Okta admin role grant opens critical finding for privileged roles", () => {
  const findings = evaluateSecurityRules(
    oktaPayload("user.account.privilege.grant", {
      actor: { alternateId: "admin@example.com", type: "User" },
      target: [
        { alternateId: "new-admin@example.com", type: "User" },
        { displayName: "SUPER_ADMIN", type: "Role" }
      ],
      debugContext: { debugData: { role: "SUPER_ADMIN" } }
    })
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "okta.admin_role_assigned");
  assert.equal(findings[0].severity, "CRITICAL");
  assert.equal(findings[0].target, "new-admin@example.com");
  assert.equal(findings[0].evidence?.grantedRole, "SUPER_ADMIN");

  const spelledOut = evaluateSecurityRules(
    oktaPayload("user.account.privilege.grant", {
      actor: { alternateId: "admin@example.com", type: "User" },
      target: [
        { alternateId: "new-admin@example.com", type: "User" },
        { displayName: "Organization Administrator", type: "Role" }
      ]
    })
  );
  assert.equal(spelledOut.length, 1);
  assert.equal(spelledOut[0].ruleId, "okta.admin_role_assigned");
  assert.equal(spelledOut[0].evidence?.grantedRole, "Organization Administrator");
});

test("Okta admin role grant ignores non-privileged roles and disabled checks", () => {
  const payload = oktaPayload("user.account.privilege.grant", {
    target: [
      { alternateId: "analyst@example.com", type: "User" },
      { displayName: "HELP_DESK_ADMIN", type: "Role" }
    ],
    debugContext: { debugData: { role: "HELP_DESK_ADMIN" } }
  });

  assert.equal(evaluateSecurityRules(payload).length, 0);

  const privileged = oktaPayload("user.account.privilege.grant", {
    target: [
      { alternateId: "new-admin@example.com", type: "User" },
      { displayName: "ORG_ADMIN", type: "Role" }
    ],
    debugContext: { debugData: { role: "ORG_ADMIN" } }
  });
  assert.equal(
    evaluateSecurityRules(privileged, ["okta.admin_role_assigned"]).length,
    0
  );
});

test("Okta MFA factor reset alerts only for admin resets of another user", () => {
  const findings = evaluateSecurityRules(
    oktaPayload("user.mfa.factor.reset_all", {
      actor: { alternateId: "helpdesk@example.com", type: "User" },
      target: [{ alternateId: "employee@example.com", type: "User" }],
      debugContext: { debugData: { factorType: "all" } }
    })
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "okta.mfa_factor_reset");
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].target, "employee@example.com");
  assert.equal(findings[0].evidence?.actor, "helpdesk@example.com");

  const selfService = evaluateSecurityRules(
    oktaPayload("user.mfa.factor.reset", {
      actor: { alternateId: "employee@example.com", type: "User" },
      target: [{ alternateId: "employee@example.com", type: "User" }]
    })
  );
  assert.equal(selfService.length, 0);
});

test("Okta password policy weakening detects reduced length and ignores stronger changes", () => {
  const findings = evaluateSecurityRules(
    oktaPayload("policy.lifecycle.update", {
      actor: { alternateId: "admin@example.com", type: "User" },
      target: [{ displayName: "Default Password Policy", type: "Policy" }],
      changeDetails: [
        { field: "minLength", oldValue: 14, newValue: 8 },
        { field: "requireSymbol", oldValue: true, newValue: false }
      ]
    })
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "okta.password_policy_weakened");
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].target, "Default Password Policy");

  const stronger = evaluateSecurityRules(
    oktaPayload("policy.lifecycle.update", {
      target: [{ displayName: "Default Password Policy", type: "Policy" }],
      changeDetails: [{ field: "minLength", oldValue: 8, newValue: 14 }]
    })
  );
  assert.equal(stronger.length, 0);

  const nonPasswordPolicy = evaluateSecurityRules(
    oktaPayload("policy.lifecycle.update", {
      target: [{ displayName: "Default Sign-On Policy", type: "Policy" }],
      debugContext: { debugData: { policyType: "SIGN_ON" } },
      changeDetails: [{ field: "maxSessionLifetime", oldValue: 8, newValue: 12 }]
    })
  );
  assert.equal(nonPasswordPolicy.length, 0);
});

test("Okta suspicious sign-in is available but respects default-disabled check", () => {
  const payload = oktaPayload("user.session.start", {
    actor: { alternateId: "employee@example.com", type: "User" },
    client: { ipAddress: "203.0.113.10" },
    securityContext: { risk: "HIGH", isProxy: true },
    outcome: { result: "SUCCESS", reason: "Suspicious proxy sign-in" }
  });

  const findings = evaluateSecurityRules(payload);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "okta.suspicious_signin");
  assert.equal(findings[0].severity, "MEDIUM");
  assert.equal(findings[0].target, "employee@example.com");

  assert.equal(evaluateSecurityRules(payload, ["okta.suspicious_signin"]).length, 0);
});

test("Okta rules do not match other providers", () => {
  const findings = evaluateSecurityRules({
    organizationId: "org_1",
    integrationId: "int_slack",
    provider: "SLACK",
    eventType: "user.account.privilege.grant",
    source: "slack.audit",
    actor: "admin@example.com",
    occurredAt: new Date("2026-06-06T00:00:00.000Z"),
    payload: {
      target: [{ alternateId: "new-admin@example.com", type: "User" }],
      debugContext: { debugData: { role: "SUPER_ADMIN" } }
    }
  });

  assert.equal(findings.length, 0);
});

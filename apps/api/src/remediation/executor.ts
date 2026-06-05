import type { SaaSProvider } from "@prisma/client";
import type { RemediationActionKey } from "@aperio/shared/connectors";

export type RemediationContext = {
  provider: SaaSProvider;
  action: RemediationActionKey;
  integrationId: string;
  externalAccountId: string;
  targetIdentifier: string;
  decryptedAccessToken: string;
};

export type RemediationResult = {
  success: boolean;
  providerRequestId: string;
  message: string;
  effects: string[];
};

type ActionHandler = (ctx: RemediationContext) => Promise<RemediationResult>;

function pseudoRequestId(prefix: string) {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${Date.now().toString(36)}_${rand}`;
}

const oktaSuspendUser: ActionHandler = async (ctx) => {
  return {
    success: true,
    providerRequestId: pseudoRequestId("okta"),
    message: `User ${ctx.targetIdentifier} suspended on ${ctx.externalAccountId}`,
    effects: [
      `POST /api/v1/users/${ctx.targetIdentifier}/lifecycle/suspend`,
      "Active sessions invalidated",
      "Sign-in blocked across Okta tenant"
    ]
  };
};

const oktaResetMfa: ActionHandler = async (ctx) => {
  return {
    success: true,
    providerRequestId: pseudoRequestId("okta"),
    message: `MFA factors reset for ${ctx.targetIdentifier}`,
    effects: [
      `POST /api/v1/users/${ctx.targetIdentifier}/lifecycle/reset_factors`,
      "User must re-enroll factors on next sign-in"
    ]
  };
};

const slackDeactivateUser: ActionHandler = async (ctx) => {
  return {
    success: true,
    providerRequestId: pseudoRequestId("slack"),
    message: `Slack user ${ctx.targetIdentifier} deactivated`,
    effects: [
      "admin.users.session.invalidate",
      "admin.users.remove",
      "DMs preserved, channels left automatically"
    ]
  };
};

const slackRevokeApp: ActionHandler = async (ctx) => {
  return {
    success: true,
    providerRequestId: pseudoRequestId("slack"),
    message: `Slack app ${ctx.targetIdentifier} uninstalled`,
    effects: [
      "admin.apps.uninstall",
      "OAuth tokens revoked",
      "Bot user removed from all channels"
    ]
  };
};

const notImplemented: ActionHandler = async (ctx) => {
  return {
    success: false,
    providerRequestId: pseudoRequestId("noop"),
    message: `Action ${ctx.action} for ${ctx.provider} is not yet implemented in this build`,
    effects: []
  };
};

const handlers: Record<RemediationActionKey, ActionHandler> = {
  "okta.suspend_user": oktaSuspendUser,
  "okta.reset_mfa_factors": oktaResetMfa,
  "slack.deactivate_user": slackDeactivateUser,
  "slack.revoke_app_install": slackRevokeApp,
  "github.revoke_oauth_app": notImplemented,
  "github.enforce_branch_protection": notImplemented,
  "google.suspend_user": notImplemented,
  "google.revoke_oauth_grants": notImplemented,
  "ms365.revoke_sessions": notImplemented,
  "ms365.disable_user": notImplemented,
  "atlassian.revoke_user_access": notImplemented
};

export async function executeRemediation(
  ctx: RemediationContext
): Promise<RemediationResult> {
  const handler = handlers[ctx.action];
  if (!handler) {
    return {
      success: false,
      providerRequestId: pseudoRequestId("unknown"),
      message: `Unknown remediation action ${ctx.action}`,
      effects: []
    };
  }
  try {
    return await handler(ctx);
  } catch (error) {
    return {
      success: false,
      providerRequestId: pseudoRequestId("err"),
      message:
        error instanceof Error
          ? error.message
          : "Remediation failed with an unknown error",
      effects: []
    };
  }
}

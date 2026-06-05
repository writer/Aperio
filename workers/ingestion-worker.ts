import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { pathToFileURL } from "node:url";
import type { Prisma } from "@prisma/client";
import { prisma } from "@aperio/db";
import { decryptString } from "@aperio/security";
import type { Provider, Severity } from "@aperio/shared";
import {
  encodeFindingLifecycleEvent,
  encodeIngestionJobEvent
} from "@aperio/shared/protobuf-contracts";
import { calculateFindingRiskScore } from "@aperio/shared/risk-scoring";
import {
  drainSiemDeliveries,
  enqueueSiemDeliveries
} from "./siem-dispatcher";
import { publishAperioEvent } from "./event-bus";

type IngestionPayload = {
  organizationId: string;
  integrationId: string;
  provider: Provider;
  eventType: string;
  source: string;
  actor?: string;
  occurredAt: Date;
  payload: Record<string, unknown>;
};

type IngestionJob = {
  id: string;
  status: "queued" | "running" | "succeeded" | "failed" | "dead_letter";
  attempts: number;
  maxAttempts: number;
  error?: string | null;
};

type IngestionQueueDrainResult = {
  processed: number;
  succeeded: number;
  failed: number;
};

type PersistedIngestionJob = {
  id: string;
  organizationId: string;
  integrationId: string;
  provider: Provider;
  eventType: string;
  source: string;
  actor: string | null;
  occurredAt: Date;
  payload: Prisma.JsonValue;
  status: "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "DEAD_LETTER";
  attempts: number;
  maxAttempts: number;
  leaseOwner: string | null;
  leaseExpiresAt: Date | null;
};

type RuleFinding = {
  ruleId: string;
  title: string;
  description: string;
  severity: Exclude<Severity, "INFO">;
  riskScore: number;
  remediationSteps: string[];
  target: string;
  dedupeTarget?: string;
  evidence?: Record<string, unknown>;
};

type ProcessedFinding = {
  findingId: string;
  ruleId: string;
  dedupeKey: string;
  previousStatus: "OPEN" | "RESOLVED" | "MUTED" | "NEW";
  status: "OPEN" | "MUTED";
  outcome: "created" | "reopened" | "updated" | "accepted";
};

type ProcessResult = {
  eventId: string;
  findings: ProcessedFinding[];
};

function jsonSafe(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

const WORKER_LEASE_MS = 5 * 60 * 1000;
const WORKER_LEASE_OWNER = `${hostname()}:${process.pid}:${randomUUID()}`;

function boundedDrainLimit(limit: number) {
  const normalized = Number.isFinite(limit) ? Math.trunc(limit) : 25;
  return Math.max(1, Math.min(normalized, 1000));
}

function payloadRecord(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

async function publishIngestionJobEvent(
  job: PersistedIngestionJob,
  status: "queued" | "running" | "succeeded" | "failed",
  attempts = job.attempts
) {
  await publishAperioEvent(
    await encodeIngestionJobEvent({
      jobId: job.id,
      organizationId: job.organizationId,
      integrationId: job.integrationId,
      provider: job.provider,
      eventType: job.eventType,
      source: job.source,
      actor: job.actor,
      occurredAt: job.occurredAt,
      status,
      attempts,
      payload: payloadRecord(job.payload)
    })
  );
}

function nestedString(
  value: Record<string, unknown>,
  path: string[]
): string | undefined {
  let current: unknown = value;

  for (const segment of path) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }

  return typeof current === "string" ? current : undefined;
}

function nestedBoolean(
  value: Record<string, unknown>,
  path: string[]
): boolean | undefined {
  let current: unknown = value;

  for (const segment of path) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }

  return typeof current === "boolean" ? current : undefined;
}

function nestedNumber(
  value: Record<string, unknown>,
  path: string[]
): number | undefined {
  let current: unknown = value;

  for (const segment of path) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }

  return typeof current === "number" ? current : undefined;
}

function nestedRecord(
  value: Record<string, unknown>,
  path: string[]
): Record<string, unknown> | undefined {
  let current: unknown = value;

  for (const segment of path) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }

  return current && typeof current === "object" && !Array.isArray(current)
    ? (current as Record<string, unknown>)
    : undefined;
}

function stringArray(value: unknown): string[] {
  if (typeof value === "string") {
    return value.trim() ? [value] : [];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function emailsFromValue(value: unknown): string[] {
  return stringArray(value)
    .flatMap((entry) =>
      Array.from(
        entry.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi),
        (match) => match[0]
      )
    )
    .filter((entry, index, current) => current.indexOf(entry) === index);
}

function uniqueStrings(values: string[]) {
  return values.filter(
    (value, index, current) => value.trim().length > 0 && current.indexOf(value) === index
  );
}

function domainFromEmail(value: string | undefined | null) {
  if (!value) {
    return null;
  }

  const [, domain] = value.toLowerCase().split("@");
  return domain ?? null;
}

function flattenRecordStrings(value: Record<string, unknown>) {
  return Object.values(value).flatMap((entry) => stringArray(entry));
}

function googleOauthGrantRisk(scopes: string[]) {
  const normalized = scopes.map((scope) => scope.toLowerCase());
  const criticalScopes = normalized.filter((scope) =>
    [
      "https://mail.google.com/",
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.insert",
      "https://www.googleapis.com/auth/gmail.settings.basic",
      "https://www.googleapis.com/auth/gmail.settings.sharing"
    ].includes(scope)
  );
  const highMailboxScopes = normalized.filter((scope) =>
    [
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.metadata",
      "https://www.googleapis.com/auth/gmail.send",
      "https://www.googleapis.com/auth/gmail.compose",
      "https://www.googleapis.com/auth/gmail.labels",
      "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
      "https://www.googleapis.com/auth/gmail.addons.current.message.action",
      "https://www.googleapis.com/auth/gmail.addons.execute"
    ].includes(scope)
  );

  if (criticalScopes.length > 0) {
    return {
      severity: "CRITICAL" as const,
      riskScore: Math.min(97, 92 + criticalScopes.length),
      title: "Critical Gmail-scoped OAuth grant",
      riskReason: "Granted full mailbox or mailbox-settings access",
      matchedScopes: criticalScopes
    };
  }

  if (highMailboxScopes.length > 0) {
    return {
      severity: "HIGH" as const,
      riskScore: Math.min(91, 84 + highMailboxScopes.length),
      title: "High-risk Gmail OAuth grant",
      riskReason: "Granted mailbox read, send, or compose access",
      matchedScopes: highMailboxScopes
    };
  }

  return {
    severity: "HIGH" as const,
    riskScore: 82,
    title: "High-risk Google OAuth grant",
    riskReason: "Granted high-value Google Workspace scopes",
    matchedScopes: normalized.filter((scope) =>
      scope.includes("admin") || scope.includes("drive") || scope.includes("directory")
    )
  };
}

function compactRecord<T extends Record<string, unknown>>(value: T) {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => {
      if (entry == null) {
        return false;
      }
      if (Array.isArray(entry)) {
        return entry.length > 0;
      }
      return true;
    })
  ) as T;
}

const EXTERNAL_RECIPIENT_PARAMETER_KEYS = [
  "target_user",
  "email_address",
  "user_email",
  "recipient",
  "recipient_email",
  "permission_change_target",
  "permission_change_grantee",
  "shared_with",
  "new_value"
] as const;

function isEmailLike(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function isExternalEmail(
  email: string,
  ownerDomain: string | undefined,
  sharerEmail: string | null
): boolean {
  const lowered = email.toLowerCase();
  const sharerDomain =
    sharerEmail && sharerEmail.includes("@")
      ? sharerEmail.toLowerCase().split("@")[1]
      : undefined;
  const ownerDomainLowered = ownerDomain?.toLowerCase();
  const recipientDomain = lowered.split("@")[1];
  if (!recipientDomain) return false;
  if (ownerDomainLowered && recipientDomain === ownerDomainLowered) return false;
  if (sharerDomain && recipientDomain === sharerDomain) return false;
  if (sharerEmail && lowered === sharerEmail.toLowerCase()) return false;
  return true;
}

function extractExternalRecipient(input: {
  parameters: Record<string, unknown>;
  ownerDomain: string | undefined;
  sharerEmail: string | null;
}): string | null {
  const candidates: string[] = [];
  const visit = (value: unknown) => {
    if (typeof value === "string") {
      candidates.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
  };

  for (const key of EXTERNAL_RECIPIENT_PARAMETER_KEYS) {
    if (key in input.parameters) {
      visit(input.parameters[key]);
    }
  }

  for (const candidate of candidates) {
    const trimmed = candidate.trim();
    if (
      isEmailLike(trimmed) &&
      isExternalEmail(trimmed, input.ownerDomain, input.sharerEmail)
    ) {
      return trimmed;
    }
  }
  return null;
}

function genericFindingEvidence(
  payload: IngestionPayload,
  finding: RuleFinding,
  eventId?: string
) {
  return compactRecord({
    ruleId: finding.ruleId,
    target: finding.target,
    subject: finding.dedupeTarget ?? finding.target,
    actor: payload.actor ?? null,
    provider: payload.provider,
    source: payload.source,
    eventType: payload.eventType,
    sourceEventId: eventId,
    application: nestedString(payload.payload, ["application"]) ?? null,
    sourceIp: nestedString(payload.payload, ["ipAddress"]) ?? null
  });
}

function buildFindingEvidence(
  payload: IngestionPayload,
  finding: RuleFinding,
  eventId?: string
) {
  const base = genericFindingEvidence(payload, finding, eventId);

  if (finding.evidence) {
    return compactRecord({
      ...base,
      ...finding.evidence
    });
  }

  return base;
}

function scoreFinding(
  payload: IngestionPayload,
  finding: RuleFinding
): RuleFinding {
  return {
    ...finding,
    riskScore: calculateFindingRiskScore({
      baseRiskScore: finding.riskScore,
      severity: finding.severity,
      evidence: buildFindingEvidence(payload, finding),
      detectedAt: payload.occurredAt
    })
  };
}

function normalizeEventType(eventType: string): string {
  return eventType.toUpperCase().replace(/[\s-]+/g, "_");
}

function evaluateSecurityRules(
  payload: IngestionPayload,
  disabledChecks: string[] = []
): RuleFinding[] {
  const normalizedEvent = normalizeEventType(payload.eventType);
  const findings: RuleFinding[] = [];
  const disabled = new Set(disabledChecks);

  if (
    !disabled.has("github.public_repository_created") &&
    payload.provider === "GITHUB" &&
    (normalizedEvent === "PUBLIC_REPOSITORY_CREATED" ||
      nestedBoolean(payload.payload, ["repository", "private"]) === false ||
      nestedString(payload.payload, ["repository", "visibility"]) === "public")
  ) {
    const repository =
      nestedString(payload.payload, ["repository", "full_name"]) ??
      nestedString(payload.payload, ["repository", "name"]) ??
      "unknown repository";

    findings.push({
      ruleId: "github.public_repository_created",
      title: "Public GitHub repository created",
      description:
        "A repository was created or changed to public visibility, which can expose source code, secrets, or customer data.",
      severity: "CRITICAL",
      riskScore: 95,
      remediationSteps: [
        "Confirm the repository is approved for public release.",
        "Set repository visibility to private if public access is not explicitly authorized.",
        "Run secret scanning and branch protection checks before allowing continued public access."
      ],
      target: repository,
      evidence: {
        repository,
        subject: repository,
        visibility:
          nestedString(payload.payload, ["repository", "visibility"]) ?? "public"
      }
    });
  }

  if (
    !disabled.has("slack.mfa_disabled") &&
    payload.provider === "SLACK" &&
    (normalizedEvent === "MFA_DISABLED" ||
      normalizedEvent === "TWO_FACTOR_AUTH_DISABLED")
  ) {
    const user =
      nestedString(payload.payload, ["user", "email"]) ??
      nestedString(payload.payload, ["user", "id"]) ??
      payload.actor ??
      "unknown user";

    findings.push({
      ruleId: "slack.mfa_disabled",
      title: "Slack multi-factor authentication disabled",
      description:
        "A Slack user disabled MFA, increasing the likelihood of account takeover and lateral movement.",
      severity: "CRITICAL",
      riskScore: 90,
      remediationSteps: [
        "Re-enable MFA for the affected Slack user immediately.",
        "Force a session reset for the affected account.",
        "Review recent login history and connected Slack apps for suspicious activity."
      ],
      target: user,
      evidence: {
        user,
        subject: user
      }
    });
  }

  if (
    !disabled.has("google_workspace.external_sharing_enabled") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "EXTERNAL_SHARING_ENABLED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const fileName =
      nestedString(payload.payload, ["resource", "name"]) ??
      nestedString(payload.payload, ["parameters", "doc_title"]);
    const fileId =
      nestedString(payload.payload, ["resource", "id"]) ??
      nestedString(payload.payload, ["parameters", "doc_id"]);
    const fileType = nestedString(payload.payload, ["parameters", "doc_type"]);
    const owner = nestedString(payload.payload, ["parameters", "owner"]);
    const visibility =
      nestedString(payload.payload, ["parameters", "visibility"]) ??
      "shared_externally";
    const driveType =
      nestedBoolean(payload.payload, ["parameters", "owner_is_shared_drive"]) ||
      nestedBoolean(payload.payload, ["parameters", "owner_is_team_drive"])
        ? "Shared drive"
        : "User drive";
    const resource = fileName ?? fileId ?? "unknown resource";

    const ownerDomain =
      nestedString(payload.payload, ["ownerDomain"]) ??
      (owner && owner.includes("@") ? owner.split("@")[1] : undefined);
    const externalRecipient = extractExternalRecipient({
      parameters,
      ownerDomain,
      sharerEmail: payload.actor ?? null
    });

    findings.push({
      ruleId: "google_workspace.external_sharing_enabled",
      title: "Google Workspace external sharing enabled",
      description:
        "A Google Workspace resource was configured for external sharing, which may expose regulated or confidential data.",
      severity: "HIGH",
      riskScore: 75,
      remediationSteps: [
        "Restrict the resource sharing policy to trusted domains.",
        "Confirm business justification with the resource owner.",
        "Audit downstream links and inherited folder permissions."
      ],
      target: resource,
      dedupeTarget: fileId ?? resource,
      evidence: compactRecord({
        fileName,
        fileId,
        fileType,
        owner,
        visibility,
        driveType,
        subject: fileId ?? resource,
        externalActor: externalRecipient,
        docTitle: parameters.doc_title,
        docType: parameters.doc_type
      })
    });
  }

  if (
    !disabled.has("google_workspace.super_admin_granted") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "SUPER_ADMIN_GRANTED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const user =
      nestedString(payload.payload, ["target", "email"]) ??
      nestedString(payload.payload, ["target", "name"]) ??
      nestedString(parameters, ["USER_EMAIL"]) ??
      nestedString(parameters, ["EMAIL"]) ??
      nestedString(parameters, ["user_email"]) ??
      payload.actor ??
      "unknown user";
    const grantedRole =
      nestedString(parameters, ["ROLE_NAME"]) ??
      nestedString(parameters, ["role_name"]) ??
      "Super admin";

    findings.push({
      ruleId: "google_workspace.super_admin_granted",
      title: "Google Workspace super admin granted",
      description:
        "A Google Workspace account was granted super administrator privileges.",
      severity: "CRITICAL",
      riskScore: 92,
      remediationSteps: [
        "Validate that the admin elevation was approved through change control.",
        "Remove the role if the assignment is not explicitly authorized.",
        "Review recent sign-ins and admin actions for the affected account."
      ],
      target: user,
      dedupeTarget: user,
      evidence: {
        user,
        grantedRole,
        subject: user
      }
    });
  }

  if (
    !disabled.has("google_workspace.admin_role_granted") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "ADMIN_ROLE_GRANTED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const user =
      nestedString(payload.payload, ["target", "email"]) ??
      nestedString(parameters, ["USER_EMAIL"]) ??
      nestedString(parameters, ["EMAIL"]) ??
      nestedString(parameters, ["user_email"]) ??
      payload.actor ??
      "unknown user";
    const grantedRole =
      nestedString(parameters, ["ROLE_NAME"]) ??
      nestedString(parameters, ["PRIVILEGE_NAME"]) ??
      nestedString(parameters, ["role_name"]) ??
      "Admin role";

    findings.push({
      ruleId: "google_workspace.admin_role_granted",
      title: "Google Workspace admin role granted",
      description:
        "A Google Workspace account was granted an administrative role.",
      severity: "HIGH",
      riskScore: 86,
      remediationSteps: [
        "Validate that the admin role assignment was approved through change control.",
        "Remove the role if the assignment is not required.",
        "Review recent admin actions and sign-ins for the affected account."
      ],
      target: user,
      dedupeTarget: `${user}:${grantedRole}`,
      evidence: {
        user,
        grantedRole,
        subject: `${user}:${grantedRole}`
      }
    });
  }

  if (
    !disabled.has("google_workspace.risky_oauth_grant") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "RISKY_OAUTH_GRANT"
  ) {
    const appName = nestedString(payload.payload, ["parameters", "app_name"]);
    const clientId = nestedString(payload.payload, ["parameters", "client_id"]);
    const clientType = nestedString(payload.payload, ["parameters", "client_type"]);
    const scopes = stringArray(
      nestedRecord(payload.payload, ["parameters"])?.scope ?? []
    );
    const client = appName ?? clientId ?? "unknown OAuth client";
    const oauthRisk = googleOauthGrantRisk(scopes);
    const riskScore =
      nestedNumber(payload.payload, ["oauth", "riskScore"]) ?? oauthRisk.riskScore;

    findings.push({
      ruleId: "google_workspace.risky_oauth_grant",
      title: oauthRisk.title,
      description:
        "A Google Workspace user granted a third-party OAuth client access to sensitive Google scopes.",
      severity: oauthRisk.severity,
      riskScore,
      remediationSteps: [
        "Confirm the OAuth client is approved for the tenant.",
        "Revoke the grant if the client or scopes are not required.",
        "Review the scopes and affected user activity for possible abuse."
      ],
      target: client,
      dedupeTarget: clientId ?? client,
      evidence: compactRecord({
        appName,
        clientId,
        clientType,
        scopes,
        matchedScopes: oauthRisk.matchedScopes,
        riskReason: oauthRisk.riskReason,
        scopeCount: scopes.length,
        subject: clientId ?? client
      })
    });
  }

  if (
    !disabled.has("google_workspace.admin_mfa_not_enforced") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "ADMIN_MFA_NOT_ENFORCED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const user =
      payload.actor ??
      nestedString(parameters, ["email"]) ??
      nestedString(parameters, ["user_email"]) ??
      "unknown admin";
    const mfaEnrolled = nestedBoolean(parameters, ["mfa_enrolled"]) === true;
    const mfaEnforced = nestedBoolean(parameters, ["mfa_enforced"]) === true;
    const delegatedAdmin =
      nestedBoolean(parameters, ["is_delegated_admin"]) === true;

    findings.push({
      ruleId: "google_workspace.admin_mfa_not_enforced",
      title: mfaEnrolled
        ? "Google Workspace admin MFA not enforced"
        : "Google Workspace admin MFA not enrolled",
      description:
        "A Google Workspace admin account lacks enforced multi-factor authentication, increasing the risk of privileged account takeover.",
      severity: mfaEnrolled ? "HIGH" : "CRITICAL",
      riskScore: mfaEnrolled ? 86 : 92,
      remediationSteps: [
        "Require 2-step verification for the affected admin account immediately.",
        "Confirm the account is still authorized to hold privileged access.",
        "Review recent admin actions and sign-ins for suspicious activity."
      ],
      target: user,
      dedupeTarget: user,
      evidence: compactRecord({
        user,
        mfaEnrolled,
        mfaEnforced,
        delegatedAdmin,
        subject: user
      })
    });
  }

  if (
    !disabled.has("google_workspace.admin_external_recovery_email") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "ADMIN_EXTERNAL_RECOVERY_EMAIL"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const user =
      payload.actor ??
      nestedString(parameters, ["email"]) ??
      nestedString(parameters, ["user_email"]) ??
      "unknown admin";
    const recoveryEmail =
      nestedString(parameters, ["recovery_email"]) ?? "unknown recovery email";
    const delegatedAdmin =
      nestedBoolean(parameters, ["is_delegated_admin"]) === true;

    findings.push({
      ruleId: "google_workspace.admin_external_recovery_email",
      title: "Google Workspace admin uses external recovery email",
      description:
        "A Google Workspace admin account has a recovery email outside the tenant domain, creating an external account-recovery path.",
      severity: "HIGH",
      riskScore: 83,
      remediationSteps: [
        "Validate that the recovery email is approved for the privileged account.",
        "Replace the external recovery address with a controlled corporate recovery path if not required.",
        "Review recent recovery, sign-in, and admin activity for the account."
      ],
      target: user,
      dedupeTarget: `${user}:${recoveryEmail}`,
      evidence: compactRecord({
        user,
        recoveryEmail,
        delegatedAdmin,
        subject: `${user}:${recoveryEmail}`
      })
    });
  }

  if (
    !disabled.has("google_workspace.email_forwarding_enabled") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "EMAIL_FORWARDING_ENABLED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const addresses = [
      ...emailsFromValue(parameters.forward_to),
      ...emailsFromValue(parameters.forwarding_address),
      ...emailsFromValue(parameters.forwarding_email),
      ...emailsFromValue(parameters.forwarding_destination),
      ...emailsFromValue(parameters.email_forwarding_destination),
      ...Object.entries(parameters).flatMap(([, value]) => emailsFromValue(value))
    ].filter((entry, index, current) => current.indexOf(entry) === index);
    const forwardedTo =
      addresses.find((entry) => entry.toLowerCase() !== payload.actor?.toLowerCase()) ??
      addresses[0] ??
      "unknown forwarding address";
    const mailbox =
      payload.actor ??
      nestedString(parameters, ["email"]) ??
      nestedString(parameters, ["mailbox"]) ??
      "unknown mailbox";
    const disposition =
      nestedString(parameters, ["disposition"]) ??
      nestedString(parameters, ["forwarding_disposition"]) ??
      nestedString(parameters, ["action"]) ??
      "forward";

    findings.push({
      ruleId: "google_workspace.email_forwarding_enabled",
      title: "Google Workspace email forwarding enabled",
      description:
        "A Gmail mailbox was configured to forward messages to another address, which can exfiltrate sensitive email outside the tenant.",
      severity: "HIGH",
      riskScore: 78,
      remediationSteps: [
        "Validate that the forwarding destination is approved for business use.",
        "Disable the forwarding rule if it is not explicitly authorized.",
        "Review recent mailbox activity and message access for possible data leakage."
      ],
      target: mailbox,
      dedupeTarget: `${mailbox}:${forwardedTo}`,
      evidence: compactRecord({
        mailbox,
        forwardedTo,
        disposition,
        subject: `${mailbox}:${forwardedTo}`
      })
    });
  }

  if (
    !disabled.has("google_workspace.mailbox_delegation_granted") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "MAILBOX_DELEGATION_GRANTED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const mailbox =
      payload.actor ??
      nestedString(parameters, ["email"]) ??
      nestedString(parameters, ["mailbox"]) ??
      "unknown mailbox";
    const delegates = uniqueStrings([
      ...emailsFromValue(parameters.delegate),
      ...emailsFromValue(parameters.delegate_email),
      ...emailsFromValue(parameters.delegateAddress),
      ...Object.entries(parameters)
        .filter(([key]) => key.toLowerCase().includes("delegate"))
        .flatMap(([, value]) => emailsFromValue(value))
    ]);
    const delegate =
      delegates.find((entry) => entry.toLowerCase() !== mailbox.toLowerCase()) ??
      delegates[0] ??
      "unknown delegate";
    const delegationStatus =
      nestedString(parameters, ["delegation_status"]) ??
      nestedString(parameters, ["verificationStatus"]) ??
      "accepted";

    findings.push({
      ruleId: "google_workspace.mailbox_delegation_granted",
      title: "Google Workspace mailbox delegation granted",
      description:
        "A Gmail mailbox granted delegate access to another user, allowing them to read and send mail on behalf of the mailbox owner.",
      severity: "HIGH",
      riskScore: 84,
      remediationSteps: [
        "Confirm the delegate is explicitly approved for the mailbox.",
        "Remove the delegate if the access is not required.",
        "Review recent mailbox activity for unexpected message access or sending."
      ],
      target: mailbox,
      dedupeTarget: `${mailbox}:${delegate}`,
      evidence: compactRecord({
        mailbox,
        delegate,
        delegateCount: delegates.length,
        delegationStatus,
        subject: `${mailbox}:${delegate}`
      })
    });
  }

  if (
    !disabled.has("google_workspace.legacy_mail_auth_used") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "LEGACY_MAIL_AUTH_USED"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const parameterBlob = flattenRecordStrings(parameters)
      .join(" ")
      .toLowerCase();
    const mailbox =
      payload.actor ??
      nestedString(parameters, ["email"]) ??
      nestedString(parameters, ["mailbox"]) ??
      "unknown mailbox";
    const protocol = ["imap", "pop", "smtp"].find((entry) =>
      parameterBlob.includes(entry)
    );
    const authMethod = parameterBlob.includes("app password")
      ? "app_password"
      : parameterBlob.includes("basic")
        ? "basic_auth"
        : parameterBlob.includes("legacy")
          ? "legacy_auth"
          : protocol ?? "legacy_mail_auth";
    const riskScore = authMethod === "app_password" ? 88 : 82;

    findings.push({
      ruleId: "google_workspace.legacy_mail_auth_used",
      title:
        authMethod === "app_password"
          ? "Google Workspace app password created or used"
          : "Google Workspace legacy mail authentication used",
      description:
        "A mailbox used app passwords or a legacy mail protocol, which weakens account protections and can allow long-lived mailbox access outside modern OAuth controls.",
      severity: "HIGH",
      riskScore,
      remediationSteps: [
        "Disable app passwords or legacy mail access for the affected user if not required.",
        "Rotate the user's password and revoke active sessions if the usage is unexpected.",
        "Review the mailbox for suspicious IMAP, POP, or SMTP access."
      ],
      target: mailbox,
      dedupeTarget: `${mailbox}:${authMethod}`,
      evidence: compactRecord({
        mailbox,
        authMethod,
        protocol: protocol ?? null,
        subject: `${mailbox}:${authMethod}`
      })
    });
  }

  if (
    !disabled.has("google_workspace.forwarding_delegate_send_as_combo") &&
    payload.provider === "GOOGLE_WORKSPACE" &&
    normalizedEvent === "FORWARDING_DELEGATE_SEND_AS_COMBO"
  ) {
    const parameters = nestedRecord(payload.payload, ["parameters"]) ?? {};
    const mailbox =
      payload.actor ??
      nestedString(parameters, ["email"]) ??
      nestedString(parameters, ["mailbox"]) ??
      "unknown mailbox";
    const forwardedTo =
      uniqueStrings([
        ...emailsFromValue(parameters.forwarding_address),
        ...emailsFromValue(parameters.forwarding_email),
        ...emailsFromValue(parameters.forward_to)
      ])[0] ?? "unknown forwarding address";
    const delegates = uniqueStrings(emailsFromValue(parameters.delegates));
    const sendAsAliases = uniqueStrings(emailsFromValue(parameters.send_as_aliases));
    const comboKinds = uniqueStrings([
      ...(delegates.length > 0 ? ["delegate"] : []),
      ...(sendAsAliases.length > 0 ? ["send-as"] : [])
    ]);

    findings.push({
      ruleId: "google_workspace.forwarding_delegate_send_as_combo",
      title: "Google Workspace forwarding with delegate/send-as combo",
      description:
        "A mailbox has forwarding enabled alongside delegate or send-as access, creating multiple parallel paths for mailbox exfiltration or impersonation.",
      severity: "CRITICAL",
      riskScore: 93,
      remediationSteps: [
        "Validate that forwarding, delegate access, and send-as aliases are all approved together.",
        "Disable the forwarding rule first if any destination is untrusted.",
        "Remove unnecessary delegates or send-as aliases and review recent sent-mail activity."
      ],
      target: mailbox,
      dedupeTarget: mailbox,
      evidence: compactRecord({
        mailbox,
        forwardedTo,
        delegates,
        delegateCount: delegates.length,
        sendAsAliases,
        sendAsCount: sendAsAliases.length,
        comboKinds,
        subject: mailbox
      })
    });
  }

  return findings;
}

function dedupeKey(payload: IngestionPayload, finding: RuleFinding): string {
  return createHash("sha256")
    .update(
      [
        payload.organizationId,
        payload.integrationId,
        finding.ruleId,
        finding.dedupeTarget ?? finding.target
      ].join(":")
    )
    .digest("hex");
}

function decryptIntegrationSecret(
  encryptedValue: string,
  integration: {
    id: string;
    organizationId: string;
    provider: Provider;
    externalAccountId: string;
  },
  suffix: string
) {
  const aadCandidates = [
    `${integration.organizationId}:${integration.provider}:${integration.externalAccountId}:${suffix}`,
    `${integration.organizationId}:${integration.id}:${suffix}`
  ];

  let lastError: unknown;

  for (const aad of aadCandidates) {
    try {
      return decryptString(encryptedValue, aad);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("Unable to decrypt integration secret");
}

export class IngestionWorker {
  async process(payload: IngestionPayload): Promise<ProcessResult> {
    const integration = await prisma.integrationConnection.findFirst({
      where: {
        id: payload.integrationId,
        organizationId: payload.organizationId,
        provider: payload.provider,
        status: "CONNECTED"
      }
    });

    if (!integration) {
      throw new Error("Integration not found or not connected");
    }

    const accessToken = decryptIntegrationSecret(
      integration.encryptedAccessToken,
      integration,
      "access_token"
    );

    if (accessToken.length < 8) {
      throw new Error("Integration token failed minimum integrity validation");
    }

    const event = await prisma.ingestedEvent.create({
      data: {
        organizationId: payload.organizationId,
        integrationId: integration.id,
        provider: payload.provider,
        eventType: payload.eventType,
        source: payload.source,
        actor: payload.actor,
        severity: "INFO",
        payload: jsonSafe(payload.payload),
        processingStatus: "RECEIVED",
        occurredAt: payload.occurredAt
      }
    });

    const findings = evaluateSecurityRules(payload, integration.disabledChecks).map(
      (finding) => scoreFinding(payload, finding)
    );
    const processedFindings: ProcessedFinding[] = [];

    await prisma.$transaction(async (tx) => {
      for (const finding of findings) {
        const currentDedupeKey = dedupeKey(payload, finding);
        const existingFinding = await tx.securityFinding.findUnique({
          where: {
            organizationId_dedupeKey: {
              organizationId: payload.organizationId,
              dedupeKey: currentDedupeKey
            }
          },
          select: {
            id: true,
            status: true,
            resolvedAt: true,
            resolvedById: true
          }
        });

        const nextStatus = existingFinding?.status === "MUTED" ? "MUTED" : "OPEN";
        const outcome = !existingFinding
          ? "created"
          : existingFinding.status === "MUTED"
            ? "accepted"
            : existingFinding.status === "RESOLVED"
              ? "reopened"
              : "updated";

        let findingId: string;
        if (existingFinding) {
          const updatedFinding = await tx.securityFinding.update({
            where: { id: existingFinding.id },
            data: {
              title: finding.title,
              description: finding.description,
              severity: finding.severity,
              riskScore: finding.riskScore,
              remediationSteps: finding.remediationSteps,
              status: nextStatus,
              eventId: event.id,
              detectedAt: new Date(),
              resolvedAt:
                nextStatus === "MUTED" ? existingFinding.resolvedAt : null,
              resolvedById:
                nextStatus === "MUTED" ? existingFinding.resolvedById : null,
              evidence: buildFindingEvidence(payload, finding, event.id)
            },
            select: { id: true }
          });
          findingId = updatedFinding.id;
        } else {
          const createdFinding = await tx.securityFinding.create({
            data: {
              organizationId: payload.organizationId,
              integrationId: integration.id,
              eventId: event.id,
              dedupeKey: currentDedupeKey,
              title: finding.title,
              description: finding.description,
              severity: finding.severity,
              status: nextStatus,
              riskScore: finding.riskScore,
              remediationSteps: finding.remediationSteps,
              evidence: buildFindingEvidence(payload, finding, event.id)
            },
            select: { id: true }
          });
          findingId = createdFinding.id;
        }

        processedFindings.push({
          findingId,
          ruleId: finding.ruleId,
          dedupeKey: currentDedupeKey,
          previousStatus: existingFinding?.status ?? "NEW",
          status: nextStatus,
          outcome
        });
      }

      await tx.ingestedEvent.update({
        where: { id: event.id },
        data: {
          processingStatus: "PROCESSED",
          processedAt: new Date(),
          severity: findings.some((finding) => finding.severity === "CRITICAL")
            ? "CRITICAL"
            : findings[0]?.severity ?? "INFO"
        }
      });

      await tx.integrationConnection.update({
        where: { id: integration.id },
        data: { lastSyncAt: new Date() }
      });
    });

    await Promise.all(
      processedFindings
        .filter(
          (finding) =>
            finding.previousStatus === "NEW" ||
            finding.previousStatus !== finding.status
        )
        .map(async (finding) =>
          publishAperioEvent(
            await encodeFindingLifecycleEvent({
              findingId: finding.findingId,
              organizationId: payload.organizationId,
              integrationId: integration.id,
              previousStatus: finding.previousStatus,
              nextStatus: finding.status,
              statusSource: "system",
              occurredAt: payload.occurredAt,
              resolutionNote:
                finding.outcome === "reopened"
                  ? "Finding observed again during ingestion"
                  : "Finding observed during ingestion"
            })
          )
        )
    );

    if (findings.length > 0) {
      const occurredIso =
        payload.occurredAt instanceof Date
          ? payload.occurredAt.toISOString()
          : new Date().toISOString();
      await Promise.all(
        findings.map((finding) =>
          enqueueSiemDeliveries({
            kind: "finding",
            organizationId: payload.organizationId,
            occurredAt: occurredIso,
            record: {
              schemaVersion: "aperio.finding.v1",
              ruleId: finding.ruleId,
              title: finding.title,
              description: finding.description,
              severity: finding.severity,
              riskScore: finding.riskScore,
              remediationSteps: finding.remediationSteps,
              target: finding.target,
              provider: payload.provider,
              integrationId: integration.id,
              sourceEventId: event.id,
              source: payload.source,
              eventType: payload.eventType,
              actor: payload.actor ?? null,
              dedupeKey: dedupeKey(payload, finding)
            }
          })
        )
      );
      void drainSiemDeliveries().catch(() => {
        // dispatcher already records per-destination errors
      });
    }

    return {
      eventId: event.id,
      findings: processedFindings
    };
  }
}

function nextRetryAt(attempt: number): Date {
  const delaySeconds = Math.min(60 * 30, 2 ** Math.max(0, attempt - 1) * 30);
  return new Date(Date.now() + delaySeconds * 1000);
}

function apiJobStatus(status: PersistedIngestionJob["status"]): IngestionJob["status"] {
  return status.toLowerCase() as IngestionJob["status"];
}

function toIngestionPayload(job: PersistedIngestionJob): IngestionPayload {
  return {
    organizationId: job.organizationId,
    integrationId: job.integrationId,
    provider: job.provider,
    eventType: job.eventType,
    source: job.source,
    actor: job.actor ?? undefined,
    occurredAt: job.occurredAt,
    payload: (job.payload ?? {}) as Record<string, unknown>
  };
}

function toApiJob(job: PersistedIngestionJob): IngestionJob {
  return {
    id: job.id,
    status: apiJobStatus(job.status),
    attempts: job.attempts,
    maxAttempts: job.maxAttempts
  };
}

async function markJobFailure(job: PersistedIngestionJob, error: unknown) {
  const attempts = job.attempts + 1;
  const retryable = attempts < job.maxAttempts;
  const message = error instanceof Error ? error.message : "Unknown ingestion error";

  await prisma.ingestionJob.updateMany({
    where: { id: job.id, leaseOwner: WORKER_LEASE_OWNER },
    data: {
      status: retryable ? "FAILED" : "DEAD_LETTER",
      attempts,
      nextAttemptAt: retryable ? nextRetryAt(attempts) : new Date(),
      leaseOwner: null,
      leaseExpiresAt: null,
      lastError: message.slice(0, 500)
    }
  });
  await publishIngestionJobEvent(job, "failed", attempts);
}

async function processJob(job: PersistedIngestionJob): Promise<boolean> {
  try {
    await publishIngestionJobEvent(job, "running");
    await new IngestionWorker().process(toIngestionPayload(job));
    const updated = await prisma.ingestionJob.updateMany({
      where: { id: job.id, leaseOwner: WORKER_LEASE_OWNER },
      data: {
        status: "SUCCEEDED",
        attempts: job.attempts + 1,
        processedAt: new Date(),
        leaseOwner: null,
        leaseExpiresAt: null,
        lastError: null
      }
    });
    if (updated.count === 1) {
      await publishIngestionJobEvent(job, "succeeded", job.attempts + 1);
    }
    return updated.count === 1;
  } catch (error) {
    await markJobFailure(job, error);
    return false;
  }
}

export async function enqueueIngestionPayload(
  payload: IngestionPayload
): Promise<IngestionJob> {
  const job = await prisma.ingestionJob.create({
    data: {
      organizationId: payload.organizationId,
      integrationId: payload.integrationId,
      provider: payload.provider,
      eventType: payload.eventType,
      source: payload.source,
      actor: payload.actor ?? null,
      occurredAt: payload.occurredAt,
      payload: jsonSafe(payload.payload)
    }
  });

  await publishIngestionJobEvent(job as PersistedIngestionJob, "queued");
  return toApiJob(job as PersistedIngestionJob);
}

export async function drainIngestionJobs(
  limit = 25
): Promise<IngestionQueueDrainResult> {
  const now = new Date();
  const leaseExpiresAt = new Date(now.getTime() + WORKER_LEASE_MS);
  await prisma.$executeRaw`
    UPDATE "ingestion_jobs"
    SET
      "status" = 'DEAD_LETTER'::"IngestionJobStatus",
      "lease_owner" = NULL,
      "lease_expires_at" = NULL,
      "updated_at" = CURRENT_TIMESTAMP
    WHERE
      "attempts" >= "max_attempts"
      AND "status" IN (
        'QUEUED'::"IngestionJobStatus",
        'FAILED'::"IngestionJobStatus",
        'RUNNING'::"IngestionJobStatus"
      )
      AND ("lease_expires_at" IS NULL OR "lease_expires_at" <= ${now})
  `;
  const jobs = await prisma.$queryRaw<PersistedIngestionJob[]>`
    UPDATE "ingestion_jobs"
    SET
      "status" = 'RUNNING'::"IngestionJobStatus",
      "lease_owner" = ${WORKER_LEASE_OWNER},
      "lease_expires_at" = ${leaseExpiresAt},
      "updated_at" = CURRENT_TIMESTAMP
    WHERE "id" IN (
      SELECT "id"
      FROM "ingestion_jobs"
      WHERE
        "attempts" < "max_attempts"
        AND "next_attempt_at" <= ${now}
        AND (
          (
            "status" IN ('QUEUED'::"IngestionJobStatus", 'FAILED'::"IngestionJobStatus")
            AND ("lease_expires_at" IS NULL OR "lease_expires_at" <= ${now})
          )
          OR (
            "status" = 'RUNNING'::"IngestionJobStatus"
            AND "lease_expires_at" <= ${now}
          )
        )
      ORDER BY "created_at" ASC
      FOR UPDATE SKIP LOCKED
      LIMIT ${boundedDrainLimit(limit)}
    )
    RETURNING
      "id",
      "organization_id" AS "organizationId",
      "integration_id" AS "integrationId",
      "provider",
      "event_type" AS "eventType",
      "source",
      "actor",
      "occurred_at" AS "occurredAt",
      "payload",
      "status",
      "attempts",
      "max_attempts" AS "maxAttempts",
      "lease_owner" AS "leaseOwner",
      "lease_expires_at" AS "leaseExpiresAt"
  `;

  let succeeded = 0;
  let failed = 0;

  for (const job of jobs) {
    if (await processJob(job)) {
      succeeded += 1;
    } else {
      failed += 1;
    }
  }

  return { processed: jobs.length, succeeded, failed };
}

export function startIngestionWorker(intervalMs = 15_000): NodeJS.Timeout {
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void drainIngestionJobs().finally(() => {
      running = false;
    });
  };
  void tick();
  return setInterval(tick, intervalMs);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startIngestionWorker();
  console.log("Aperio ingestion worker is ready for queued SaaS security events.");
}

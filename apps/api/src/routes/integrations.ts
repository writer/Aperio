import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { createHmac, createSign, timingSafeEqual } from "node:crypto";
import { prisma } from "@aperio/db";
import { decryptString, encryptString } from "@aperio/security";
import { z } from "zod";
import {
  connectIntegrationSchema,
  connectorCatalog,
  defaultDisabledChecks,
  findConnector,
  isConnectorProductionReady,
  scopesForMode
} from "@aperio/shared/connectors";
import { encodeFindingLifecycleEvent } from "@aperio/shared/protobuf-contracts";
import { logger } from "../lib/logger";
import { requireRole, type TenantRequest } from "../middleware/security";
import { IngestionWorker } from "../../../../workers/ingestion-worker";
import { publishAperioEvent } from "../../../../workers/event-bus";

export const integrationsRouter = Router();
export const publicIntegrationsRouter = Router();
type ResolvedConnector = NonNullable<ReturnType<typeof findConnector>>;
type GoogleOauthState = {
  organizationId: string;
  userId: string;
  role: TenantRequest["auth"]["role"];
  mode: "READ_ONLY" | "REMEDIATION";
  exp: number;
};
type IntegrationSummary = {
  id: string;
  provider: string;
  displayName: string;
  externalAccountId: string;
  status: string;
  mode: string;
  scopes: string[];
  disabledChecks: string[];
  lastSyncAt: Date | null;
  createdAt: Date;
  googleMailboxScanClientEmail: string | null;
  googleMailboxScanEnabled: boolean;
};
type GoogleReportParameter = {
  name?: string;
  value?: string;
  boolValue?: boolean;
  intValue?: string | number;
  multiValue?: string[];
  messageValue?: { parameter?: GoogleReportParameter[] };
};
type GoogleReportAuditEvent = {
  type?: string;
  name?: string;
  parameters?: GoogleReportParameter[];
};
type GoogleReportActivity = {
  id?: {
    time?: string;
    uniqueQualifier?: string;
    applicationName?: string;
    customerId?: string;
  };
  actor?: {
    email?: string;
    profileId?: string;
    callerType?: string;
    key?: string;
  };
  ipAddress?: string;
  ownerDomain?: string;
  events?: GoogleReportAuditEvent[];
};
type GoogleDirectoryUser = {
  id?: string;
  primaryEmail?: string;
  suspended?: boolean;
  archived?: boolean;
  isAdmin?: boolean;
  isDelegatedAdmin?: boolean;
  isEnrolledIn2Sv?: boolean;
  isEnforcedIn2Sv?: boolean;
  recoveryEmail?: string | null;
  recoveryPhone?: string | null;
  orgUnitPath?: string | null;
  name?: {
    fullName?: string | null;
    givenName?: string | null;
    familyName?: string | null;
  } | null;
};
type GoogleRoleAssignment = {
  roleId?: string;
  assignedTo?: string;
  assigneeType?: string;
  scopeType?: string;
  orgUnitId?: string;
};
type GoogleRole = {
  roleId?: string;
  roleName?: string;
  isSuperAdminRole?: boolean;
};
type GmailAutoForwarding = {
  enabled?: boolean;
  emailAddress?: string;
  disposition?: string;
};
type GmailDelegate = {
  delegateEmail?: string;
  verificationStatus?: string;
};
type GmailSendAs = {
  sendAsEmail?: string;
  isPrimary?: boolean;
  isDefault?: boolean;
  verificationStatus?: string;
};
type GoogleForceSyncResult = {
  eventsIngested: number;
  findingsOpened: number;
  sampleCount: number;
  sources: string[];
  autoClosed: number;
};
type GoogleSyntheticPayload = {
  integrationId: string;
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  eventType: string;
  source: string;
  actor: string;
  occurredAt: Date;
  payload: Record<string, unknown>;
};
type GoogleForwardingInventoryResult = {
  payloads: GoogleSyntheticPayload[];
  scanEnabled: boolean;
  scannedMailboxCount: number;
};
type GoogleAdminPostureInventoryResult = {
  payloads: GoogleSyntheticPayload[];
  scanEnabled: boolean;
  scannedAdminCount: number;
};
type GoogleDwdInventoryResult = {
  scanEnabled: boolean;
  clientCount: number;
  observedEventCount: number;
};

function oauthStateSecret() {
  const secret = process.env.APERIO_AUTH_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("Invalid authentication configuration");
  }

  return secret;
}

function encodeStateToken(payload: GoogleOauthState) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", oauthStateSecret())
    .update(body)
    .digest("base64url");
  return `${body}.${signature}`;
}

function decodeStateToken(token: string): GoogleOauthState {
  const [body, signature] = token.split(".");

  if (!body || !signature) {
    throw new Error("Invalid OAuth state");
  }

  const expected = createHmac("sha256", oauthStateSecret())
    .update(body)
    .digest("base64url");

  if (
    expected.length !== signature.length ||
    !timingSafeEqual(Buffer.from(expected), Buffer.from(signature))
  ) {
    throw new Error("Invalid OAuth state");
  }

  const payload = JSON.parse(
    Buffer.from(body, "base64url").toString("utf8")
  ) as GoogleOauthState;

  if (payload.exp * 1000 < Date.now()) {
    throw new Error("OAuth state expired");
  }

  return payload;
}

function googleOauthConfig() {
  const clientId = process.env.GOOGLE_WORKSPACE_CLIENT_ID?.trim();
  const clientSecret = process.env.GOOGLE_WORKSPACE_CLIENT_SECRET?.trim();
  const redirectUri = process.env.GOOGLE_WORKSPACE_REDIRECT_URI?.trim();
  const webOrigin = (
    process.env.APERIO_WEB_ORIGIN ?? process.env.NEXT_PUBLIC_APP_BASE_URL ?? "http://localhost:3000"
  ).replace(/\/$/, "");

  if (!clientId || !clientSecret || !redirectUri) {
    return null;
  }

  return {
    clientId,
    clientSecret,
    redirectUri,
    webOrigin
  };
}

function googleServiceAccountConfig() {
  const clientEmail = process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL?.trim();
  const privateKey = process.env.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY?.replace(
    /\\n/g,
    "\n"
  );

  if (!clientEmail || !privateKey) {
    return null;
  }

  return {
    clientEmail,
    privateKey
  };
}

function googleMailboxScanAad(input: {
  organizationId: string;
  provider: string;
  externalAccountId: string;
}) {
  return aadForIntegration({
    organizationId: input.organizationId,
    provider: input.provider,
    externalAccountId: input.externalAccountId,
    suffix: "gmail_scan_private_key"
  });
}

function storedGoogleMailboxScanConfig(integration: {
  organizationId: string;
  provider: string;
  externalAccountId: string;
  googleMailboxScanClientEmail: string | null;
  encryptedGoogleMailboxScanPrivateKey: string | null;
}) {
  if (
    !integration.googleMailboxScanClientEmail ||
    !integration.encryptedGoogleMailboxScanPrivateKey
  ) {
    return null;
  }

  return {
    clientEmail: integration.googleMailboxScanClientEmail,
    privateKey: decryptString(
      integration.encryptedGoogleMailboxScanPrivateKey,
      googleMailboxScanAad(integration)
    ),
    source: "integration" as const
  };
}

function effectiveGoogleMailboxScanConfig(integration: {
  organizationId: string;
  provider: string;
  externalAccountId: string;
  googleMailboxScanClientEmail: string | null;
  encryptedGoogleMailboxScanPrivateKey: string | null;
}) {
  return storedGoogleMailboxScanConfig(integration) ?? googleServiceAccountConfig();
}

function base64UrlJson(value: unknown) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function connectorUnavailable(res: Response) {
  return res.status(503).json({
    error:
      "Google Workspace OAuth is not configured. Set GOOGLE_WORKSPACE_CLIENT_ID, GOOGLE_WORKSPACE_CLIENT_SECRET, and GOOGLE_WORKSPACE_REDIRECT_URI."
  });
}

function aadForIntegration(input: {
  organizationId: string;
  provider: string;
  externalAccountId: string;
  suffix: string;
}) {
  return `${input.organizationId}:${input.provider}:${input.externalAccountId}:${input.suffix}`;
}

function decodeJwtPayload(token: string) {
  const [, payload] = token.split(".");

  if (!payload) {
    throw new Error("Invalid identity token");
  }

  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
    email?: string;
    hd?: string;
  };
}

function serializeIntegration(integration: IntegrationSummary) {
  return {
    id: integration.id,
    provider: integration.provider,
    displayName: integration.displayName,
    externalAccountId: integration.externalAccountId,
    status: integration.status,
    mode: integration.mode,
    scopes: integration.scopes,
    disabledChecks: integration.disabledChecks,
    googleMailboxScanEnabled: integration.googleMailboxScanEnabled,
    googleMailboxScanClientEmail: integration.googleMailboxScanClientEmail,
    lastSyncAt: integration.lastSyncAt?.toISOString() ?? null,
    createdAt: integration.createdAt.toISOString()
  };
}

async function refreshGoogleAccessToken(refreshToken: string) {
  const config = googleOauthConfig();

  if (!config) {
    throw new Error("Google Workspace OAuth is not configured");
  }

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      refresh_token: refreshToken,
      grant_type: "refresh_token"
    })
  });

  if (!response.ok) {
    throw new Error("Unable to refresh the Google Workspace access token");
  }

  const body = (await response.json()) as { access_token?: string };

  if (!body.access_token) {
    throw new Error("Google did not return an access token");
  }

  return body.access_token;
}

async function fetchGoogleServiceAccountAccessToken(input: {
  clientEmail: string;
  privateKey: string;
  subject: string;
  scopes: string[];
}) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = base64UrlJson({ alg: "RS256", typ: "JWT" });
  const claims = base64UrlJson({
    iss: input.clientEmail,
    scope: input.scopes.join(" "),
    aud: "https://oauth2.googleapis.com/token",
    sub: input.subject,
    iat: issuedAt,
    exp: issuedAt + 3600
  });
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${claims}`);
  signer.end();
  const assertion = `${header}.${claims}.${signer
    .sign(input.privateKey)
    .toString("base64url")}`;

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });

  if (!response.ok) {
    throw new Error("Unable to mint a Google service account access token");
  }

  const body = (await response.json()) as { access_token?: string };

  if (!body.access_token) {
    throw new Error("Google did not return a service account access token");
  }

  return body.access_token;
}

async function mapWithConcurrency<TInput, TOutput>(
  items: TInput[],
  limit: number,
  mapper: (item: TInput, index: number) => Promise<TOutput>
) {
  const results = new Array<TOutput>(items.length);
  let nextIndex = 0;

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (nextIndex < items.length) {
        const currentIndex = nextIndex;
        nextIndex += 1;
        results[currentIndex] = await mapper(items[currentIndex] as TInput, currentIndex);
      }
    })
  );

  return results;
}

async function probeGoogleWorkspace(integration: {
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  externalAccountId: string;
  encryptedAccessToken: string;
}) {
  const refreshToken = decryptString(
    integration.encryptedAccessToken,
    aadForIntegration({
      organizationId: integration.organizationId,
      provider: integration.provider,
      externalAccountId: integration.externalAccountId,
      suffix: "access_token"
    })
  );
  const accessToken = await refreshGoogleAccessToken(refreshToken);

  const reportsResponse = await fetch(
    "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=10",
    {
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    }
  );

  if (reportsResponse.ok) {
    const body = (await reportsResponse.json()) as { items?: unknown[] };
    return {
      sampleCount: body.items?.length ?? 0,
      source: "reports.login"
    };
  }

  const usersResponse = await fetch(
    "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=1&orderBy=email",
    {
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    }
  );

  if (!usersResponse.ok) {
    throw new Error("Google Workspace sync probe failed");
  }

  const body = (await usersResponse.json()) as { users?: unknown[] };
  return {
    sampleCount: body.users?.length ?? 0,
    source: "directory.users"
  };
}

function googleSyncStart(lastSyncAt: Date | null) {
  return new Date(
    (lastSyncAt?.getTime() ?? Date.now() - 24 * 60 * 60 * 1000) -
      5 * 60 * 1000
  ).toISOString();
}

function normalizeGoogleParameterValue(parameter: GoogleReportParameter): unknown {
  if (parameter.boolValue !== undefined) {
    return parameter.boolValue;
  }
  if (parameter.value !== undefined) {
    return parameter.value;
  }
  if (parameter.intValue !== undefined) {
    const parsed = Number(parameter.intValue);
    return Number.isNaN(parsed) ? parameter.intValue : parsed;
  }
  if (parameter.multiValue?.length) {
    return parameter.multiValue;
  }
  if (parameter.messageValue?.parameter?.length) {
    return Object.fromEntries(
      parameter.messageValue.parameter.map((nested) => [
        nested.name ?? "unknown",
        normalizeGoogleParameterValue(nested)
      ])
    );
  }
  return null;
}

function googleParametersToObject(parameters: GoogleReportParameter[] = []) {
  return Object.fromEntries(
    parameters
      .filter((parameter) => parameter.name)
      .map((parameter) => [
        parameter.name as string,
        normalizeGoogleParameterValue(parameter)
      ])
  );
}

function collectStrings(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (typeof value === "number" || typeof value === "boolean" || value == null) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectStrings(item));
  }
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((item) =>
      collectStrings(item)
    );
  }
  return [];
}

function uniqueGoogleStrings(values: string[]) {
  return values.filter(
    (value, index, current) => value.trim().length > 0 && current.indexOf(value) === index
  );
}

function sameEmailDomain(email: string, domain: string) {
  return email.toLowerCase().endsWith(`@${domain.toLowerCase()}`);
}

function classifyGoogleEvent(input: {
  application: string;
  event: GoogleReportAuditEvent;
  parameters: Record<string, unknown>;
}) {
  const lowerEventName = (input.event.name ?? "").toLowerCase();
  const lowerEventType = (input.event.type ?? "").toLowerCase();
  const lowerValues = collectStrings(input.parameters).map((value) =>
    value.toLowerCase()
  );
  const valuesBlob = lowerValues.join(" ");
  const eventBlob = `${lowerEventType} ${lowerEventName}`;
  const containsOneOf = (needles: string[]) =>
    needles.some(
      (needle) => eventBlob.includes(needle) || valuesBlob.includes(needle)
    );
  const containsNoneOf = (needles: string[]) => !containsOneOf(needles);

  if (
    input.application === "drive" &&
    containsOneOf([
      "external",
      "outside_domain",
      "public",
      "anyone_with_link",
      "shared_externally"
    ]) &&
    containsOneOf(["acl", "share", "visibility", "permission", "access"])
  ) {
    return "EXTERNAL_SHARING_ENABLED";
  }

  if (
    input.application === "admin" &&
    containsOneOf(["super_admin", "super administrator"]) &&
    containsOneOf(["role", "privilege", "admin"])
  ) {
    return "SUPER_ADMIN_GRANTED";
  }

  if (
    input.application === "admin" &&
    containsNoneOf(["super_admin", "super administrator", "remove", "removed", "delete"]) &&
    containsOneOf(["role", "privilege", "admin"]) &&
    containsOneOf(["assign", "assigned", "grant", "granted", "add", "added", "create"])
  ) {
    return "ADMIN_ROLE_GRANTED";
  }

  if (
    (input.application === "token" || input.application === "login") &&
    containsOneOf(["grant", "authorize", "oauth", "token"]) &&
    containsOneOf([
      "mail.google.com",
      "gmail",
      "https://www.googleapis.com/auth/admin",
      "https://www.googleapis.com/auth/drive",
      "directory",
      "reports.audit"
    ])
  ) {
    return "RISKY_OAUTH_GRANT";
  }

  if (
    input.application === "gmail" &&
    containsOneOf(["forward", "forwarding", "auto-forward"]) &&
    containsNoneOf(["disable", "disabled", "remove", "removed", "delete", "deleted", "off"]) &&
    containsOneOf(["enable", "enabled", "add", "create", "update", "change", "on"])
  ) {
    return "EMAIL_FORWARDING_ENABLED";
  }

  if (
    input.application === "gmail" &&
    containsOneOf(["delegate", "delegation"]) &&
    containsNoneOf(["disable", "disabled", "remove", "removed", "delete", "deleted", "off"]) &&
    containsOneOf(["accept", "accepted", "add", "create", "grant", "granted", "enable"])
  ) {
    return "MAILBOX_DELEGATION_GRANTED";
  }

  if (
    (input.application === "login" || input.application === "gmail") &&
    containsOneOf([
      "app_password",
      "app password",
      "application-specific password",
      "imap",
      "pop",
      "smtp",
      "basic auth",
      "legacy auth",
      "less secure"
    ]) &&
    containsNoneOf(["disable", "disabled", "remove", "removed", "delete", "deleted"]) &&
    containsOneOf(["auth", "authenticate", "login", "created", "create", "use", "used", "success"])
  ) {
    return "LEGACY_MAIL_AUTH_USED";
  }

  const applicationPrefix = input.application.toUpperCase();
  const typePart = (input.event.type ?? "activity")
    .replace(/[^a-z0-9]+/gi, "_")
    .toUpperCase();
  const namePart = (input.event.name ?? "event")
    .replace(/[^a-z0-9]+/gi, "_")
    .toUpperCase();

  return `${applicationPrefix}_${typePart}_${namePart}`.slice(0, 180);
}

async function fetchGoogleReportActivities(input: {
  accessToken: string;
  application: string;
  startTime: string;
  endTime: string;
}) {
  const url = new URL(
    `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/${input.application}`
  );
  url.searchParams.set("maxResults", "100");
  url.searchParams.set("startTime", input.startTime);
  url.searchParams.set("endTime", input.endTime);

  const response = await fetch(url, {
    headers: {
      authorization: `Bearer ${input.accessToken}`
    }
  });

  if (!response.ok) {
    throw new Error(`Unable to fetch Google Workspace ${input.application} activities`);
  }

  const body = (await response.json()) as { items?: GoogleReportActivity[] };
  return body.items ?? [];
}

async function listGoogleWorkspaceUsers(input: {
  accessToken: string;
  projection?: "basic" | "full";
  onlyActive?: boolean;
}) {
  const users: GoogleDirectoryUser[] = [];
  let pageToken: string | undefined;

  do {
    const url = new URL(
      "https://admin.googleapis.com/admin/directory/v1/users"
    );
    url.searchParams.set("customer", "my_customer");
    url.searchParams.set("maxResults", "100");
    url.searchParams.set("orderBy", "email");
    url.searchParams.set("projection", input.projection ?? "basic");
    url.searchParams.set("viewType", "admin_view");
    if (input.onlyActive !== false) {
      url.searchParams.set("query", "isSuspended=false");
    }

    if (pageToken) {
      url.searchParams.set("pageToken", pageToken);
    }

    const response = await fetch(url, {
      headers: {
        authorization: `Bearer ${input.accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error("Unable to list Google Workspace users for mailbox scanning");
    }

    const body = (await response.json()) as {
      users?: GoogleDirectoryUser[];
      nextPageToken?: string;
    };

    users.push(
      ...(body.users ?? []).filter((user) =>
        input.onlyActive === false
          ? !user.archived && user.primaryEmail
          : !user.suspended && !user.archived && user.primaryEmail
      )
    );

    pageToken = body.nextPageToken;
  } while (pageToken);

  return users;
}

async function fetchGoogleRoleAssignments(accessToken: string) {
  const assignments: GoogleRoleAssignment[] = [];
  let pageToken: string | undefined;

  do {
    const url = new URL(
      "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments"
    );
    url.searchParams.set("maxResults", "100");

    if (pageToken) {
      url.searchParams.set("pageToken", pageToken);
    }

    const response = await fetch(url, {
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });

    if (response.status === 403) {
      return null;
    }

    if (!response.ok) {
      throw new Error("Unable to list Google Workspace admin role assignments");
    }

    const body = (await response.json()) as {
      items?: GoogleRoleAssignment[];
      nextPageToken?: string;
    };

    assignments.push(...(body.items ?? []));
    pageToken = body.nextPageToken;
  } while (pageToken);

  return assignments;
}

async function fetchGoogleRole(accessToken: string, roleId: string) {
  const response = await fetch(
    `https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles/${encodeURIComponent(roleId)}`,
    {
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    }
  );

  if (response.status === 403) {
    return null;
  }

  if (!response.ok) {
    throw new Error(`Unable to fetch Google Workspace role ${roleId}`);
  }

  return (await response.json()) as GoogleRole;
}

function googleIdentityKind(email: string) {
  const localPart = email.split("@")[0]?.toLowerCase() ?? "";

  if (localPart.includes("bot")) {
    return "BOT" as const;
  }

  if (
    localPart.startsWith("svc-") ||
    localPart.startsWith("service-") ||
    localPart.includes("automation")
  ) {
    return "SERVICE_ACCOUNT" as const;
  }

  return "USER" as const;
}

function googlePrivilegedIdentityRisk(input: {
  isAdmin: boolean;
  isDelegatedAdmin: boolean;
  roleNames: string[];
  mfaEnabled: boolean;
  recoveryEmail: string | null | undefined;
  primaryEmail: string;
}) {
  return Math.min(
    100,
    (input.isAdmin ? 72 : 60) +
      Math.min(12, input.roleNames.length * 4) +
      (input.mfaEnabled ? 0 : 18) +
      (input.recoveryEmail &&
      !sameEmailDomain(input.recoveryEmail, input.primaryEmail.split("@")[1] ?? "")
        ? 8
        : 0)
  );
}

export async function syncGoogleWorkspacePrivilegedIdentities(input: {
  accessToken: string;
  organizationId: string;
  integrationId: string;
}) {
  const users = await listGoogleWorkspaceUsers({
    accessToken: input.accessToken,
    projection: "full",
    onlyActive: false
  });
  const roleAssignments = await fetchGoogleRoleAssignments(input.accessToken);
  const roleIds = roleAssignments
    ? Array.from(
        new Set(
          roleAssignments
            .map((assignment) => assignment.roleId)
            .filter((roleId): roleId is string => Boolean(roleId))
        )
      )
    : [];
  const roles = await mapWithConcurrency(roleIds, 5, async (roleId) =>
    fetchGoogleRole(input.accessToken, roleId)
  );
  const roleNameById = new Map(
    roles
      .filter((role): role is GoogleRole => Boolean(role?.roleId))
      .map((role) => [role.roleId as string, role.roleName ?? "Admin role"])
  );
  const roleNamesByUserId = new Map<string, string[]>();

  for (const assignment of roleAssignments ?? []) {
    if (
      (assignment.assigneeType && assignment.assigneeType !== "USER") ||
      !assignment.assignedTo ||
      !assignment.roleId
    ) {
      continue;
    }

    const roleName = roleNameById.get(assignment.roleId);
    if (!roleName) {
      continue;
    }

    const current = roleNamesByUserId.get(assignment.assignedTo) ?? [];
    current.push(roleName);
    roleNamesByUserId.set(assignment.assignedTo, current);
  }

  const privilegedUsers = users
    .filter(
      (user) =>
        Boolean(user.primaryEmail) &&
        (user.isAdmin === true ||
          user.isDelegatedAdmin === true ||
          (user.id ? (roleNamesByUserId.get(user.id)?.length ?? 0) > 0 : false))
    )
    .map((user) => {
      const email = user.primaryEmail as string;
      const roleNames = uniqueGoogleStrings([
        ...(user.isAdmin ? ["Super admin"] : []),
        ...(user.isDelegatedAdmin ? ["Delegated admin"] : []),
        ...(user.id ? roleNamesByUserId.get(user.id) ?? [] : [])
      ]);
      const mfaEnabled = user.isEnrolledIn2Sv === true && user.isEnforcedIn2Sv === true;
      const status: "ACTIVE" | "SUSPENDED" = user.suspended ? "SUSPENDED" : "ACTIVE";

      return {
        email,
        displayName: user.name?.fullName?.trim() || email,
        kind: googleIdentityKind(email),
        status,
        role: roleNames.join(", ") || (user.isAdmin ? "Super admin" : "Delegated admin"),
        roleNames,
        mfaEnabled,
        riskScore: googlePrivilegedIdentityRisk({
          isAdmin: user.isAdmin === true,
          isDelegatedAdmin: user.isDelegatedAdmin === true,
          roleNames,
          mfaEnabled,
          recoveryEmail: user.recoveryEmail,
          primaryEmail: email
        })
      };
    });
  const observedEmails = privilegedUsers.map((user) => user.email);

  await prisma.$transaction(async (tx) => {
    for (const user of privilegedUsers) {
      await tx.saasIdentity.upsert({
        where: {
          organizationId_provider_externalId: {
            organizationId: input.organizationId,
            provider: "GOOGLE_WORKSPACE",
            externalId: user.email
          }
        },
        update: {
          integrationId: input.integrationId,
          email: user.email,
          displayName: user.displayName,
          kind: user.kind,
          status: user.status,
          role: user.role,
          groups: [],
          scopeHints: user.roleNames,
          mfaEnabled: user.mfaEnabled,
          isPrivileged: true,
          isExternal: false,
          lastObservedAt: new Date(),
          riskScore: user.riskScore
        },
        create: {
          organizationId: input.organizationId,
          integrationId: input.integrationId,
          provider: "GOOGLE_WORKSPACE",
          externalId: user.email,
          email: user.email,
          displayName: user.displayName,
          kind: user.kind,
          status: user.status,
          role: user.role,
          groups: [],
          scopeHints: user.roleNames,
          mfaEnabled: user.mfaEnabled,
          isPrivileged: true,
          isExternal: false,
          lastObservedAt: new Date(),
          riskScore: user.riskScore
        }
      });
    }

    await tx.saasIdentity.updateMany({
      where: {
        organizationId: input.organizationId,
        integrationId: input.integrationId,
        provider: "GOOGLE_WORKSPACE",
        ...(observedEmails.length > 0
          ? { externalId: { notIn: observedEmails } }
          : {})
      },
      data: {
        isPrivileged: false,
        role: "User",
        scopeHints: [],
        riskScore: 20
      }
    });
  });

  return {
    privilegedIdentityCount: privilegedUsers.length,
    roleManagementGranted: roleAssignments !== null
  };
}

async function fetchGoogleMailboxAutoForwarding(input: {
  accessToken: string;
  userEmail: string;
}) {
  const response = await fetch(
    "https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding",
    {
      headers: {
        authorization: `Bearer ${input.accessToken}`
      }
    }
  );

  if (response.status === 400 || response.status === 404) {
    return null;
  }

  if (response.status === 403) {
    throw new Error(
      "Google Workspace mailbox scanning is not authorized. Configure domain-wide delegation with gmail.settings.basic and gmail.settings.sharing."
    );
  }

  if (!response.ok) {
    throw new Error(
      `Unable to fetch Gmail auto-forwarding settings for ${input.userEmail}`
    );
  }

  return (await response.json()) as GmailAutoForwarding;
}

async function fetchGoogleMailboxDelegates(input: {
  accessToken: string;
  userEmail: string;
}) {
  const response = await fetch(
    "https://gmail.googleapis.com/gmail/v1/users/me/settings/delegates",
    {
      headers: {
        authorization: `Bearer ${input.accessToken}`
      }
    }
  );

  if (response.status === 400 || response.status === 404) {
    return [] as GmailDelegate[];
  }

  if (response.status === 403) {
    throw new Error(
      "Google Workspace mailbox scanning is not authorized. Configure domain-wide delegation with gmail.settings.sharing."
    );
  }

  if (!response.ok) {
    throw new Error(`Unable to fetch Gmail delegates for ${input.userEmail}`);
  }

  const body = (await response.json()) as { delegates?: GmailDelegate[] };
  return body.delegates ?? [];
}

async function fetchGoogleMailboxSendAs(input: {
  accessToken: string;
  userEmail: string;
}) {
  const response = await fetch(
    "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs",
    {
      headers: {
        authorization: `Bearer ${input.accessToken}`
      }
    }
  );

  if (response.status === 400 || response.status === 404) {
    return [] as GmailSendAs[];
  }

  if (response.status === 403) {
    throw new Error(
      "Google Workspace mailbox scanning is not authorized. Configure domain-wide delegation with gmail.settings.sharing."
    );
  }

  if (!response.ok) {
    throw new Error(`Unable to fetch Gmail send-as aliases for ${input.userEmail}`);
  }

  const body = (await response.json()) as { sendAs?: GmailSendAs[] };
  return body.sendAs ?? [];
}

export async function scanGoogleWorkspaceMailboxForwarding(input: {
  accessToken: string;
  integrationId: string;
  organizationId: string;
  externalAccountId: string;
  googleMailboxScanClientEmail: string | null;
  encryptedGoogleMailboxScanPrivateKey: string | null;
}) {
  const config = effectiveGoogleMailboxScanConfig({
    organizationId: input.organizationId,
    provider: "GOOGLE_WORKSPACE",
    externalAccountId: input.externalAccountId,
    googleMailboxScanClientEmail: input.googleMailboxScanClientEmail,
    encryptedGoogleMailboxScanPrivateKey: input.encryptedGoogleMailboxScanPrivateKey
  });

  if (!config) {
    return {
      payloads: [],
      scanEnabled: false,
      scannedMailboxCount: 0
    } satisfies GoogleForwardingInventoryResult;
  }

  const users = (await listGoogleWorkspaceUsers({ accessToken: input.accessToken }))
    .map((user) => user.primaryEmail)
    .filter((userEmail): userEmail is string => Boolean(userEmail));
  const scanResults = await mapWithConcurrency(users, 5, async (userEmail) => {
    const mailboxAccessToken = await fetchGoogleServiceAccountAccessToken({
      clientEmail: config.clientEmail,
      privateKey: config.privateKey,
      subject: userEmail,
      scopes: [
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.settings.sharing"
      ]
    });
    const [autoForwarding, delegates, sendAsAliases] = await Promise.all([
      fetchGoogleMailboxAutoForwarding({
        accessToken: mailboxAccessToken,
        userEmail
      }),
      fetchGoogleMailboxDelegates({
        accessToken: mailboxAccessToken,
        userEmail
      }),
      fetchGoogleMailboxSendAs({
        accessToken: mailboxAccessToken,
        userEmail
      })
    ]);

    const payloads: GoogleForwardingInventoryResult["payloads"] = [];
    const acceptedDelegates = uniqueGoogleStrings(
      delegates
        .filter(
          (delegate) =>
            delegate.verificationStatus?.toLowerCase() !== "pending" &&
            Boolean(delegate.delegateEmail)
        )
        .map((delegate) => delegate.delegateEmail as string)
    );
    const nonPrimarySendAsAliases = uniqueGoogleStrings(
      sendAsAliases
        .filter(
          (alias) =>
            Boolean(alias.sendAsEmail) &&
            alias.sendAsEmail?.toLowerCase() !== userEmail.toLowerCase() &&
            alias.verificationStatus?.toLowerCase() !== "pending"
        )
        .map((alias) => alias.sendAsEmail as string)
    );
    const externalSendAsAliases = nonPrimarySendAsAliases.filter(
      (alias) => !sameEmailDomain(alias, input.externalAccountId)
    );

    if (autoForwarding?.enabled && autoForwarding.emailAddress) {
      payloads.push({
        integrationId: input.integrationId,
        organizationId: input.organizationId,
        provider: "GOOGLE_WORKSPACE",
        eventType: "EMAIL_FORWARDING_ENABLED",
        source: "google_workspace.settings.gmail",
        actor: userEmail,
        occurredAt: new Date(),
        payload: {
          provider: "GOOGLE_WORKSPACE",
          application: "gmail",
          ownerDomain: input.externalAccountId,
          ipAddress: null,
          actor: {
            email: userEmail
          },
          event: {
            name: "auto_forwarding_enabled",
            type: "settings_scan"
          },
          parameters: {
            email: userEmail,
            enabled: true,
            forwarding_address: autoForwarding.emailAddress,
            forwarding_disposition: autoForwarding.disposition ?? null
          }
        }
      });
    }

    for (const delegateEmail of acceptedDelegates) {
      payloads.push({
        integrationId: input.integrationId,
        organizationId: input.organizationId,
        provider: "GOOGLE_WORKSPACE",
        eventType: "MAILBOX_DELEGATION_GRANTED",
        source: "google_workspace.settings.gmail",
        actor: userEmail,
        occurredAt: new Date(),
        payload: {
          provider: "GOOGLE_WORKSPACE",
          application: "gmail",
          ownerDomain: input.externalAccountId,
          ipAddress: null,
          actor: {
            email: userEmail
          },
          event: {
            name: "delegate_granted",
            type: "settings_scan"
          },
          parameters: {
            email: userEmail,
            delegate_email: delegateEmail,
            delegation_status: "accepted"
          }
        }
      });
    }

    if (
      autoForwarding?.enabled &&
      autoForwarding.emailAddress &&
      (acceptedDelegates.length > 0 || nonPrimarySendAsAliases.length > 0)
    ) {
      payloads.push({
        integrationId: input.integrationId,
        organizationId: input.organizationId,
        provider: "GOOGLE_WORKSPACE",
        eventType: "FORWARDING_DELEGATE_SEND_AS_COMBO",
        source: "google_workspace.settings.gmail",
        actor: userEmail,
        occurredAt: new Date(),
        payload: {
          provider: "GOOGLE_WORKSPACE",
          application: "gmail",
          ownerDomain: input.externalAccountId,
          ipAddress: null,
          actor: {
            email: userEmail
          },
          event: {
            name: "forwarding_delegate_send_as_combo",
            type: "settings_scan"
          },
          parameters: {
            email: userEmail,
            forwarding_address: autoForwarding.emailAddress,
            forwarding_disposition: autoForwarding.disposition ?? null,
            delegates: acceptedDelegates,
            send_as_aliases: nonPrimarySendAsAliases,
            external_send_as_aliases: externalSendAsAliases
          }
        }
      });
    }

    return payloads;
  });

  return {
    payloads: scanResults.flat(),
    scanEnabled: true,
    scannedMailboxCount: users.length
  } satisfies GoogleForwardingInventoryResult;
}

export async function scanGoogleWorkspaceAdminPosture(input: {
  accessToken: string;
  integrationId: string;
  organizationId: string;
  externalAccountId: string;
}) {
  const users = await listGoogleWorkspaceUsers({
    accessToken: input.accessToken,
    projection: "full"
  });
  const adminUsers = users.filter(
    (user) =>
      Boolean(user.primaryEmail) && (user.isAdmin === true || user.isDelegatedAdmin === true)
  );
  const payloads: GoogleAdminPostureInventoryResult["payloads"] = [];

  for (const user of adminUsers) {
    const email = user.primaryEmail as string;
    const mfaEnrolled = user.isEnrolledIn2Sv === true;
    const mfaEnforced = user.isEnforcedIn2Sv === true;

    if (!mfaEnrolled || !mfaEnforced) {
      payloads.push({
        integrationId: input.integrationId,
        organizationId: input.organizationId,
        provider: "GOOGLE_WORKSPACE",
        eventType: "ADMIN_MFA_NOT_ENFORCED",
        source: "google_workspace.directory.users",
        actor: email,
        occurredAt: new Date(),
        payload: {
          provider: "GOOGLE_WORKSPACE",
          application: "directory",
          ownerDomain: input.externalAccountId,
          ipAddress: null,
          actor: {
            email
          },
          event: {
            name: "admin_mfa_not_enforced",
            type: "directory_scan"
          },
          parameters: {
            email,
            is_admin: user.isAdmin === true,
            is_delegated_admin: user.isDelegatedAdmin === true,
            mfa_enrolled: mfaEnrolled,
            mfa_enforced: mfaEnforced
          }
        }
      });
    }

    if (
      user.recoveryEmail &&
      !sameEmailDomain(user.recoveryEmail, input.externalAccountId)
    ) {
      payloads.push({
        integrationId: input.integrationId,
        organizationId: input.organizationId,
        provider: "GOOGLE_WORKSPACE",
        eventType: "ADMIN_EXTERNAL_RECOVERY_EMAIL",
        source: "google_workspace.directory.users",
        actor: email,
        occurredAt: new Date(),
        payload: {
          provider: "GOOGLE_WORKSPACE",
          application: "directory",
          ownerDomain: input.externalAccountId,
          ipAddress: null,
          actor: {
            email
          },
          event: {
            name: "admin_external_recovery_email",
            type: "directory_scan"
          },
          parameters: {
            email,
            recovery_email: user.recoveryEmail,
            recovery_phone: user.recoveryPhone ?? null,
            is_admin: user.isAdmin === true,
            is_delegated_admin: user.isDelegatedAdmin === true
          }
        }
      });
    }
  }

  return {
    payloads,
    scanEnabled: true,
    scannedAdminCount: adminUsers.length
  } satisfies GoogleAdminPostureInventoryResult;
}

async function fetchAllGoogleAdminAuditEvents(input: {
  accessToken: string;
  eventName: string;
}) {
  const all: GoogleReportActivity[] = [];
  let pageToken: string | undefined;
  let pageCount = 0;

  do {
    const url = new URL(
      "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin"
    );
    url.searchParams.set("maxResults", "1000");
    url.searchParams.set("eventName", input.eventName);
    if (pageToken) {
      url.searchParams.set("pageToken", pageToken);
    }

    const response = await fetch(url, {
      headers: {
        authorization: `Bearer ${input.accessToken}`
      }
    });

    if (response.status === 403) {
      const err = new Error("forbidden") as Error & { status?: number };
      err.status = 403;
      throw err;
    }
    if (response.status === 400 || response.status === 404) {
      return all;
    }
    if (!response.ok) {
      const bodyText = await response.text().catch(() => "");
      logger.warn("google.admin_audit_fetch_failed", {
        eventName: input.eventName,
        status: response.status,
        body: bodyText.slice(0, 500)
      });
      return all;
    }

    const body = (await response.json()) as {
      items?: GoogleReportActivity[];
      nextPageToken?: string;
    };

    all.push(...(body.items ?? []));
    pageToken = body.nextPageToken;
    pageCount += 1;
  } while (pageToken && pageCount < 50);

  return all;
}

function computeDwdRisk(scopes: string[]) {
  const lower = scopes.map((scope) => scope.toLowerCase());
  const criticalScopes = new Set([
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.insert",
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.settings.sharing",
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/cloud-platform"
  ]);
  const highScopes = new Set([
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/apps.groups.settings"
  ]);

  const hasCritical = lower.some((scope) => criticalScopes.has(scope));
  const hasHigh = lower.some((scope) => highScopes.has(scope));
  const touchesSensitiveData = lower.some(
    (scope) =>
      scope.includes("gmail") ||
      scope.includes("mail.google.com") ||
      scope.includes("drive") ||
      scope.includes("admin.directory")
  );

  if (hasCritical) {
    return {
      score: Math.min(100, 90 + lower.length),
      criticality: "CRITICAL" as const,
      touchesSensitiveData
    };
  }
  if (hasHigh) {
    return {
      score: Math.min(95, 78 + lower.length),
      criticality: "HIGH" as const,
      touchesSensitiveData
    };
  }
  return {
    score: Math.min(80, 60 + lower.length * 2),
    criticality: "HIGH" as const,
    touchesSensitiveData
  };
}

type DwdAuditEvent = {
  occurredAt: Date;
  eventName: "AUTHORIZE_API_CLIENT_ACCESS" | "REVOKE_API_CLIENT_ACCESS";
  clientId: string;
  scopes: string[];
  actor: string | null;
};

export async function scanGoogleWorkspaceDomainWideDelegations(input: {
  accessToken: string;
  integrationId: string;
  organizationId: string;
}) {
  let authActivities: GoogleReportActivity[] = [];
  let revokeActivities: GoogleReportActivity[] = [];

  try {
    [authActivities, revokeActivities] = await Promise.all([
      fetchAllGoogleAdminAuditEvents({
        accessToken: input.accessToken,
        eventName: "AUTHORIZE_API_CLIENT_ACCESS"
      }),
      fetchAllGoogleAdminAuditEvents({
        accessToken: input.accessToken,
        eventName: "REVOKE_API_CLIENT_ACCESS"
      })
    ]);
  } catch (error) {
    if ((error as { status?: number })?.status === 403) {
      return {
        scanEnabled: false,
        clientCount: 0,
        observedEventCount: 0
      } satisfies GoogleDwdInventoryResult;
    }
    throw error;
  }

  const fromActivity = (
    activity: GoogleReportActivity,
    eventName: "AUTHORIZE_API_CLIENT_ACCESS" | "REVOKE_API_CLIENT_ACCESS"
  ): DwdAuditEvent | null => {
    const ev = activity.events?.find(
      (entry) => (entry.name ?? "").toUpperCase() === eventName
    );
    if (!ev) {
      return null;
    }
    const params = googleParametersToObject(ev.parameters);
    const clientIdValue = params.CLIENT_ID ?? params.client_id;
    const clientId = typeof clientIdValue === "string" ? clientIdValue.trim() : "";
    if (!clientId) {
      return null;
    }
    const scopesValue = params.API_SCOPES ?? params.api_scopes ?? params.SCOPE;
    let scopes: string[] = [];
    if (Array.isArray(scopesValue)) {
      scopes = scopesValue.filter((value): value is string => typeof value === "string");
    } else if (typeof scopesValue === "string") {
      scopes = scopesValue
        .split(/[,\s]+/)
        .map((value) => value.trim())
        .filter(Boolean);
    }
    const occurredAtRaw = activity.id?.time;
    const occurredAt = occurredAtRaw ? new Date(occurredAtRaw) : new Date();
    return {
      occurredAt: Number.isNaN(occurredAt.getTime()) ? new Date() : occurredAt,
      eventName,
      clientId,
      scopes,
      actor: activity.actor?.email ?? null
    };
  };

  const events: DwdAuditEvent[] = [
    ...authActivities
      .map((activity) => fromActivity(activity, "AUTHORIZE_API_CLIENT_ACCESS"))
      .filter((event): event is DwdAuditEvent => event !== null),
    ...revokeActivities
      .map((activity) => fromActivity(activity, "REVOKE_API_CLIENT_ACCESS"))
      .filter((event): event is DwdAuditEvent => event !== null)
  ].sort((a, b) => a.occurredAt.getTime() - b.occurredAt.getTime());

  type ClientState = {
    scopes: Set<string>;
    grantedBy: Set<string>;
    firstAuthorizedAt: Date;
    lastChangedAt: Date;
  };
  const state = new Map<string, ClientState>();

  for (const event of events) {
    if (event.eventName === "REVOKE_API_CLIENT_ACCESS") {
      const existing = state.get(event.clientId);
      if (!existing) {
        continue;
      }
      if (event.scopes.length === 0) {
        state.delete(event.clientId);
        continue;
      }
      for (const scope of event.scopes) {
        existing.scopes.delete(scope);
      }
      existing.lastChangedAt = event.occurredAt;
      if (existing.scopes.size === 0) {
        state.delete(event.clientId);
      }
      continue;
    }

    const existing = state.get(event.clientId);
    if (existing) {
      for (const scope of event.scopes) {
        existing.scopes.add(scope);
      }
      if (event.actor) {
        existing.grantedBy.add(event.actor);
      }
      existing.lastChangedAt = event.occurredAt;
    } else {
      state.set(event.clientId, {
        scopes: new Set(event.scopes),
        grantedBy: new Set(event.actor ? [event.actor] : []),
        firstAuthorizedAt: event.occurredAt,
        lastChangedAt: event.occurredAt
      });
    }
  }

  const existingAssets = await prisma.securityAsset.findMany({
    where: {
      organizationId: input.organizationId,
      integrationId: input.integrationId,
      type: "OAUTH_APP",
      labels: { has: "dwd" }
    },
    select: { id: true, externalId: true, labels: true }
  });
  const existingByClientId = new Map(
    existingAssets
      .filter((asset) => asset.externalId)
      .map((asset) => [asset.externalId as string, asset])
  );
  const observedClientIds = new Set<string>();

  for (const [clientId, entry] of state) {
    observedClientIds.add(clientId);
    const scopes = Array.from(entry.scopes);
    const risk = computeDwdRisk(scopes);
    const summary =
      scopes.length === 0
        ? "Domain-wide delegated client (no scopes recorded)"
        : `Domain-wide delegated client · ${scopes.length} scope${scopes.length === 1 ? "" : "s"}`;
    const labels = Array.from(new Set(["dwd", "oauth", "google-workspace"]));
    const data = {
      name: clientId.slice(0, 180),
      summary,
      labels,
      criticality: risk.criticality,
      exposureLevel: "TRUSTED_EXTERNAL" as const,
      containsSensitiveData: risk.touchesSensitiveData,
      isPrivileged: true,
      riskScore: risk.score,
      lastObservedAt: entry.lastChangedAt
    };

    const existing = existingByClientId.get(clientId);
    if (existing) {
      await prisma.securityAsset.update({
        where: { id: existing.id },
        data
      });
    } else {
      await prisma.securityAsset.create({
        data: {
          organizationId: input.organizationId,
          integrationId: input.integrationId,
          type: "OAUTH_APP",
          provider: "GOOGLE_WORKSPACE",
          externalId: clientId,
          ...data
        }
      });
    }
  }

  const removedAssetIds = existingAssets
    .filter((asset) => asset.externalId && !observedClientIds.has(asset.externalId))
    .map((asset) => asset.id);

  if (removedAssetIds.length > 0) {
    await prisma.securityAsset.updateMany({
      where: { id: { in: removedAssetIds } },
      data: {
        riskScore: 0,
        criticality: "LOW",
        summary: "Previously domain-wide delegated client (revoked)",
        labels: ["dwd", "oauth", "google-workspace", "revoked"]
      }
    });
  }

  return {
    scanEnabled: true,
    clientCount: state.size,
    observedEventCount: events.length
  } satisfies GoogleDwdInventoryResult;
}

type GoogleOauthTokenGrant = {
  clientId: string;
  displayText?: string;
  scopes?: string[];
  anonymous?: boolean;
  nativeApp?: boolean;
  userKey?: string;
};

type GoogleOauthGrantsInventoryResult = {
  scanEnabled: boolean;
  appCount: number;
  grantCount: number;
};

async function fetchGoogleUserTokens(input: {
  accessToken: string;
  userKey: string;
}) {
  const response = await fetch(
    `https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(
      input.userKey
    )}/tokens`,
    {
      headers: {
        authorization: `Bearer ${input.accessToken}`
      }
    }
  );

  if (response.status === 403) {
    const err = new Error("forbidden") as Error & { status?: number };
    err.status = 403;
    throw err;
  }
  if (response.status === 404) {
    return [] as GoogleOauthTokenGrant[];
  }
  if (!response.ok) {
    throw new Error(
      `Unable to fetch OAuth tokens for Google user ${input.userKey}`
    );
  }

  const body = (await response.json()) as { items?: GoogleOauthTokenGrant[] };
  return body.items ?? [];
}

const SHADOW_IT_CRITICAL_SCOPES = new Set([
  "https://mail.google.com/",
  "https://www.googleapis.com/auth/gmail.insert",
  "https://www.googleapis.com/auth/gmail.settings.basic",
  "https://www.googleapis.com/auth/gmail.settings.sharing",
  "https://www.googleapis.com/auth/admin.directory.user",
  "https://www.googleapis.com/auth/admin.directory.user.security",
  "https://www.googleapis.com/auth/admin.directory.group",
  "https://www.googleapis.com/auth/admin.directory.rolemanagement",
  "https://www.googleapis.com/auth/cloud-platform"
]);

const SHADOW_IT_HIGH_SCOPES = new Set([
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.compose",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/drive.file",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
  "https://www.googleapis.com/auth/apps.groups.settings"
]);

const SHADOW_IT_MEDIUM_SCOPES = new Set([
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.metadata",
  "https://www.googleapis.com/auth/gmail.labels",
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/drive.metadata",
  "https://www.googleapis.com/auth/drive.metadata.readonly",
  "https://www.googleapis.com/auth/contacts",
  "https://www.googleapis.com/auth/contacts.readonly",
  "https://www.googleapis.com/auth/calendar",
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.group.readonly"
]);

const SHADOW_IT_LOW_SCOPES = new Set([
  "openid",
  "profile",
  "email",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/calendar.events.readonly",
  "https://www.googleapis.com/auth/tasks.readonly",
  "https://www.googleapis.com/auth/spreadsheets.readonly",
  "https://www.googleapis.com/auth/documents.readonly"
]);

function classifyShadowItScope(scope: string): "critical" | "high" | "medium" | "low" {
  const lower = scope.toLowerCase().trim();
  if (SHADOW_IT_CRITICAL_SCOPES.has(lower)) return "critical";
  if (SHADOW_IT_HIGH_SCOPES.has(lower)) return "high";
  if (SHADOW_IT_MEDIUM_SCOPES.has(lower)) return "medium";
  if (SHADOW_IT_LOW_SCOPES.has(lower)) return "low";

  if (
    lower.includes("admin.directory") ||
    lower.includes("admin.reports") ||
    lower.includes("cloud-platform")
  ) {
    return lower.includes("readonly") ? "high" : "critical";
  }
  if (lower === "https://mail.google.com/") return "critical";
  if (lower.includes("gmail.")) {
    if (lower.includes("readonly") || lower.includes("metadata")) return "medium";
    return "high";
  }
  if (lower.includes("drive.")) {
    if (lower.includes("readonly") || lower.includes("metadata")) return "medium";
    return "high";
  }
  if (lower.includes("calendar")) {
    return lower.includes("readonly") ? "low" : "medium";
  }
  if (lower.includes("userinfo") || lower === "openid" || lower === "email") {
    return "low";
  }

  return "medium";
}

function computeShadowItOauthRisk(scopes: string[]) {
  const classes = scopes.map(classifyShadowItScope);
  const counts = {
    critical: classes.filter((c) => c === "critical").length,
    high: classes.filter((c) => c === "high").length,
    medium: classes.filter((c) => c === "medium").length,
    low: classes.filter((c) => c === "low").length
  };

  const touchesSensitiveData =
    counts.critical > 0 ||
    counts.high > 0 ||
    scopes.some((scope) => {
      const lower = scope.toLowerCase();
      return (
        lower.includes("gmail") ||
        lower === "https://mail.google.com/" ||
        lower.includes("drive") ||
        lower.includes("admin.directory")
      );
    });

  let criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  let baseScore: number;

  if (counts.critical > 0) {
    criticality = "CRITICAL";
    baseScore = 85 + Math.min(15, counts.critical * 3 + counts.high);
  } else if (counts.high > 0) {
    criticality = "HIGH";
    baseScore = 60 + Math.min(20, counts.high * 4 + counts.medium);
  } else if (counts.medium > 0) {
    criticality = "MEDIUM";
    baseScore = 35 + Math.min(20, counts.medium * 4);
  } else if (counts.low > 0 || scopes.length > 0) {
    criticality = "LOW";
    baseScore = 10 + Math.min(15, scopes.length);
  } else {
    criticality = "LOW";
    baseScore = 5;
  }

  return {
    score: Math.max(0, Math.min(100, baseScore)),
    criticality,
    touchesSensitiveData
  };
}

export async function syncGoogleWorkspaceOauthGrants(input: {
  accessToken: string;
  integrationId: string;
  organizationId: string;
}) {
  let users: GoogleDirectoryUser[] = [];
  try {
    users = await listGoogleWorkspaceUsers({
      accessToken: input.accessToken,
      projection: "basic",
      onlyActive: true
    });
  } catch {
    return {
      scanEnabled: false,
      appCount: 0,
      grantCount: 0
    } satisfies GoogleOauthGrantsInventoryResult;
  }

  logger.info("google.shadow_it_oauth_scan_starting", {
    integrationId: input.integrationId,
    userCount: users.length
  });

  type AggregatedApp = {
    clientId: string;
    displayName: string | null;
    scopes: Set<string>;
    anonymous: boolean;
    nativeApp: boolean;
    grants: Map<
      string,
      {
        userEmail: string;
        userExternalId: string | null;
        userDisplayName: string | null;
        scopes: string[];
        anonymous: boolean;
        nativeApp: boolean;
        observedAt: Date;
      }
    >;
  };

  const apps = new Map<string, AggregatedApp>();
  let sawForbidden = false;
  let observedAnyUser = false;
  let usersWithTokens = 0;
  let totalTokensSeen = 0;
  let usersProcessed = 0;
  const now = new Date();

  const candidates = users.filter(
    (user): user is GoogleDirectoryUser & { primaryEmail: string } =>
      Boolean(user.primaryEmail)
  );
  const CONCURRENCY = 8;
  let cursor = 0;

  async function processOne(user: GoogleDirectoryUser & { primaryEmail: string }) {
    if (sawForbidden) return;
    const email = user.primaryEmail;
    let tokens: GoogleOauthTokenGrant[] = [];
    try {
      tokens = await fetchGoogleUserTokens({
        accessToken: input.accessToken,
        userKey: email
      });
    } catch (error) {
      if ((error as { status?: number })?.status === 403) {
        sawForbidden = true;
        logger.warn("google.shadow_it_oauth_forbidden", {
          integrationId: input.integrationId,
          userEmail: email,
          hint: "Reconnect the Google Workspace integration to grant admin.directory.user.security scope."
        });
      }
      return;
    }

    observedAnyUser = true;
    if (tokens.length > 0) {
      usersWithTokens += 1;
      totalTokensSeen += tokens.length;
    }

    for (const token of tokens) {
      const clientId = (token.clientId ?? "").trim();
      if (!clientId) {
        continue;
      }
      const displayName = (token.displayText ?? "").trim() || null;
      const scopes = Array.isArray(token.scopes) ? token.scopes : [];
      const existing = apps.get(clientId);
      if (!existing) {
        apps.set(clientId, {
          clientId,
          displayName,
          scopes: new Set(scopes),
          anonymous: Boolean(token.anonymous),
          nativeApp: Boolean(token.nativeApp),
          grants: new Map([
            [
              email,
              {
                userEmail: email,
                userExternalId: user.id ?? null,
                userDisplayName:
                  user.name?.fullName ??
                  [user.name?.givenName, user.name?.familyName]
                    .filter(Boolean)
                    .join(" ") ??
                  null,
                scopes,
                anonymous: Boolean(token.anonymous),
                nativeApp: Boolean(token.nativeApp),
                observedAt: now
              }
            ]
          ])
        });
      } else {
        if (!existing.displayName && displayName) {
          existing.displayName = displayName;
        }
        for (const scope of scopes) {
          existing.scopes.add(scope);
        }
        existing.grants.set(email, {
          userEmail: email,
          userExternalId: user.id ?? null,
          userDisplayName:
            user.name?.fullName ??
            [user.name?.givenName, user.name?.familyName]
              .filter(Boolean)
              .join(" ") ??
            null,
          scopes,
          anonymous: Boolean(token.anonymous),
          nativeApp: Boolean(token.nativeApp),
          observedAt: now
        });
      }
    }
  }

  async function worker() {
    while (cursor < candidates.length && !sawForbidden) {
      const idx = cursor++;
      const user = candidates[idx];
      if (!user) continue;
      await processOne(user);
      usersProcessed += 1;
      if (usersProcessed % 25 === 0) {
        logger.info("google.shadow_it_oauth_scan_progress", {
          integrationId: input.integrationId,
          processed: usersProcessed,
          total: candidates.length,
          appsSoFar: apps.size
        });
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, candidates.length) }, () =>
      worker()
    )
  );

  if (sawForbidden || !observedAnyUser) {
    logger.warn("google.shadow_it_oauth_scan_disabled", {
      integrationId: input.integrationId,
      reason: sawForbidden ? "forbidden" : "no_users_observed",
      usersListed: users.length
    });
    return {
      scanEnabled: false,
      appCount: 0,
      grantCount: 0
    } satisfies GoogleOauthGrantsInventoryResult;
  }

  logger.info("google.shadow_it_oauth_scan_complete", {
    integrationId: input.integrationId,
    usersListed: users.length,
    usersWithTokens,
    totalTokensSeen,
    distinctApps: apps.size
  });

  const existingAssets = await prisma.securityAsset.findMany({
    where: {
      organizationId: input.organizationId,
      integrationId: input.integrationId,
      type: "OAUTH_APP",
      labels: { has: "shadow-it" }
    },
    select: { id: true, externalId: true }
  });
  const existingByClientId = new Map(
    existingAssets
      .filter((asset) => asset.externalId)
      .map((asset) => [asset.externalId as string, asset])
  );

  let totalGrants = 0;
  const observedClientIds = new Set<string>();

  for (const app of apps.values()) {
    observedClientIds.add(app.clientId);
    const scopes = Array.from(app.scopes);
    const risk = computeShadowItOauthRisk(scopes);
    const displayLabel = (app.displayName ?? app.clientId).slice(0, 180);
    const summary =
      `${app.grants.size} user${app.grants.size === 1 ? "" : "s"} authorized · ` +
      `${scopes.length} scope${scopes.length === 1 ? "" : "s"}`;
    const labels = Array.from(
      new Set([
        "shadow-it",
        "oauth",
        "google-workspace",
        "user-granted",
        app.nativeApp ? "native-app" : "web-app"
      ])
    );
    const assetData = {
      name: displayLabel,
      summary,
      labels,
      criticality: risk.criticality,
      exposureLevel: "TRUSTED_EXTERNAL" as const,
      containsSensitiveData: risk.touchesSensitiveData,
      isPrivileged: false,
      riskScore: risk.score,
      lastObservedAt: now
    };

    let assetId: string;
    const existing = existingByClientId.get(app.clientId);
    if (existing) {
      const updated = await prisma.securityAsset.update({
        where: { id: existing.id },
        data: assetData,
        select: { id: true }
      });
      assetId = updated.id;
    } else {
      const created = await prisma.securityAsset.create({
        data: {
          organizationId: input.organizationId,
          integrationId: input.integrationId,
          type: "OAUTH_APP",
          provider: "GOOGLE_WORKSPACE",
          externalId: app.clientId,
          ...assetData
        },
        select: { id: true }
      });
      assetId = created.id;
    }

    const grantOps = Array.from(app.grants.values()).map((grant) =>
      prisma.oauthAppGrant.upsert({
        where: {
          organizationId_integrationId_externalAppId_userEmail: {
            organizationId: input.organizationId,
            integrationId: input.integrationId,
            externalAppId: app.clientId,
            userEmail: grant.userEmail
          }
        },
        update: {
          assetId,
          appDisplayName: app.displayName,
          userExternalId: grant.userExternalId,
          userDisplayName: grant.userDisplayName,
          scopes: grant.scopes,
          anonymous: grant.anonymous,
          nativeApp: grant.nativeApp,
          lastObservedAt: grant.observedAt
        },
        create: {
          organizationId: input.organizationId,
          integrationId: input.integrationId,
          assetId,
          provider: "GOOGLE_WORKSPACE",
          externalAppId: app.clientId,
          appDisplayName: app.displayName,
          userEmail: grant.userEmail,
          userExternalId: grant.userExternalId,
          userDisplayName: grant.userDisplayName,
          scopes: grant.scopes,
          anonymous: grant.anonymous,
          nativeApp: grant.nativeApp,
          lastObservedAt: grant.observedAt
        }
      })
    );
    if (grantOps.length > 0) {
      await prisma.$transaction(grantOps);
      totalGrants += grantOps.length;
    }

    await prisma.oauthAppGrant.deleteMany({
      where: {
        organizationId: input.organizationId,
        integrationId: input.integrationId,
        externalAppId: app.clientId,
        userEmail: { notIn: Array.from(app.grants.keys()) }
      }
    });
  }

  if (observedClientIds.size === 0 && existingAssets.length > 0) {
    await prisma.oauthAppGrant.deleteMany({
      where: {
        organizationId: input.organizationId,
        integrationId: input.integrationId
      }
    });
  } else {
    const orphanedAssetIds = existingAssets
      .filter(
        (asset) => asset.externalId && !observedClientIds.has(asset.externalId)
      )
      .map((asset) => asset.id);
    if (orphanedAssetIds.length > 0) {
      await prisma.oauthAppGrant.deleteMany({
        where: { assetId: { in: orphanedAssetIds } }
      });
      await prisma.securityAsset.deleteMany({
        where: { id: { in: orphanedAssetIds } }
      });
    }
  }

  return {
    scanEnabled: true,
    appCount: apps.size,
    grantCount: totalGrants
  } satisfies GoogleOauthGrantsInventoryResult;
}

function googleAdminEmailFromIntegration(integration: {
  organizationId: string;
  provider: string;
  externalAccountId: string;
  encryptedRefreshToken: string | null;
}) {
  if (!integration.encryptedRefreshToken) {
    return null;
  }

  return decryptString(
    integration.encryptedRefreshToken,
    aadForIntegration({
      organizationId: integration.organizationId,
      provider: integration.provider,
      externalAccountId: integration.externalAccountId,
      suffix: "refresh_token"
    })
  );
}

function mapGoogleActivitiesToPayloads(input: {
  integrationId: string;
  organizationId: string;
  externalAccountId: string;
  activitiesByApplication: Array<{
    application: string;
    activities: GoogleReportActivity[];
  }>;
}) {
  return input.activitiesByApplication
    .flatMap(({ application, activities }) =>
      activities.flatMap((activity) =>
        (activity.events ?? []).map((event) => {
          const parameters = googleParametersToObject(event.parameters);
          return {
            integrationId: input.integrationId,
            organizationId: input.organizationId,
            provider: "GOOGLE_WORKSPACE" as const,
            eventType: classifyGoogleEvent({
              application,
              event,
              parameters
            }),
            source: `google_workspace.reports.${application}`,
            actor:
              activity.actor?.email ??
              activity.actor?.key ??
              activity.actor?.profileId,
            occurredAt: new Date(activity.id?.time ?? Date.now()),
            payload: {
              provider: "GOOGLE_WORKSPACE",
              application,
              ownerDomain: activity.ownerDomain ?? input.externalAccountId,
              ipAddress: activity.ipAddress ?? null,
              actor: activity.actor ?? null,
              event: {
                name: event.name ?? null,
                type: event.type ?? null
              },
              parameters,
              reportId: activity.id ?? null
            }
          };
        })
      )
    )
    .sort((left, right) => left.occurredAt.getTime() - right.occurredAt.getTime());
}

const googleMailboxStateRuleIds = [
  "google_workspace.email_forwarding_enabled",
  "google_workspace.mailbox_delegation_granted",
  "google_workspace.forwarding_delegate_send_as_combo"
] as const;
const googleAdminStateRuleIds = [
  "google_workspace.admin_mfa_not_enforced",
  "google_workspace.admin_external_recovery_email"
] as const;

async function autoCloseMissingFindings(input: {
  organizationId: string;
  integrationId: string;
  observedByRule: Map<string, Set<string>>;
  stateVerifiedRuleIds: Set<string>;
}) {
  const openFindings = await prisma.securityFinding.findMany({
    where: {
      organizationId: input.organizationId,
      integrationId: input.integrationId,
      status: "OPEN"
    },
    select: {
      id: true,
      dedupeKey: true,
      evidence: true
    }
  });

  const staleFindings = openFindings.filter((finding) => {
    const evidence =
      finding.evidence && typeof finding.evidence === "object"
        ? (finding.evidence as Record<string, unknown>)
        : {};
    const ruleId = typeof evidence.ruleId === "string" ? evidence.ruleId : null;

    if (ruleId === null || !input.stateVerifiedRuleIds.has(ruleId)) {
      return false;
    }

    return !input.observedByRule.get(ruleId)?.has(finding.dedupeKey);
  });

  if (staleFindings.length === 0) {
    return 0;
  }

  await prisma.$transaction([
    prisma.securityFinding.updateMany({
      where: {
        id: { in: staleFindings.map((finding) => finding.id) }
      },
      data: {
        status: "RESOLVED",
        resolvedAt: new Date(),
        resolvedById: null
      }
    }),
    prisma.tenantAuditLog.createMany({
      data: staleFindings.map((finding) => ({
        organizationId: input.organizationId,
        actorUserId: null,
        action: "finding.auto_close",
        targetType: "security_finding",
        targetId: finding.id,
        metadata: {
          reason: "Issue not observed in latest provider sync",
          previousStatus: "OPEN"
        }
      }))
    })
  ]);

  await Promise.all(
    staleFindings.map(async (finding) =>
      publishAperioEvent(
        await encodeFindingLifecycleEvent({
          findingId: finding.id,
          organizationId: input.organizationId,
          integrationId: input.integrationId,
          previousStatus: "OPEN",
          nextStatus: "RESOLVED",
          actorUserId: null,
          statusSource: "system",
          occurredAt: new Date(),
          resolutionNote: "Issue not observed in latest provider sync"
        })
      )
    )
  );

  return staleFindings.length;
}

async function ingestGoogleWorkspaceEvents(integration: {
  id: string;
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  externalAccountId: string;
  encryptedAccessToken: string;
  googleMailboxScanClientEmail: string | null;
  encryptedGoogleMailboxScanPrivateKey: string | null;
  lastSyncAt: Date | null;
}) {
  const refreshToken = decryptString(
    integration.encryptedAccessToken,
    aadForIntegration({
      organizationId: integration.organizationId,
      provider: integration.provider,
      externalAccountId: integration.externalAccountId,
      suffix: "access_token"
    })
  );
  const accessToken = await refreshGoogleAccessToken(refreshToken);
  const startTime = googleSyncStart(integration.lastSyncAt);
  const endTime = new Date().toISOString();
  const applications = ["login", "admin", "drive", "token", "gmail"] as const;
  const activitiesByApplication = await Promise.all(
    applications.map(async (application) => ({
      application,
      activities: await fetchGoogleReportActivities({
        accessToken,
        application,
        startTime,
        endTime
      })
    }))
  );
  const auditPayloads = mapGoogleActivitiesToPayloads({
    integrationId: integration.id,
    organizationId: integration.organizationId,
    externalAccountId: integration.externalAccountId,
    activitiesByApplication
  });
  await syncGoogleWorkspacePrivilegedIdentities({
    accessToken,
    integrationId: integration.id,
    organizationId: integration.organizationId
  });
  const adminPostureInventory = await scanGoogleWorkspaceAdminPosture({
    accessToken,
    integrationId: integration.id,
    organizationId: integration.organizationId,
    externalAccountId: integration.externalAccountId
  });
  const forwardingInventory = await scanGoogleWorkspaceMailboxForwarding({
    accessToken,
    integrationId: integration.id,
    organizationId: integration.organizationId,
    externalAccountId: integration.externalAccountId,
    googleMailboxScanClientEmail: integration.googleMailboxScanClientEmail,
    encryptedGoogleMailboxScanPrivateKey:
      integration.encryptedGoogleMailboxScanPrivateKey
  });
  const dwdInventory = await scanGoogleWorkspaceDomainWideDelegations({
    accessToken,
    integrationId: integration.id,
    organizationId: integration.organizationId
  });
  let oauthGrantsInventory: GoogleOauthGrantsInventoryResult = {
    scanEnabled: false,
    appCount: 0,
    grantCount: 0
  };
  try {
    oauthGrantsInventory = await syncGoogleWorkspaceOauthGrants({
      accessToken,
      integrationId: integration.id,
      organizationId: integration.organizationId
    });
  } catch (error) {
    logger.error("google.shadow_it_oauth_scan_failed", {
      integrationId: integration.id,
      error: error instanceof Error ? error.message : String(error)
    });
  }
  const payloads = [
    ...auditPayloads,
    ...adminPostureInventory.payloads,
    ...forwardingInventory.payloads
  ].sort((left, right) => left.occurredAt.getTime() - right.occurredAt.getTime());

  const eventsBefore = await prisma.ingestedEvent.count({
    where: {
      organizationId: integration.organizationId,
      integrationId: integration.id
    }
  });

  const worker = new IngestionWorker();
  const observedByRule = new Map<string, Set<string>>();
  const recordObservation = (ruleId: string, dedupeKey: string) => {
    let bucket = observedByRule.get(ruleId);
    if (!bucket) {
      bucket = new Set<string>();
      observedByRule.set(ruleId, bucket);
    }
    bucket.add(dedupeKey);
  };
  let reopenedOrOpenedCount = 0;

  for (const payload of payloads) {
    const result = await worker.process(payload);
    for (const finding of result.findings) {
      recordObservation(finding.ruleId, finding.dedupeKey);
      if (finding.outcome === "created" || finding.outcome === "reopened") {
        reopenedOrOpenedCount += 1;
      }
    }
  }

  const stateVerifiedRuleIds = new Set<string>();
  if (forwardingInventory.scanEnabled) {
    for (const ruleId of googleMailboxStateRuleIds) {
      stateVerifiedRuleIds.add(ruleId);
    }
  }
  if (adminPostureInventory.scanEnabled) {
    for (const ruleId of googleAdminStateRuleIds) {
      stateVerifiedRuleIds.add(ruleId);
    }
  }

  const autoClosed = await autoCloseMissingFindings({
    organizationId: integration.organizationId,
    integrationId: integration.id,
    observedByRule,
    stateVerifiedRuleIds
  });

  if (payloads.length === 0) {
    await prisma.integrationConnection.update({
      where: { id: integration.id },
      data: { lastSyncAt: new Date(), status: "CONNECTED" }
    });

    return {
      eventsIngested: 0,
      findingsOpened: 0,
      sampleCount: 0,
      autoClosed,
      sources: [
        ...activitiesByApplication
          .filter(({ activities }) => activities.length > 0)
          .map(({ application }) => application),
        ...(adminPostureInventory.scanEnabled ? ["directory_users"] : []),
        ...(forwardingInventory.scanEnabled ? ["gmail_settings"] : []),
        ...(dwdInventory.scanEnabled ? ["domain_wide_delegations"] : []),
        ...(oauthGrantsInventory.scanEnabled ? ["user_oauth_grants"] : [])
      ]
    } satisfies GoogleForceSyncResult;
  }

  const eventsAfter = await prisma.ingestedEvent.count({
    where: {
      organizationId: integration.organizationId,
      integrationId: integration.id
    }
  });

  return {
    eventsIngested: Math.max(0, eventsAfter - eventsBefore),
    findingsOpened: reopenedOrOpenedCount,
    sampleCount: payloads.length,
    autoClosed,
    sources: [
      ...activitiesByApplication
        .filter(({ activities }) => activities.length > 0)
        .map(({ application }) => application),
      ...(adminPostureInventory.scanEnabled ? ["directory_users"] : []),
      ...(forwardingInventory.scanEnabled ? ["gmail_settings"] : []),
      ...(dwdInventory.scanEnabled ? ["domain_wide_delegations"] : []),
      ...(oauthGrantsInventory.scanEnabled ? ["user_oauth_grants"] : [])
    ]
  } satisfies GoogleForceSyncResult;
}

async function upsertManagedIntegration(input: {
  tenantReq: TenantRequest;
  connector: ResolvedConnector;
  provider: "GOOGLE_WORKSPACE";
  externalAccountId: string;
  displayName: string;
  mode: "READ_ONLY" | "REMEDIATION";
  credentials: {
    accessToken: string;
    refreshToken?: string | null;
  };
  metadata?: Record<string, unknown>;
  requestIp?: string | null;
}) {
  const aad = (suffix: string) =>
    aadForIntegration({
      organizationId: input.tenantReq.tenantId,
      provider: input.provider,
      externalAccountId: input.externalAccountId,
      suffix
    });

  return prisma.$transaction(async (tx) => {
    const existing = await tx.integrationConnection.findUnique({
      where: {
        organizationId_provider_externalAccountId: {
          organizationId: input.tenantReq.tenantId,
          provider: input.provider,
          externalAccountId: input.externalAccountId
        }
      },
      select: { id: true }
    });

    const integration = existing
      ? await tx.integrationConnection.update({
          where: { id: existing.id },
          data: {
            displayName: input.displayName,
            scopes: scopesForMode(input.connector, input.mode),
            disabledChecks: defaultDisabledChecks(input.connector),
            mode: input.mode,
            encryptedAccessToken: encryptString(
              input.credentials.accessToken,
              aad("access_token")
            ),
            encryptedRefreshToken: input.credentials.refreshToken
              ? encryptString(input.credentials.refreshToken, aad("refresh_token"))
              : null,
            status: "CONNECTED"
          },
          select: {
            id: true,
            provider: true,
            displayName: true,
            externalAccountId: true,
            status: true,
            mode: true,
            scopes: true,
            disabledChecks: true,
            lastSyncAt: true,
            createdAt: true
          }
        })
      : await tx.integrationConnection.create({
          data: {
            organizationId: input.tenantReq.tenantId,
            provider: input.provider,
            displayName: input.displayName,
            externalAccountId: input.externalAccountId,
            scopes: scopesForMode(input.connector, input.mode),
            disabledChecks: defaultDisabledChecks(input.connector),
            mode: input.mode,
            encryptedAccessToken: encryptString(
              input.credentials.accessToken,
              aad("access_token")
            ),
            encryptedRefreshToken: input.credentials.refreshToken
              ? encryptString(input.credentials.refreshToken, aad("refresh_token"))
              : null,
            tokenKeyVersion: "v1",
            status: "CONNECTED"
          },
          select: {
            id: true,
            provider: true,
            displayName: true,
            externalAccountId: true,
            status: true,
            mode: true,
            scopes: true,
            disabledChecks: true,
            lastSyncAt: true,
            createdAt: true
          }
        });

    if (!existing) {
      await tx.securityAsset.create({
        data: {
          organizationId: input.tenantReq.tenantId,
          integrationId: integration.id,
          ownerUserId: input.tenantReq.auth.userId,
          type: "APPLICATION",
          provider: integration.provider,
          name: integration.displayName,
          summary: `${integration.provider.replace(/_/g, " ")} control plane`,
          externalId: integration.externalAccountId,
          labels: ["integration", integration.mode.toLowerCase()],
          criticality: "HIGH",
          exposureLevel: "INTERNAL",
          ownershipStatus: "ASSIGNED",
          containsSensitiveData: false,
          isPrivileged: integration.mode === "REMEDIATION",
          riskScore: integration.mode === "REMEDIATION" ? 55 : 35
        }
      });
    }

    await tx.tenantAuditLog.create({
      data: {
        organizationId: input.tenantReq.tenantId,
        actorUserId: input.tenantReq.auth.userId,
        action: existing ? "integration.oauth.reconnect" : "integration.oauth.connect",
        targetType: "integration_connection",
        targetId: integration.id,
        ipAddress: input.requestIp ?? undefined,
        metadata: {
          provider: integration.provider,
          displayName: integration.displayName,
          externalAccountId: integration.externalAccountId,
          mode: integration.mode,
          ...(input.metadata ?? {})
        }
      }
    });

    return integration;
  });
}

const listCatalog: RequestHandler = (_req, res: Response) => {
  res.json({
    data: connectorCatalog.map((connector) => ({
      provider: connector.provider,
      name: connector.name,
      category: connector.category,
      availability: connector.availability,
      readinessNote: connector.readinessNote,
      description: connector.description,
      readScopes: connector.readScopes,
      remediationScopes: connector.remediationScopes,
      remediationActions: connector.remediationActions,
      findingChecks: connector.findingChecks,
      docsUrl: connector.docsUrl,
      fields: connector.fields
    }))
  });
};

const listIntegrations: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const integrations = await prisma.integrationConnection.findMany({
      where: { organizationId: tenantReq.tenantId },
      orderBy: [{ createdAt: "desc" }],
      select: {
        id: true,
        provider: true,
        displayName: true,
        externalAccountId: true,
        status: true,
        mode: true,
        scopes: true,
        disabledChecks: true,
        googleMailboxScanClientEmail: true,
        encryptedGoogleMailboxScanPrivateKey: true,
        lastSyncAt: true,
        createdAt: true
      }
    });

    return res.json({
      data: integrations.map((integration) =>
        serializeIntegration({
          ...integration,
          googleMailboxScanEnabled: Boolean(
            integration.googleMailboxScanClientEmail &&
              integration.encryptedGoogleMailboxScanPrivateKey
          )
        })
      )
    });
  } catch (error) {
    return next(error);
  }
};

const googleMailboxScanSchema = z
  .object({
    enabled: z.boolean(),
    serviceAccountClientEmail: z.string().trim().email().optional(),
    privateKey: z.string().trim().min(1).optional()
  })
  .strict();

const getGoogleMailboxScanConfig: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const integrationId = req.params.id;

  if (!integrationId) {
    return res.status(400).json({ error: "Integration id is required" });
  }

  try {
    const integration = await prisma.integrationConnection.findFirst({
      where: { id: integrationId, organizationId: tenantReq.tenantId },
      select: {
        id: true,
        provider: true,
        googleMailboxScanClientEmail: true,
        encryptedGoogleMailboxScanPrivateKey: true
      }
    });

    if (!integration) {
      return res.status(404).json({ error: "Integration not found" });
    }

    if (integration.provider !== "GOOGLE_WORKSPACE") {
      return res.status(400).json({
        error: "Mailbox scan configuration is only supported for Google Workspace"
      });
    }

    return res.json({
      data: {
        enabled: Boolean(
          integration.googleMailboxScanClientEmail &&
            integration.encryptedGoogleMailboxScanPrivateKey
        ),
        serviceAccountClientEmail: integration.googleMailboxScanClientEmail
      }
    });
  } catch (error) {
    return next(error);
  }
};

const updateGoogleMailboxScanConfig: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const integrationId = req.params.id;

  if (!integrationId) {
    return res.status(400).json({ error: "Integration id is required" });
  }

  const parsed = googleMailboxScanSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "Invalid mailbox scan payload",
      details: parsed.error.flatten()
    });
  }

  try {
    const integration = await prisma.integrationConnection.findFirst({
      where: { id: integrationId, organizationId: tenantReq.tenantId },
      select: {
        id: true,
        organizationId: true,
        provider: true,
        externalAccountId: true,
        googleMailboxScanClientEmail: true,
        encryptedGoogleMailboxScanPrivateKey: true,
        encryptedRefreshToken: true
      }
    });

    if (!integration) {
      return res.status(404).json({ error: "Integration not found" });
    }

    if (integration.provider !== "GOOGLE_WORKSPACE") {
      return res.status(400).json({
        error: "Mailbox scan configuration is only supported for Google Workspace"
      });
    }

    if (!parsed.data.enabled) {
      const updated = await prisma.$transaction(async (tx) => {
        const result = await tx.integrationConnection.update({
          where: { id: integration.id },
          data: {
            googleMailboxScanClientEmail: null,
            encryptedGoogleMailboxScanPrivateKey: null
          },
          select: {
            googleMailboxScanClientEmail: true
          }
        });

        await tx.tenantAuditLog.create({
          data: {
            organizationId: tenantReq.tenantId,
            actorUserId: tenantReq.auth.userId,
            action: "integration.google_mailbox_scan.disable",
            targetType: "integration_connection",
            targetId: integration.id,
            ipAddress: req.ip
          }
        });

        return result;
      });

      return res.json({
        data: {
          enabled: false,
          serviceAccountClientEmail: updated.googleMailboxScanClientEmail
        }
      });
    }

    const nextClientEmail =
      parsed.data.serviceAccountClientEmail?.trim() ??
      integration.googleMailboxScanClientEmail ??
      null;

    if (!nextClientEmail) {
      return res.status(400).json({
        error: "Service account client email is required to enable mailbox scanning"
      });
    }

    const existingPrivateKey =
      integration.googleMailboxScanClientEmail === nextClientEmail &&
      integration.encryptedGoogleMailboxScanPrivateKey
        ? decryptString(
            integration.encryptedGoogleMailboxScanPrivateKey,
            googleMailboxScanAad(integration)
          )
        : null;

    const nextPrivateKey = parsed.data.privateKey?.trim() || existingPrivateKey;

    if (!nextPrivateKey) {
      return res.status(400).json({
        error: "Private key is required when enabling mailbox scanning"
      });
    }

    const adminEmail = googleAdminEmailFromIntegration(integration);

    if (!adminEmail) {
      return res.status(400).json({
        error: "Google admin email could not be recovered for this integration"
      });
    }

    await fetchGoogleServiceAccountAccessToken({
      clientEmail: nextClientEmail,
      privateKey: nextPrivateKey,
      subject: adminEmail,
      scopes: ["https://www.googleapis.com/auth/gmail.settings.basic"]
    });

    const updated = await prisma.$transaction(async (tx) => {
      const result = await tx.integrationConnection.update({
        where: { id: integration.id },
        data: {
          googleMailboxScanClientEmail: nextClientEmail,
          encryptedGoogleMailboxScanPrivateKey: encryptString(
            nextPrivateKey,
            googleMailboxScanAad(integration)
          )
        },
        select: {
          googleMailboxScanClientEmail: true
        }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "integration.google_mailbox_scan.enable",
          targetType: "integration_connection",
          targetId: integration.id,
          ipAddress: req.ip,
          metadata: {
            serviceAccountClientEmail: nextClientEmail
          }
        }
      });

      return result;
    });

    return res.json({
      data: {
        enabled: true,
        serviceAccountClientEmail: updated.googleMailboxScanClientEmail
      }
    });
  } catch (error) {
    return next(error);
  }
};

const googleOauthStartSchema = z
  .object({
    mode: z.enum(["READ_ONLY", "REMEDIATION"]).default("READ_ONLY")
  })
  .strict();

const startGoogleWorkspaceOauth: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = googleOauthStartSchema.safeParse({
      mode:
        typeof req.body?.mode === "string"
          ? req.body.mode
          : typeof req.query.mode === "string"
            ? req.query.mode
            : "READ_ONLY"
    });

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid Google Workspace OAuth payload",
        details: parsed.error.flatten()
      });
    }

    const connector = findConnector("GOOGLE_WORKSPACE");

    if (!connector) {
      return res.status(404).json({ error: "Unsupported connector" });
    }

    const config = googleOauthConfig();

    if (!config) {
      return connectorUnavailable(res);
    }

    const state = encodeStateToken({
      organizationId: tenantReq.tenantId,
      userId: tenantReq.auth.userId,
      role: tenantReq.auth.role,
      mode: parsed.data.mode,
      exp: Math.floor(Date.now() / 1000) + 10 * 60
    });

    const scopes = [
      "openid",
      "email",
      "profile",
      ...scopesForMode(connector, parsed.data.mode)
    ];

    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("include_granted_scopes", "true");
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("state", state);

    return res.json({
      data: {
        url: url.toString()
      }
    });
  } catch (error) {
    return next(error);
  }
};

const googleWorkspaceOauthCallback: RequestHandler = async (
  req,
  res: Response,
  _next: NextFunction
) => {
  try {
    const code = typeof req.query.code === "string" ? req.query.code : null;
    const stateToken =
      typeof req.query.state === "string" ? req.query.state : null;
    const callbackError =
      typeof req.query.error === "string" ? req.query.error : null;
    const config = googleOauthConfig();
    const fallbackOrigin =
      config?.webOrigin ??
      (process.env.APERIO_WEB_ORIGIN ?? "http://localhost:3000").replace(/\/$/, "");

    if (callbackError) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent(callbackError)}`
      );
    }

    if (!code || !stateToken) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent("Missing OAuth callback parameters")}`
      );
    }

    if (!config) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent("Google Workspace OAuth is not configured")}`
      );
    }

    const state = decodeStateToken(stateToken);
    const connector = findConnector("GOOGLE_WORKSPACE");

    if (!connector) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent("Unsupported connector")}`
      );
    }

    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        code,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectUri,
        grant_type: "authorization_code"
      })
    });

    if (!tokenResponse.ok) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent("Unable to exchange Google authorization code")}`
      );
    }

    const tokens = (await tokenResponse.json()) as {
      access_token?: string;
      refresh_token?: string;
      id_token?: string;
    };

    if (!tokens.refresh_token || !tokens.id_token) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent("Google did not return an offline refresh token")}`
      );
    }

    const identity = decodeJwtPayload(tokens.id_token);
    const adminEmail = identity.email?.trim().toLowerCase();
    const hostedDomain =
      identity.hd?.trim().toLowerCase() ??
      adminEmail?.split("@")[1]?.trim().toLowerCase();

    if (!adminEmail || !hostedDomain) {
      return res.redirect(
        `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent("Unable to determine the Google Workspace admin identity")}`
      );
    }

    const tenantReq = {
      tenantId: state.organizationId,
      auth: {
        userId: state.userId,
        organizationId: state.organizationId,
        role: state.role,
        sessionId: null,
        sessionToken: ""
      }
    } as TenantRequest;

    await upsertManagedIntegration({
      tenantReq,
      connector,
      provider: "GOOGLE_WORKSPACE",
      externalAccountId: hostedDomain,
      displayName: `Google Workspace – ${hostedDomain}`,
      mode: state.mode,
      credentials: {
        accessToken: tokens.refresh_token,
        refreshToken: adminEmail
      },
      metadata: {
        oauth: true,
        adminEmail
      },
      requestIp: req.ip
    });

    return res.redirect(
      `${fallbackOrigin}/connectors?google_connect=success&provider=google-workspace`
    );
  } catch (error) {
    const fallbackOrigin = (
      process.env.APERIO_WEB_ORIGIN ?? "http://localhost:3000"
    ).replace(/\/$/, "");
    return res.redirect(
      `${fallbackOrigin}/connectors?google_connect=error&message=${encodeURIComponent(
        error instanceof Error ? error.message : "Google Workspace connection failed"
      )}`
    );
  }
};

const createIntegration: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = connectIntegrationSchema.safeParse(req.body);

    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid connector payload", details: parsed.error.flatten() });
    }

    const connector = findConnector(parsed.data.provider);

    if (!connector) {
      return res.status(404).json({ error: "Unsupported connector" });
    }

    if (
      !isConnectorProductionReady(connector) &&
      process.env.APERIO_ALLOW_PREVIEW_CONNECTORS !== "true"
    ) {
      return res.status(403).json({
        error:
          connector.readinessNote ??
          `${connector.name} is still in preview and is not enabled for real customer data.`
      });
    }

    const existing = await prisma.integrationConnection.findUnique({
      where: {
        organizationId_provider_externalAccountId: {
          organizationId: tenantReq.tenantId,
          provider: parsed.data.provider,
          externalAccountId: parsed.data.externalAccountId
        }
      },
      select: { id: true }
    });

    if (existing) {
      return res
        .status(409)
        .json({ error: "Connector already registered for this account" });
    }

    const aad = (suffix: string) =>
      `${tenantReq.tenantId}:${parsed.data.provider}:${parsed.data.externalAccountId}:${suffix}`;

    const integration = await prisma.$transaction(async (tx) => {
      const created = await tx.integrationConnection.create({
        data: {
          organizationId: tenantReq.tenantId,
          provider: parsed.data.provider,
          displayName: parsed.data.displayName,
          externalAccountId: parsed.data.externalAccountId,
          scopes: scopesForMode(connector, parsed.data.mode),
          disabledChecks: defaultDisabledChecks(connector),
          mode: parsed.data.mode,
          encryptedAccessToken: encryptString(
            parsed.data.credentials.accessToken,
            aad("access_token")
          ),
          encryptedRefreshToken: parsed.data.credentials.refreshToken
            ? encryptString(
                parsed.data.credentials.refreshToken,
                aad("refresh_token")
              )
            : null,
          encryptedWebhookSecret: parsed.data.credentials.webhookSecret
            ? encryptString(
                parsed.data.credentials.webhookSecret,
                aad("webhook_secret")
              )
            : null,
          tokenKeyVersion: "v1",
          status: "CONNECTED"
        },
        select: {
          id: true,
          provider: true,
          displayName: true,
          externalAccountId: true,
          status: true,
          mode: true,
          scopes: true,
          disabledChecks: true,
          googleMailboxScanClientEmail: true,
          encryptedGoogleMailboxScanPrivateKey: true,
          createdAt: true,
          lastSyncAt: true
        }
      });

      await tx.securityAsset.create({
        data: {
          organizationId: tenantReq.tenantId,
          integrationId: created.id,
          ownerUserId: tenantReq.auth.userId,
          type: "APPLICATION",
          provider: created.provider,
          name: created.displayName,
          summary: `${created.provider.replace(/_/g, " ")} control plane`,
          externalId: created.externalAccountId,
          labels: ["integration", created.mode.toLowerCase()],
          criticality: "HIGH",
          exposureLevel: "INTERNAL",
          ownershipStatus: "ASSIGNED",
          containsSensitiveData: false,
          isPrivileged: created.mode === "REMEDIATION",
          riskScore: created.mode === "REMEDIATION" ? 55 : 35
        }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "integration.connect",
          targetType: "integration_connection",
          targetId: created.id,
          ipAddress: req.ip,
          metadata: {
            provider: created.provider,
            displayName: created.displayName,
            externalAccountId: created.externalAccountId,
            mode: created.mode
          }
        }
      });

      return created;
    });

    return res.status(201).json({
      data: serializeIntegration({
        ...integration,
        googleMailboxScanEnabled: Boolean(
          integration.googleMailboxScanClientEmail &&
            integration.encryptedGoogleMailboxScanPrivateKey
        )
      })
    });
  } catch (error) {
    return next(error);
  }
};

const deleteIntegration: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const integrationId = req.params.id;

  if (!integrationId) {
    return res.status(400).json({ error: "Integration id is required" });
  }

  try {
    const deleted = await prisma.$transaction(async (tx) => {
      const existing = await tx.integrationConnection.findFirst({
        where: {
          id: integrationId,
          organizationId: tenantReq.tenantId
        },
        select: { id: true, provider: true, displayName: true }
      });

      if (!existing) {
        return null;
      }

      await tx.integrationConnection.delete({ where: { id: existing.id } });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "integration.disconnect",
          targetType: "integration_connection",
          targetId: existing.id,
          ipAddress: req.ip,
          metadata: {
            provider: existing.provider,
            displayName: existing.displayName
          }
        }
      });

      return existing;
    });

    if (!deleted) {
      return res.status(404).json({ error: "Integration not found" });
    }

    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
};

const forceSyncIntegration: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const integrationId = req.params.id;

  if (!integrationId) {
    return res.status(400).json({ error: "Integration id is required" });
  }

  try {
    const integration = await prisma.integrationConnection.findFirst({
      where: {
        id: integrationId,
        organizationId: tenantReq.tenantId
      },
      select: {
        id: true,
        organizationId: true,
        provider: true,
        displayName: true,
        externalAccountId: true,
        status: true,
        mode: true,
        scopes: true,
        disabledChecks: true,
        encryptedAccessToken: true,
        encryptedRefreshToken: true,
        googleMailboxScanClientEmail: true,
        encryptedGoogleMailboxScanPrivateKey: true,
        lastSyncAt: true,
        createdAt: true
      }
    });

    if (!integration) {
      return res.status(404).json({ error: "Integration not found" });
    }

    let result: GoogleForceSyncResult;

    switch (integration.provider) {
      case "GOOGLE_WORKSPACE":
        result = await ingestGoogleWorkspaceEvents({
          id: integration.id,
          organizationId: integration.organizationId,
          provider: integration.provider,
          externalAccountId: integration.externalAccountId,
          encryptedAccessToken: integration.encryptedAccessToken,
          googleMailboxScanClientEmail: integration.googleMailboxScanClientEmail,
          encryptedGoogleMailboxScanPrivateKey:
            integration.encryptedGoogleMailboxScanPrivateKey,
          lastSyncAt: integration.lastSyncAt
        });
        break;
      default:
        return res.status(501).json({
          error: `Force sync is not implemented for ${integration.provider.replace(/_/g, " ")} yet`
        });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const nextIntegration = await tx.integrationConnection.update({
        where: { id: integration.id },
        data: {
          status: "CONNECTED"
        },
        select: {
          id: true,
          provider: true,
          displayName: true,
          externalAccountId: true,
          status: true,
          mode: true,
          scopes: true,
          disabledChecks: true,
          googleMailboxScanClientEmail: true,
          encryptedGoogleMailboxScanPrivateKey: true,
          lastSyncAt: true,
          createdAt: true
        }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "integration.force_sync",
          targetType: "integration_connection",
          targetId: integration.id,
          ipAddress: req.ip,
          metadata: {
            provider: integration.provider,
            sampleCount: result.sampleCount,
            eventsIngested: result.eventsIngested,
            findingsOpened: result.findingsOpened,
            autoClosed: result.autoClosed,
            sources: result.sources
          }
        }
      });

      return nextIntegration;
    });

    return res.json({
      data: serializeIntegration({
        ...updated,
        googleMailboxScanEnabled: Boolean(
          updated.googleMailboxScanClientEmail &&
            updated.encryptedGoogleMailboxScanPrivateKey
        )
      }),
      sync: result
    });
  } catch (error) {
    return next(error);
  }
};

const updateChecksSchema = z.object({
  disabledChecks: z.array(z.string().min(1).max(120)).max(100)
});

const getChecks: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const integrationId = req.params.id;
  if (!integrationId) {
    return res.status(400).json({ error: "Integration id is required" });
  }
  try {
    const integration = await prisma.integrationConnection.findFirst({
      where: { id: integrationId, organizationId: tenantReq.tenantId },
      select: { id: true, provider: true, disabledChecks: true }
    });
    if (!integration) {
      return res.status(404).json({ error: "Integration not found" });
    }
    const connector = findConnector(integration.provider);
    if (!connector) {
      return res.status(400).json({ error: "Unsupported connector" });
    }
    return res.json({
      data: {
        integrationId: integration.id,
        disabledChecks: integration.disabledChecks,
        checks: connector.findingChecks.map((check) => ({
          ...check,
          enabled: !integration.disabledChecks.includes(check.key)
        }))
      }
    });
  } catch (error) {
    return next(error);
  }
};

const updateChecks: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const integrationId = req.params.id;
  if (!integrationId) {
    return res.status(400).json({ error: "Integration id is required" });
  }
  const parsed = updateChecksSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid checks payload", details: parsed.error.flatten() });
  }
  try {
    const integration = await prisma.integrationConnection.findFirst({
      where: { id: integrationId, organizationId: tenantReq.tenantId },
      select: { id: true, provider: true, disabledChecks: true }
    });
    if (!integration) {
      return res.status(404).json({ error: "Integration not found" });
    }
    const connector = findConnector(integration.provider);
    if (!connector) {
      return res.status(400).json({ error: "Unsupported connector" });
    }
    const validKeys = new Set(connector.findingChecks.map((c) => c.key));
    const nextDisabled = Array.from(
      new Set(parsed.data.disabledChecks.filter((key) => validKeys.has(key)))
    );

    const updated = await prisma.$transaction(async (tx) => {
      const result = await tx.integrationConnection.update({
        where: { id: integration.id },
        data: { disabledChecks: nextDisabled },
        select: { id: true, disabledChecks: true }
      });
      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "integration.checks.update",
          targetType: "integration_connection",
          targetId: integration.id,
          ipAddress: req.ip,
          metadata: {
            previousDisabled: integration.disabledChecks,
            nextDisabled
          }
        }
      });
      return result;
    });

    return res.json({
      data: {
        integrationId: updated.id,
        disabledChecks: updated.disabledChecks,
        checks: connector.findingChecks.map((check) => ({
          ...check,
          enabled: !updated.disabledChecks.includes(check.key)
        }))
      }
    });
  } catch (error) {
    return next(error);
  }
};

integrationsRouter.get("/catalog", listCatalog);
integrationsRouter.get("/", listIntegrations);
integrationsRouter.post(
  "/google-workspace/oauth/start",
  requireRole(["OWNER", "ADMIN"]),
  startGoogleWorkspaceOauth
);
integrationsRouter.post(
  "/",
  requireRole(["OWNER", "ADMIN"]),
  createIntegration
);
integrationsRouter.get("/:id/checks", getChecks);
integrationsRouter.patch(
  "/:id/checks",
  requireRole(["OWNER", "ADMIN"]),
  updateChecks
);
integrationsRouter.get(
  "/:id/google-mailbox-scan",
  requireRole(["OWNER", "ADMIN"]),
  getGoogleMailboxScanConfig
);
integrationsRouter.patch(
  "/:id/google-mailbox-scan",
  requireRole(["OWNER", "ADMIN"]),
  updateGoogleMailboxScanConfig
);
integrationsRouter.post(
  "/:id/force-sync",
  requireRole(["OWNER", "ADMIN"]),
  forceSyncIntegration
);
integrationsRouter.delete(
  "/:id",
  requireRole(["OWNER", "ADMIN"]),
  deleteIntegration
);
publicIntegrationsRouter.get(
  "/google-workspace/oauth/callback",
  googleWorkspaceOauthCallback
);

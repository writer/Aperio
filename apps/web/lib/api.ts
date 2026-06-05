const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ??
  "http://localhost:4000";

const AUTH_TOKEN_STORAGE_KEY = "aperio.auth.token";

export type TenantRole = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export type AuthSession = {
  token: string;
  user: {
    id: string;
    email: string;
    displayName: string | null;
    mfaEnabled: boolean;
    role: TenantRole;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
  };
};

function authTokenFromStorage() {
  if (typeof window === "undefined") {
    return null;
  }

  return window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY);
}

export function getAuthToken() {
  return authTokenFromStorage();
}

export function setAuthToken(token: string) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token);
}

export function clearAuthToken() {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAuthToken();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {})
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as
      | {
          error?: string;
          details?: {
            formErrors?: string[];
            fieldErrors?: Record<string, string[] | undefined>;
          };
        }
      | null;
    const fieldErrors = Object.values(body?.details?.fieldErrors ?? {})
      .flat()
      .filter((value): value is string => Boolean(value));
    const detailMessage = [...(body?.details?.formErrors ?? []), ...fieldErrors]
      .join(". ")
      .trim();

    throw new Error(
      detailMessage ||
        body?.error ||
        `Request failed with ${response.status}`
    );
  }

  return response.json() as Promise<T>;
}

export type DashboardMetrics = {
  totalRiskScore: number;
  openCriticalFindings: number;
  connectedApps: number;
  eventIngestionRate: number;
};

export type Provider =
  | "GITHUB"
  | "SLACK"
  | "GOOGLE_WORKSPACE"
  | "ONE_PASSWORD"
  | "OKTA"
  | "MICROSOFT_365"
  | "ATLASSIAN";

export type SignupPayload = {
  organizationName: string;
  organizationSlug: string;
  notificationEmail?: string;
  ownerEmail: string;
  ownerDisplayName?: string;
  password: string;
};

export type LoginPayload = {
  organizationSlug: string;
  email: string;
  password: string;
  totpCode?: string;
};

export type Finding = {
  id: string;
  assetId?: string | null;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "OPEN" | "RESOLVED" | "MUTED";
  riskScore: number;
  detectedAt: string;
  resolvedAt?: string | null;
  evidence?: Record<string, unknown>;
  remediationSteps: string[];
  integration: {
    id?: string;
    provider: Provider;
    displayName: string;
  };
};

export type FindingsFilters = {
  severity?: Finding["severity"];
  status?: Finding["status"] | "ALL";
  provider?: Provider;
  integrationId?: string;
  limit?: number;
  cursor?: string;
};

export type ConnectorField = {
  key: string;
  label: string;
  placeholder?: string;
  helper?: string;
  type: "text" | "password" | "url";
  required: boolean;
  secret: boolean;
};

export type IntegrationMode = "READ_ONLY" | "REMEDIATION";

export type RemediationAction = {
  key: string;
  label: string;
  description: string;
  severityHint: "CRITICAL" | "HIGH" | "MEDIUM";
};

export type FindingCheck = {
  key: string;
  title: string;
  description: string;
  severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  defaultEnabled: boolean;
};

export type FindingCheckStatus = FindingCheck & { enabled: boolean };

export type ConnectorDefinition = {
  provider: Provider;
  name: string;
  category: "Identity" | "Productivity" | "Source Control" | "Messaging";
  availability: "production_ready" | "preview";
  readinessNote?: string;
  description: string;
  readScopes: string[];
  remediationScopes: string[];
  remediationActions: RemediationAction[];
  findingChecks: FindingCheck[];
  docsUrl: string;
  fields: ConnectorField[];
};

export type IntegrationConnection = {
  id: string;
  provider: Provider;
  displayName: string;
  externalAccountId: string;
  status: "CONNECTED" | "DISABLED" | "ERROR";
  mode: IntegrationMode;
  scopes: string[];
  disabledChecks: string[];
  googleMailboxScanEnabled: boolean;
  googleMailboxScanClientEmail: string | null;
  lastSyncAt: string | null;
  createdAt: string;
};

export type GoogleMailboxScanConfig = {
  enabled: boolean;
  serviceAccountClientEmail: string | null;
};

export type IntegrationCheckState = {
  integrationId: string;
  disabledChecks: string[];
  checks: FindingCheckStatus[];
};

export type SiemKind =
  | "SPLUNK_HEC"
  | "PANTHER"
  | "PANOPTICON"
  | "ELASTIC"
  | "DATADOG"
  | "GENERIC_WEBHOOK"
  | "JSON_FILE";

export type SiemStream = "FINDINGS" | "EVENTS" | "AUDIT_LOGS";

export type SiemField = {
  key: "endpointUrl" | "token" | "filePath" | "index";
  label: string;
  placeholder?: string;
  helper?: string;
  type: "text" | "password" | "url";
  required: boolean;
  secret: boolean;
};

export type SiemDestinationDefinition = {
  kind: SiemKind;
  name: string;
  vendor: string;
  description: string;
  category: "Cloud SIEM" | "Hosted Search" | "Observability" | "Generic";
  docsUrl: string;
  defaultStreams: SiemStream[];
  fields: SiemField[];
};

export type SiemDestination = {
  id: string;
  kind: SiemKind;
  name: string;
  endpointUrl: string | null;
  filePath: string | null;
  index: string | null;
  streams: SiemStream[];
  status: "ACTIVE" | "PAUSED" | "ERROR";
  lastDeliveryAt: string | null;
  lastError: string | null;
  deliveriesOk: number;
  deliveriesFail: number;
  createdAt: string;
};

export type CreateSiemPayload = {
  kind: SiemKind;
  name: string;
  endpointUrl?: string;
  filePath?: string;
  index?: string;
  token?: string;
  streams: SiemStream[];
};

export type SiemTestResult = {
  destinationId: string;
  ok: boolean;
  message: string;
};

export type ConnectIntegrationPayload = {
  provider: Provider;
  displayName: string;
  externalAccountId: string;
  mode: IntegrationMode;
  credentials: {
    accessToken: string;
    refreshToken?: string;
    webhookSecret?: string;
  };
};

export type RemediationResult = {
  findingId: string;
  action: string;
  success: boolean;
  message: string;
  providerRequestId: string;
  effects: string[];
};

export async function signup(payload: SignupPayload) {
  return request<{ data: AuthSession }>("/api/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function login(payload: LoginPayload) {
  return request<{ data: AuthSession }>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchCurrentSession() {
  return request<{ data: AuthSession }>("/api/v1/auth/me");
}

export async function logoutCurrentSession() {
  return request<{ data: { ok: boolean } }>("/api/v1/auth/logout", {
    method: "POST",
    body: JSON.stringify({})
  });
}

export type WorkspaceMembership = {
  id: string;
  name: string;
  slug: string;
  role: TenantRole;
  current: boolean;
};

export async function fetchWorkspaces() {
  return request<{ data: WorkspaceMembership[] }>("/api/v1/auth/workspaces");
}

export async function switchWorkspace(organizationSlug: string) {
  return request<{ data: AuthSession }>("/api/v1/auth/workspaces/switch", {
    method: "POST",
    body: JSON.stringify({ organizationSlug })
  });
}

export async function requestPasswordReset(payload: {
  organizationSlug: string;
  email: string;
}) {
  return request<{
    data: {
      accepted: boolean;
      delivery?: "manual_link" | "email";
      resetUrl?: string;
      expiresAt?: string;
    };
  }>("/api/v1/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function resetPassword(payload: {
  token: string;
  password: string;
}) {
  return request<{ data: AuthSession }>("/api/v1/auth/reset-password", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function acceptInvite(payload: {
  token: string;
  displayName?: string;
  password: string;
}) {
  return request<{ data: AuthSession }>(
    "/api/v1/auth/invitations/accept",
    {
      method: "POST",
      body: JSON.stringify(payload)
    }
  );
}

export type MfaEnrollment = {
  secret: string;
  otpauthUrl: string;
};

export async function beginMfaEnrollment() {
  return request<{ data: MfaEnrollment }>("/api/v1/auth/mfa/setup", {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function enableMfa(code: string) {
  return request<{ data: AuthSession }>("/api/v1/auth/mfa/enable", {
    method: "POST",
    body: JSON.stringify({ code })
  });
}

export async function disableMfa(payload: {
  password: string;
  code?: string;
}) {
  return request<{ data: AuthSession }>("/api/v1/auth/mfa/disable", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchDashboardMetrics() {
  return request<{ data: DashboardMetrics }>("/api/v1/dashboard/metrics");
}

export async function fetchFindings(filters?: FindingsFilters) {
  const params = new URLSearchParams();
  params.set("limit", String(filters?.limit ?? 50));
  if (!filters || filters.status !== "ALL") {
    params.set("status", filters?.status ?? "OPEN");
  }
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.provider) params.set("provider", filters.provider);
  if (filters?.integrationId) params.set("integrationId", filters.integrationId);
  if (filters?.cursor) params.set("cursor", filters.cursor);
  return request<{
    data: Finding[];
    pageInfo: { total: number; nextCursor: string | null };
  }>(`/api/v1/findings?${params.toString()}`);
}

export async function fetchFinding(id: string) {
  return request<{ data: Finding }>(`/api/v1/findings/${encodeURIComponent(id)}`);
}

export async function updateFindingStatus(
  id: string,
  payload: {
    status: "RESOLVED" | "MUTED";
    resolutionNote?: string;
  }
) {
  return request<{ data: { id: string; status: "RESOLVED" | "MUTED" } }>(
    `/api/v1/findings/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload)
    }
  );
}

export async function resolveFinding(id: string, resolutionNote?: string) {
  return updateFindingStatus(id, {
    status: "RESOLVED",
    resolutionNote:
      resolutionNote ?? "Resolved from the Aperio executive dashboard"
  });
}

export async function acceptFindingRisk(id: string, resolutionNote?: string) {
  return updateFindingStatus(id, {
    status: "MUTED",
    resolutionNote:
      resolutionNote ?? "Risk accepted from the Aperio finding detail page"
  });
}

export async function fetchConnectorCatalog() {
  return request<{ data: ConnectorDefinition[] }>(
    "/api/v1/integrations/catalog"
  );
}

export async function fetchIntegrations() {
  return request<{ data: IntegrationConnection[] }>("/api/v1/integrations");
}

export async function fetchGoogleMailboxScanConfig(integrationId: string) {
  return request<{ data: GoogleMailboxScanConfig }>(
    `/api/v1/integrations/${encodeURIComponent(integrationId)}/google-mailbox-scan`
  );
}

export async function connectIntegration(payload: ConnectIntegrationPayload) {
  return request<{ data: IntegrationConnection }>("/api/v1/integrations", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function updateGoogleMailboxScanConfig(
  integrationId: string,
  payload: {
    enabled: boolean;
    serviceAccountClientEmail?: string;
    privateKey?: string;
  }
) {
  return request<{ data: GoogleMailboxScanConfig }>(
    `/api/v1/integrations/${encodeURIComponent(integrationId)}/google-mailbox-scan`,
    {
      method: "PATCH",
      body: JSON.stringify(payload)
    }
  );
}

export async function startGoogleWorkspaceOAuth(mode: IntegrationMode) {
  return request<{ data: { url: string } }>(
    "/api/v1/integrations/google-workspace/oauth/start",
    {
      method: "POST",
      body: JSON.stringify({ mode })
    }
  );
}

export async function fetchSiemCatalog() {
  return request<{ data: SiemDestinationDefinition[] }>(
    "/api/v1/siem/catalog"
  );
}

export async function fetchSiemDestinations() {
  return request<{ data: SiemDestination[] }>("/api/v1/siem");
}

export async function createSiemDestination(payload: CreateSiemPayload) {
  return request<{ data: SiemDestination }>("/api/v1/siem", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function testSiemDestination(id: string) {
  return request<{ data: SiemTestResult }>(
    `/api/v1/siem/${encodeURIComponent(id)}/test`,
    { method: "POST" }
  );
}

export async function deleteSiemDestination(id: string) {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/siem/${encodeURIComponent(id)}`,
    { method: "DELETE", cache: "no-store" }
  );
  if (!response.ok && response.status !== 204) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string }
      | null;
    throw new Error(body?.error ?? `Request failed with ${response.status}`);
  }
}

export async function fetchIntegrationChecks(integrationId: string) {
  return request<{ data: IntegrationCheckState }>(
    `/api/v1/integrations/${encodeURIComponent(integrationId)}/checks`
  );
}

export async function updateIntegrationChecks(
  integrationId: string,
  disabledChecks: string[]
) {
  return request<{ data: IntegrationCheckState }>(
    `/api/v1/integrations/${encodeURIComponent(integrationId)}/checks`,
    {
      method: "PATCH",
      body: JSON.stringify({ disabledChecks })
    }
  );
}

export async function forceSyncIntegration(integrationId: string) {
  return request<{
    data: IntegrationConnection;
    sync: {
      sampleCount: number;
      eventsIngested: number;
      findingsOpened: number;
      sources: string[];
    };
  }>(`/api/v1/integrations/${encodeURIComponent(integrationId)}/force-sync`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function remediateFinding(
  findingId: string,
  payload: { action: string; targetIdentifier?: string; note?: string }
) {
  return request<{ data: RemediationResult }>(
    `/api/v1/findings/${encodeURIComponent(findingId)}/remediate`,
    {
      method: "POST",
      body: JSON.stringify(payload)
    }
  );
}

export async function disconnectIntegration(id: string) {
  const token = getAuthToken();
  const response = await fetch(
    `${API_BASE_URL}/api/v1/integrations/${encodeURIComponent(id)}`,
    {
      method: "DELETE",
      cache: "no-store",
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {})
      }
    }
  );

  if (!response.ok && response.status !== 204) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string }
      | null;
    throw new Error(body?.error ?? `Request failed with ${response.status}`);
  }
}

export type TenantSettings = {
  id: string;
  name: string;
  slug: string;
  notificationEmail: string | null;
  dataRetentionDays: number;
  criticalRiskThreshold: number;
  defaultSlaHours: number;
  autoResolveLowSeverity: boolean;
  enforceSsoOnly: boolean;
  webhookAlertUrl: string | null;
  createdAt: string;
  updatedAt: string;
};

export type TenantMember = {
  id: string;
  email: string;
  displayName: string | null;
  isActive: boolean;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  isBreakGlass: boolean;
  role: TenantRole;
  authState: "ACTIVE" | "INVITED" | "PASSWORD_RESET_PENDING";
  pendingActionExpiresAt: string | null;
  createdAt: string;
};

export type AuditLogEntry = {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  actor: string;
  createdAt: string;
  metadata: Record<string, unknown> | null;
};

export type SecurityAssetType =
  | "APPLICATION"
  | "OAUTH_APP"
  | "SERVICE_ACCOUNT"
  | "DATA_RESOURCE"
  | "WORKSPACE"
  | "VAULT"
  | "REPOSITORY";

export type AssetCriticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AssetExposureLevel = "INTERNAL" | "TRUSTED_EXTERNAL" | "PUBLIC";
export type AssetOwnershipStatus =
  | "ASSIGNED"
  | "UNASSIGNED"
  | "REVIEW_REQUIRED";
export type RiskExceptionStatus = "ACTIVE" | "EXPIRED" | "REVOKED";

export type SecurityAsset = {
  id: string;
  type: SecurityAssetType;
  provider: Provider | null;
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: AssetCriticality;
  exposureLevel: AssetExposureLevel;
  ownershipStatus: AssetOwnershipStatus;
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  createdAt: string;
  updatedAt: string;
  integration: {
    id: string;
    provider: Provider;
    displayName: string;
  } | null;
  owner: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
  businessOwner: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
  openFindingCount: number;
  activeExceptionCount: number;
};

export type RiskException = {
  id: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: RiskExceptionStatus;
  expiresAt: string | null;
  approvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  asset: {
    id: string;
    name: string;
    type: SecurityAssetType;
  } | null;
  finding: {
    id: string;
    title: string;
    severity: Finding["severity"];
    status: Finding["status"];
  } | null;
  createdBy: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
  approvedBy: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
};

export type SecurityIdentity = {
  id: string;
  entityId: string;
  kind: "USER" | "SERVICE_ACCOUNT" | "BOT";
  name: string;
  email: string | null;
  provider: Provider | null;
  integration: {
    id: string;
    provider: Provider;
    displayName: string;
  } | null;
  role: string;
  privileged: boolean;
  mfaEnabled: boolean | null;
  status: "ACTIVE" | "SUSPENDED" | "DORMANT";
  isExternal: boolean;
  lastObservedAt: string | null;
  linkedAssetCount: number;
  riskScore: number;
};

export type SecurityGraphNode = {
  id: string;
  label: string;
  kind: string;
  riskScore: number;
  privileged: boolean;
  exposureLevel: string;
  criticality: string;
};

export type SecurityGraphEdge = {
  id: string;
  sourceId: string;
  targetId: string;
  relationshipType: string;
};

export type AttackPath = {
  id: string;
  title: string;
  score: number;
  findingTitle: string;
  entryPoint: string;
  target: string;
  owner: string;
  exposureLevel: AssetExposureLevel;
  criticality: AssetCriticality;
  reason: string;
  path: string[];
};

export type DomainWideDelegation = {
  integrationId: string;
  provider: "GOOGLE_WORKSPACE";
  displayName: string;
  workspaceDomain: string;
  serviceAccountClientEmail: string | null;
  scopes: string[];
  status: "ENABLED" | "NOT_CONFIGURED";
  integrationStatus: "CONNECTED" | "DISABLED" | "ERROR";
  mode: "READ_ONLY" | "REMEDIATION";
  openMailboxFindings: number;
  lastSyncAt: string | null;
  configuredAt: string;
};

export type SecurityOverview = {
  summary: {
    privilegedIdentities: number;
    adminIdentitiesWithoutMfa: number;
    riskyOauthApps: number;
    exposedDataAssets: number;
    unownedAssets: number;
    activeExceptions: number;
    topBlastRadiusScore: number;
  };
  identities: SecurityIdentity[];
  graph: {
    nodes: SecurityGraphNode[];
    edges: SecurityGraphEdge[];
  };
  oauthApps: SecurityAsset[];
  dataAssets: SecurityAsset[];
  attackPaths: AttackPath[];
  ownershipGaps: SecurityAsset[];
  exceptions: RiskException[];
  domainWideDelegations?: DomainWideDelegation[];
};

export type CreateSecurityAssetPayload = {
  integrationId?: string;
  ownerUserId?: string;
  businessOwnerUserId?: string;
  type: SecurityAssetType;
  provider?: Provider;
  name: string;
  summary?: string;
  externalId?: string;
  labels: string[];
  criticality: AssetCriticality;
  exposureLevel: AssetExposureLevel;
  ownershipStatus?: AssetOwnershipStatus;
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt?: string;
};

export type UpdateSecurityAssetPayload = Partial<CreateSecurityAssetPayload>;

export type CreateRiskExceptionPayload = {
  assetId?: string;
  findingId?: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  expiresAt?: string;
};

export type UpdateRiskExceptionPayload = Partial<{
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: RiskExceptionStatus;
  expiresAt: string;
}>;

export type TenantSettingsUpdate = Partial<{
  name: string;
  notificationEmail: string;
  dataRetentionDays: number;
  criticalRiskThreshold: number;
  defaultSlaHours: number;
  autoResolveLowSeverity: boolean;
  enforceSsoOnly: boolean;
  webhookAlertUrl: string;
}>;

export async function fetchTenantSettings() {
  return request<{ data: TenantSettings }>("/api/v1/admin/settings");
}

export async function updateTenantSettings(payload: TenantSettingsUpdate) {
  return request<{ data: TenantSettings }>("/api/v1/admin/settings", {
    method: "PATCH",
    body: JSON.stringify(payload)
  });
}

export async function fetchTenantMembers() {
  return request<{ data: TenantMember[] }>("/api/v1/admin/members");
}

export type CreateMemberPayload = {
  email: string;
  displayName?: string;
  roleName: TenantRole;
};

export type InvitationResult = {
  delivery: "manual_link" | "email";
  url?: string;
  expiresAt: string;
};

export async function createTenantMember(payload: CreateMemberPayload) {
  return request<{ data: TenantMember; invitation: InvitationResult }>(
    "/api/v1/admin/members",
    {
      method: "POST",
      body: JSON.stringify(payload)
    }
  );
}

export async function createMemberResetLink(id: string) {
  return request<{ data: TenantMember; reset: InvitationResult }>(
    `/api/v1/admin/members/${encodeURIComponent(id)}/reset-link`,
    {
    method: "POST",
      body: JSON.stringify({})
    }
  );
}

export async function updateMemberRole(id: string, roleName: TenantRole) {
  return request<{ data: TenantMember }>(
    `/api/v1/admin/members/${encodeURIComponent(id)}/role`,
    {
      method: "PATCH",
      body: JSON.stringify({ roleName })
    }
  );
}

export async function fetchAuditLogs() {
  return request<{ data: AuditLogEntry[] }>("/api/v1/admin/audit-logs");
}

export async function fetchSecurityOverview() {
  return request<{ data: SecurityOverview }>("/api/v1/security/overview");
}

export async function fetchSecurityAssets() {
  return request<{ data: SecurityAsset[] }>("/api/v1/security/assets");
}

export async function createSecurityAsset(payload: CreateSecurityAssetPayload) {
  return request<{ data: SecurityAsset }>("/api/v1/security/assets", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function updateSecurityAsset(
  id: string,
  payload: UpdateSecurityAssetPayload
) {
  return request<{ data: SecurityAsset }>(
    `/api/v1/security/assets/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload)
    }
  );
}

export async function fetchRiskExceptions() {
  return request<{ data: RiskException[] }>("/api/v1/security/exceptions");
}

export async function createRiskException(payload: CreateRiskExceptionPayload) {
  return request<{ data: RiskException }>("/api/v1/security/exceptions", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function updateRiskException(
  id: string,
  payload: UpdateRiskExceptionPayload
) {
  return request<{ data: RiskException }>(
    `/api/v1/security/exceptions/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload)
    }
  );
}

export type ShadowItOauthApp = {
  id: string;
  provider: Provider | null;
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: AssetCriticality;
  containsSensitiveData: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  userCount: number;
  scopes: string[];
  integration: {
    id: string;
    provider: Provider;
    displayName: string;
  } | null;
};

export type ShadowItOauthAppGrant = {
  id: string;
  userEmail: string;
  userExternalId: string | null;
  userDisplayName: string | null;
  scopes: string[];
  anonymous: boolean;
  nativeApp: boolean;
  lastObservedAt: string;
};

export type ShadowItOauthAppDetail = {
  app: {
    id: string;
    name: string;
    externalId: string | null;
    provider: Provider | null;
  };
  grants: ShadowItOauthAppGrant[];
};

export async function fetchShadowItOauthApps() {
  return request<{ data: ShadowItOauthApp[] }>("/api/v1/shadow-it/oauth-apps");
}

export async function fetchShadowItOauthAppGrants(assetId: string) {
  return request<{ data: ShadowItOauthAppDetail }>(
    `/api/v1/shadow-it/oauth-apps/${encodeURIComponent(assetId)}/grants`
  );
}

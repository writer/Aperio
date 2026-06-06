import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import {
  AperioService,
  type ConnectorDefinition as ProtoConnectorDefinition,
  type Finding as ProtoFinding,
  type GoogleMailboxScanConfig as ProtoGoogleMailboxScanConfig,
  type IntegrationCheckState as ProtoIntegrationCheckState,
  type IntegrationConnection as ProtoIntegrationConnection,
  type RemediationResult as ProtoRemediationResult,
  type RiskException as ProtoRiskException,
  type SecurityAsset as ProtoSecurityAsset,
  type SiemDestination as ProtoSiemDestination,
  type SiemDestinationDefinition as ProtoSiemDestinationDefinition,
  type ShadowItOauthApp as ProtoShadowItOauthApp,
  type ShadowItOauthAppGrant as ProtoShadowItOauthAppGrant
} from "./gen/aperio/v1/api_pb";

const CONNECT_BASE_URL =
  process.env.NEXT_PUBLIC_CONNECT_API_BASE_URL?.replace(/\/$/, "") ??
  "http://localhost:4100";

export type ConnectDashboardMetrics = {
  totalRiskScore: number;
  openCriticalFindings: number;
  connectedApps: number;
  eventIngestionRate: number;
};

export type ConnectFinding = {
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
    provider:
      | "GITHUB"
      | "SLACK"
      | "GOOGLE_WORKSPACE"
      | "ONE_PASSWORD"
      | "OKTA"
      | "MICROSOFT_365"
      | "ATLASSIAN";
    displayName: string;
  };
};

export type ConnectFindingsFilters = {
  severity?: ConnectFinding["severity"];
  status?: ConnectFinding["status"] | "ALL";
  provider?: ConnectFinding["integration"]["provider"];
  integrationId?: string;
  limit?: number;
  cursor?: string;
};

type ConnectProvider = ConnectFinding["integration"]["provider"];

export type ConnectIntegrationConnection = {
  id: string;
  provider: ConnectProvider;
  displayName: string;
  externalAccountId: string;
  status: "CONNECTED" | "DISABLED" | "ERROR";
  mode: "READ_ONLY" | "REMEDIATION";
  scopes: string[];
  disabledChecks: string[];
  googleMailboxScanEnabled: boolean;
  googleMailboxScanClientEmail: string | null;
  lastSyncAt: string | null;
  createdAt: string;
};

export type ConnectIntegrationPayload = {
  provider: ConnectProvider;
  displayName: string;
  externalAccountId: string;
  mode: "READ_ONLY" | "REMEDIATION";
  credentials: {
    accessToken: string;
    refreshToken?: string;
    webhookSecret?: string;
  };
};

export type ConnectConnectorDefinition = {
  provider: ConnectProvider;
  name: string;
  category: string;
  availability: "production_ready" | "preview";
  readinessNote?: string;
  description: string;
  readScopes: string[];
  remediationScopes: string[];
  remediationActions: {
    key: string;
    label: string;
    description: string;
    severityHint: "CRITICAL" | "HIGH" | "MEDIUM";
  }[];
  findingChecks: {
    key: string;
    title: string;
    description: string;
    severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    defaultEnabled: boolean;
  }[];
  docsUrl: string;
  fields: {
    key: string;
    label: string;
    placeholder?: string;
    helper?: string;
    type: "text" | "password" | "url";
    required: boolean;
    secret: boolean;
  }[];
};

export type ConnectGoogleMailboxScanConfig = {
  enabled: boolean;
  serviceAccountClientEmail: string | null;
};

export type ConnectIntegrationCheckState = {
  integrationId: string;
  disabledChecks: string[];
  checks: {
    key: string;
    title: string;
    description: string;
    severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    defaultEnabled: boolean;
    enabled: boolean;
  }[];
};

export type ConnectSyncSummary = {
  sampleCount: number;
  eventsIngested: number;
  findingsOpened: number;
  sources: string[];
};

export type ConnectSiemDestination = {
  id: string;
  kind: string;
  name: string;
  endpointUrl: string | null;
  filePath: string | null;
  index: string | null;
  streams: string[];
  status: "ACTIVE" | "PAUSED" | "ERROR";
  lastDeliveryAt: string | null;
  lastError: string | null;
  deliveriesOk: number;
  deliveriesFail: number;
  createdAt: string;
};

export type ConnectSiemDestinationDefinition = {
  kind: string;
  name: string;
  vendor: string;
  description: string;
  category: "Cloud SIEM" | "Hosted Search" | "Observability" | "Graph" | "Generic";
  docsUrl: string;
  defaultStreams: string[];
  fields: {
    key: "endpointUrl" | "token" | "filePath" | "index";
    label: string;
    placeholder?: string;
    helper?: string;
    type: "text" | "password" | "url";
    required: boolean;
    secret: boolean;
  }[];
};

export type ConnectCreateSiemPayload = {
  kind: string;
  name: string;
  endpointUrl?: string;
  filePath?: string;
  index?: string;
  token?: string;
  streams: string[];
};

export type ConnectSiemTestResult = {
  destinationId: string;
  ok: boolean;
  message: string;
};

export type ConnectShadowItOauthApp = {
  id: string;
  provider: ConnectProvider | "";
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  containsSensitiveData: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  userCount: number;
  scopes: string[];
  integration: {
    id: string;
    provider: ConnectProvider | "";
    displayName: string;
  } | null;
};

export type ConnectShadowItOauthAppGrant = {
  id: string;
  userEmail: string;
  userExternalId: string | null;
  userDisplayName: string | null;
  scopes: string[];
  anonymous: boolean;
  nativeApp: boolean;
  lastObservedAt: string;
};

export type ConnectShadowItOauthAppDetail = {
  app: {
    id: string;
    name: string;
    externalId: string | null;
    provider: ConnectProvider | "";
  };
  grants: ConnectShadowItOauthAppGrant[];
};

export type ConnectSecurityAsset = {
  id: string;
  type: string;
  provider: ConnectProvider | null;
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  exposureLevel: "PUBLIC" | "PARTNER" | "INTERNAL" | "RESTRICTED";
  ownershipStatus: "ASSIGNED" | "UNASSIGNED" | "REVIEW_REQUIRED";
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  createdAt: string;
  updatedAt: string;
  integration: {
    id: string;
    provider: ConnectProvider;
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

export type ConnectSecurityAssetsFilters = {
  type?: string;
  ownershipStatus?: string;
  integrationId?: string;
};

export type ConnectRiskException = {
  id: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  expiresAt: string | null;
  approvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  asset: {
    id: string;
    name: string;
    type: string;
  } | null;
  finding: {
    id: string;
    title: string;
    severity: ConnectFinding["severity"];
    status: ConnectFinding["status"];
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

export type ConnectRemediationResult = {
  findingId: string;
  action: string;
  success: boolean;
  message: string;
  providerRequestId: string;
  effects: string[];
};

const transport = createConnectTransport({
  baseUrl: CONNECT_BASE_URL,
  fetch(input, init) {
    return fetch(input, {
      ...init,
      credentials: "include",
      cache: "no-store"
    });
  }
});

const client = createClient(AperioService, transport);

function parseEvidence(evidenceJson: string) {
  if (!evidenceJson) {
    return undefined;
  }
  const parsed = JSON.parse(evidenceJson) as unknown;
  return parsed && typeof parsed === "object"
    ? (parsed as Record<string, unknown>)
    : undefined;
}

function findingFromProto(finding: ProtoFinding): ConnectFinding {
  return {
    id: finding.id,
    assetId: finding.assetId || null,
    title: finding.title,
    description: finding.description,
    severity: finding.severity as ConnectFinding["severity"],
    status: finding.status as ConnectFinding["status"],
    riskScore: finding.riskScore,
    remediationSteps: finding.remediationSteps,
    evidence: parseEvidence(finding.evidenceJson),
    detectedAt: finding.detectedAt,
    resolvedAt: finding.resolvedAt || null,
    integration: {
      id: finding.integration?.id,
      provider: (finding.integration?.provider ??
        "") as ConnectFinding["integration"]["provider"],
      displayName: finding.integration?.displayName ?? ""
    }
  };
}

function integrationFromProto(
  integration: ProtoIntegrationConnection
): ConnectIntegrationConnection {
  return {
    id: integration.id,
    provider: integration.provider as ConnectProvider,
    displayName: integration.displayName,
    externalAccountId: integration.externalAccountId,
    status: integration.status as ConnectIntegrationConnection["status"],
    mode: integration.mode as ConnectIntegrationConnection["mode"],
    scopes: integration.scopes,
    disabledChecks: integration.disabledChecks,
    googleMailboxScanEnabled: integration.googleMailboxScanEnabled,
    googleMailboxScanClientEmail:
      integration.googleMailboxScanClientEmail || null,
    lastSyncAt: integration.lastSyncAt || null,
    createdAt: integration.createdAt
  };
}

function connectorDefinitionFromProto(
  definition: ProtoConnectorDefinition
): ConnectConnectorDefinition {
  return {
    provider: definition.provider as ConnectProvider,
    name: definition.name,
    category: definition.category,
    availability: definition.availability as ConnectConnectorDefinition["availability"],
    readinessNote: definition.readinessNote || undefined,
    description: definition.description,
    readScopes: definition.readScopes,
    remediationScopes: definition.remediationScopes,
    remediationActions: definition.remediationActions.map((action) => ({
      key: action.key,
      label: action.label,
      description: action.description,
      severityHint: action.severityHint as "CRITICAL" | "HIGH" | "MEDIUM"
    })),
    findingChecks: definition.findingChecks.map((check) => ({
      key: check.key,
      title: check.title,
      description: check.description,
      severityHint: check.severityHint as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      defaultEnabled: check.defaultEnabled
    })),
    docsUrl: definition.docsUrl,
    fields: definition.fields.map((field) => ({
      key: field.key,
      label: field.label,
      placeholder: field.placeholder || undefined,
      helper: field.helper || undefined,
      type: field.type as "text" | "password" | "url",
      required: field.required,
      secret: field.secret
    }))
  };
}

function googleMailboxScanConfigFromProto(
  config: ProtoGoogleMailboxScanConfig
): ConnectGoogleMailboxScanConfig {
  return {
    enabled: config.enabled,
    serviceAccountClientEmail: config.serviceAccountClientEmail || null
  };
}

function integrationCheckStateFromProto(
  state: ProtoIntegrationCheckState
): ConnectIntegrationCheckState {
  return {
    integrationId: state.integrationId,
    disabledChecks: state.disabledChecks,
    checks: state.checks.map((check) => ({
      key: check.key,
      title: check.title,
      description: check.description,
      severityHint: check.severityHint as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      defaultEnabled: check.defaultEnabled,
      enabled: check.enabled
    }))
  };
}

function siemDestinationFromProto(
  destination: ProtoSiemDestination
): ConnectSiemDestination {
  return {
    id: destination.id,
    kind: destination.kind,
    name: destination.name,
    endpointUrl: destination.endpointUrl || null,
    filePath: destination.filePath || null,
    index: destination.index || null,
    streams: destination.streams,
    status: destination.status as ConnectSiemDestination["status"],
    lastDeliveryAt: destination.lastDeliveryAt || null,
    lastError: destination.lastError || null,
    deliveriesOk: destination.deliveriesOk,
    deliveriesFail: destination.deliveriesFail,
    createdAt: destination.createdAt
  };
}

function siemDefinitionFromProto(
  definition: ProtoSiemDestinationDefinition
): ConnectSiemDestinationDefinition {
  return {
    kind: definition.kind,
    name: definition.name,
    vendor: definition.vendor,
    description: definition.description,
    category: definition.category as ConnectSiemDestinationDefinition["category"],
    docsUrl: definition.docsUrl,
    defaultStreams: definition.defaultStreams,
    fields: definition.fields.map((field) => ({
      key: field.key as "endpointUrl" | "token" | "filePath" | "index",
      label: field.label,
      placeholder: field.placeholder || undefined,
      helper: field.helper || undefined,
      type: field.type as "text" | "password" | "url",
      required: field.required,
      secret: field.secret
    }))
  };
}

function remediationResultFromProto(
  result: ProtoRemediationResult
): ConnectRemediationResult {
  return {
    findingId: result.findingId,
    action: result.action,
    success: result.success,
    message: result.message,
    providerRequestId: result.providerRequestId,
    effects: result.effects
  };
}

function shadowItOauthAppFromProto(
  app: ProtoShadowItOauthApp
): ConnectShadowItOauthApp {
  return {
    id: app.id,
    provider: app.provider as ConnectProvider | "",
    name: app.name,
    summary: app.summary || null,
    externalId: app.externalId || null,
    labels: app.labels,
    criticality: app.criticality as ConnectShadowItOauthApp["criticality"],
    containsSensitiveData: app.containsSensitiveData,
    riskScore: app.riskScore,
    lastObservedAt: app.lastObservedAt || null,
    userCount: app.userCount,
    scopes: app.scopes,
    integration: app.integration
      ? {
          id: app.integration.id,
          provider: app.integration.provider as ConnectProvider | "",
          displayName: app.integration.displayName
        }
      : null
  };
}

function shadowItGrantFromProto(
  grant: ProtoShadowItOauthAppGrant
): ConnectShadowItOauthAppGrant {
  return {
    id: grant.id,
    userEmail: grant.userEmail,
    userExternalId: grant.userExternalId || null,
    userDisplayName: grant.userDisplayName || null,
    scopes: grant.scopes,
    anonymous: grant.anonymous,
    nativeApp: grant.nativeApp,
    lastObservedAt: grant.lastObservedAt
  };
}

function securityAssetFromProto(asset: ProtoSecurityAsset): ConnectSecurityAsset {
  return {
    id: asset.id,
    type: asset.type,
    provider: asset.provider ? (asset.provider as ConnectProvider) : null,
    name: asset.name,
    summary: asset.summary || null,
    externalId: asset.externalId || null,
    labels: asset.labels,
    criticality: asset.criticality as ConnectSecurityAsset["criticality"],
    exposureLevel: asset.exposureLevel as ConnectSecurityAsset["exposureLevel"],
    ownershipStatus:
      asset.ownershipStatus as ConnectSecurityAsset["ownershipStatus"],
    containsSensitiveData: asset.containsSensitiveData,
    isPrivileged: asset.isPrivileged,
    riskScore: asset.riskScore,
    lastObservedAt: asset.lastObservedAt || null,
    createdAt: asset.createdAt,
    updatedAt: asset.updatedAt,
    integration: asset.integration
      ? {
          id: asset.integration.id,
          provider: asset.integration.provider as ConnectProvider,
          displayName: asset.integration.displayName
        }
      : null,
    owner: asset.owner
      ? {
          id: asset.owner.id,
          email: asset.owner.email,
          displayName: asset.owner.displayName || null
        }
      : null,
    businessOwner: asset.businessOwner
      ? {
          id: asset.businessOwner.id,
          email: asset.businessOwner.email,
          displayName: asset.businessOwner.displayName || null
        }
      : null,
    openFindingCount: asset.openFindingCount,
    activeExceptionCount: asset.activeExceptionCount
  };
}

function riskExceptionFromProto(
  exception: ProtoRiskException
): ConnectRiskException {
  return {
    id: exception.id,
    title: exception.title,
    rationale: exception.rationale,
    compensatingControls: exception.compensatingControls,
    status: exception.status as ConnectRiskException["status"],
    expiresAt: exception.expiresAt || null,
    approvedAt: exception.approvedAt || null,
    createdAt: exception.createdAt,
    updatedAt: exception.updatedAt,
    asset: exception.asset
      ? {
          id: exception.asset.id,
          name: exception.asset.name,
          type: exception.asset.type
        }
      : null,
    finding: exception.finding
      ? {
          id: exception.finding.id,
          title: exception.finding.title,
          severity: exception.finding.severity as ConnectFinding["severity"],
          status: exception.finding.status as ConnectFinding["status"]
        }
      : null,
    createdBy: exception.createdBy
      ? {
          id: exception.createdBy.id,
          email: exception.createdBy.email,
          displayName: exception.createdBy.displayName || null
        }
      : null,
    approvedBy: exception.approvedBy
      ? {
          id: exception.approvedBy.id,
          email: exception.approvedBy.email,
          displayName: exception.approvedBy.displayName || null
        }
      : null
  };
}

export const aperioConnectClient = {
  async callApi<T>(input: {
    method: string;
    path: string;
    body?: unknown;
  }): Promise<T> {
    const response = await client.callApi({
      method: input.method,
      path: input.path,
      bodyJson: input.body === undefined ? "" : JSON.stringify(input.body)
    });
    return JSON.parse(response.bodyJson || "{}") as T;
  },
  checkHealth() {
    return client.checkHealth({});
  },
  async getDashboardMetrics(): Promise<{ data: ConnectDashboardMetrics }> {
    const response = await client.getDashboardMetrics({});
    return {
      data: response.data ?? {
        totalRiskScore: 0,
        openCriticalFindings: 0,
        connectedApps: 0,
        eventIngestionRate: 0
      }
    };
  },
  async listFindings(filters?: ConnectFindingsFilters): Promise<{
    data: ConnectFinding[];
    pageInfo: { total: number; nextCursor: string | null };
  }> {
    const response = await client.listFindings({
      severity: filters?.severity ?? "",
      status: filters?.status === "ALL" ? "ALL" : filters?.status ?? "OPEN",
      provider: filters?.provider ?? "",
      integrationId: filters?.integrationId ?? "",
      limit: filters?.limit ?? 50,
      cursor: filters?.cursor ?? ""
    });
    return {
      data: response.data.map(findingFromProto),
      pageInfo: {
        total: response.pageInfo?.total ?? 0,
        nextCursor: response.pageInfo?.nextCursor || null
      }
    };
  },
  async getFinding(id: string): Promise<{ data: ConnectFinding }> {
    const response = await client.getFinding({ id });
    if (!response.data) {
      throw new Error("Finding not found");
    }
    return { data: findingFromProto(response.data) };
  },
  async updateFindingStatus(
    id: string,
    payload: { status: "RESOLVED" | "MUTED"; resolutionNote?: string }
  ): Promise<{ data: { id: string; status: "RESOLVED" | "MUTED" } }> {
    const response = await client.updateFindingStatus({
      id,
      status: payload.status,
      resolutionNote: payload.resolutionNote ?? ""
    });
    if (!response.data) {
      throw new Error("Finding update failed");
    }
    return {
      data: {
        id: response.data.id,
        status: response.data.status as "RESOLVED" | "MUTED"
      }
    };
  },
  async remediateFinding(
    findingId: string,
    payload: { action: string; targetIdentifier?: string; note?: string }
  ): Promise<{ data: ConnectRemediationResult }> {
    const response = await client.remediateFinding({
      findingId,
      action: payload.action,
      targetIdentifier: payload.targetIdentifier ?? "",
      note: payload.note ?? ""
    });
    if (!response.data) {
      throw new Error("Remediation failed");
    }
    return { data: remediationResultFromProto(response.data) };
  },
  async listConnectorCatalog(): Promise<{
    data: ConnectConnectorDefinition[];
  }> {
    const response = await client.listConnectorCatalog({});
    return { data: response.data.map(connectorDefinitionFromProto) };
  },
  async listIntegrations(): Promise<{ data: ConnectIntegrationConnection[] }> {
    const response = await client.listIntegrations({});
    return { data: response.data.map(integrationFromProto) };
  },
  async createIntegration(
    payload: ConnectIntegrationPayload
  ): Promise<{ data: ConnectIntegrationConnection }> {
    const response = await client.createIntegration({
      provider: payload.provider,
      displayName: payload.displayName,
      externalAccountId: payload.externalAccountId,
      mode: payload.mode,
      credentials: {
        accessToken: payload.credentials.accessToken,
        refreshToken: payload.credentials.refreshToken ?? "",
        webhookSecret: payload.credentials.webhookSecret ?? ""
      }
    });
    if (!response.data) {
      throw new Error("Integration create failed");
    }
    return { data: integrationFromProto(response.data) };
  },
  async deleteIntegration(id: string): Promise<void> {
    await client.deleteIntegration({ id });
  },
  async getIntegrationChecks(
    integrationId: string
  ): Promise<{ data: ConnectIntegrationCheckState }> {
    const response = await client.getIntegrationChecks({ integrationId });
    if (!response.data) {
      throw new Error("Integration checks unavailable");
    }
    return { data: integrationCheckStateFromProto(response.data) };
  },
  async updateIntegrationChecks(
    integrationId: string,
    disabledChecks: string[]
  ): Promise<{ data: ConnectIntegrationCheckState }> {
    const response = await client.updateIntegrationChecks({
      integrationId,
      disabledChecks
    });
    if (!response.data) {
      throw new Error("Integration checks update failed");
    }
    return { data: integrationCheckStateFromProto(response.data) };
  },
  async getGoogleMailboxScanConfig(
    integrationId: string
  ): Promise<{ data: ConnectGoogleMailboxScanConfig }> {
    const response = await client.getGoogleMailboxScanConfig({
      integrationId
    });
    if (!response.data) {
      throw new Error("Google mailbox scan config unavailable");
    }
    return { data: googleMailboxScanConfigFromProto(response.data) };
  },
  async updateGoogleMailboxScanConfig(
    integrationId: string,
    payload: {
      enabled: boolean;
      serviceAccountClientEmail?: string;
      privateKey?: string;
    }
  ): Promise<{ data: ConnectGoogleMailboxScanConfig }> {
    const response = await client.updateGoogleMailboxScanConfig({
      integrationId,
      enabled: payload.enabled,
      serviceAccountClientEmail: payload.serviceAccountClientEmail ?? "",
      privateKey: payload.privateKey ?? ""
    });
    if (!response.data) {
      throw new Error("Google mailbox scan config update failed");
    }
    return { data: googleMailboxScanConfigFromProto(response.data) };
  },
  async startGoogleWorkspaceOAuth(
    mode: "READ_ONLY" | "REMEDIATION"
  ): Promise<{ data: { url: string } }> {
    const response = await client.startGoogleWorkspaceOAuth({ mode });
    return { data: { url: response.data?.url ?? "" } };
  },
  async forceSyncIntegration(integrationId: string): Promise<{
    data: ConnectIntegrationConnection;
    sync: ConnectSyncSummary;
  }> {
    const response = await client.forceSyncIntegration({ integrationId });
    if (!response.data) {
      throw new Error("Integration sync failed");
    }
    return {
      data: integrationFromProto(response.data),
      sync: {
        sampleCount: response.sync?.sampleCount ?? 0,
        eventsIngested: response.sync?.eventsIngested ?? 0,
        findingsOpened: response.sync?.findingsOpened ?? 0,
        sources: response.sync?.sources ?? []
      }
    };
  },
  async listSiemCatalog(): Promise<{
    data: ConnectSiemDestinationDefinition[];
  }> {
    const response = await client.listSiemCatalog({});
    return { data: response.data.map(siemDefinitionFromProto) };
  },
  async listSiemDestinations(): Promise<{ data: ConnectSiemDestination[] }> {
    const response = await client.listSiemDestinations({});
    return { data: response.data.map(siemDestinationFromProto) };
  },
  async createSiemDestination(
    payload: ConnectCreateSiemPayload
  ): Promise<{ data: ConnectSiemDestination }> {
    const response = await client.createSiemDestination({
      kind: payload.kind,
      name: payload.name,
      endpointUrl: payload.endpointUrl ?? "",
      filePath: payload.filePath ?? "",
      index: payload.index ?? "",
      token: payload.token ?? "",
      streams: payload.streams
    });
    if (!response.data) {
      throw new Error("SIEM destination create failed");
    }
    return { data: siemDestinationFromProto(response.data) };
  },
  async deleteSiemDestination(id: string): Promise<void> {
    await client.deleteSiemDestination({ id });
  },
  async testSiemDestination(
    id: string
  ): Promise<{ data: ConnectSiemTestResult }> {
    const response = await client.testSiemDestination({ id });
    if (!response.data) {
      throw new Error("SIEM destination test failed");
    }
    return {
      data: {
        destinationId: response.data.destinationId,
        ok: response.data.ok,
        message: response.data.message
      }
    };
  },
  async listShadowItOauthApps(): Promise<{ data: ConnectShadowItOauthApp[] }> {
    const response = await client.listShadowItOauthApps({});
    return { data: response.data.map(shadowItOauthAppFromProto) };
  },
  async listShadowItOauthAppGrants(
    assetId: string
  ): Promise<{ data: ConnectShadowItOauthAppDetail }> {
    const response = await client.listShadowItOauthAppGrants({ assetId });
    if (!response.data?.app) {
      throw new Error("OAuth app not found");
    }
    return {
      data: {
        app: {
          id: response.data.app.id,
          name: response.data.app.name,
          externalId: response.data.app.externalId || null,
          provider: response.data.app.provider as ConnectProvider | ""
        },
        grants: response.data.grants.map(shadowItGrantFromProto)
      }
    };
  },
  async listSecurityAssets(
    filters?: ConnectSecurityAssetsFilters
  ): Promise<{ data: ConnectSecurityAsset[] }> {
    const response = await client.listSecurityAssets({
      type: filters?.type ?? "",
      ownershipStatus: filters?.ownershipStatus ?? "",
      integrationId: filters?.integrationId ?? ""
    });
    return { data: response.data.map(securityAssetFromProto) };
  },
  async listRiskExceptions(): Promise<{ data: ConnectRiskException[] }> {
    const response = await client.listRiskExceptions({});
    return { data: response.data.map(riskExceptionFromProto) };
  }
};

import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import {
  AperioService,
  type Finding as ProtoFinding,
  type RiskException as ProtoRiskException,
  type SecurityAsset as ProtoSecurityAsset,
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
  async listIntegrations(): Promise<{ data: ConnectIntegrationConnection[] }> {
    const response = await client.listIntegrations({});
    return {
      data: response.data.map((integration) => ({
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
      }))
    };
  },
  async listSiemDestinations(): Promise<{ data: ConnectSiemDestination[] }> {
    const response = await client.listSiemDestinations({});
    return {
      data: response.data.map((destination) => ({
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
      }))
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

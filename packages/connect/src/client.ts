import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import {
  AperioService,
  type Finding as ProtoFinding
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

export const aperioConnectClient = {
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
  }
};

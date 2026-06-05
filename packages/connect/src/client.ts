import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { AperioService } from "./gen/aperio/v1/api_pb";

const CONNECT_BASE_URL =
  process.env.NEXT_PUBLIC_CONNECT_API_BASE_URL?.replace(/\/$/, "") ??
  "http://localhost:4100";

export type ConnectDashboardMetrics = {
  totalRiskScore: number;
  openCriticalFindings: number;
  connectedApps: number;
  eventIngestionRate: number;
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
  }
};

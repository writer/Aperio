"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  fetchFindings,
  fetchIntegrations,
  forceSyncIntegration,
  type Finding,
  type IntegrationConnection
} from "../../lib/api";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { formatRelative, providerLabel } from "../../lib/format";
import { FindingsTable } from "../findings/findings-table";

export function AppFindingsPage({
  integrationId
}: {
  integrationId: string;
}) {
  const { toast } = useToast();
  const [integration, setIntegration] = useState<IntegrationConnection | null>(
    null
  );
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [integrations, findingsResponse] = await Promise.all([
        fetchIntegrations(),
        fetchFindings({ status: "ALL", integrationId, limit: 100 })
      ]);
      setIntegration(
        integrations.data.find((entry) => entry.id === integrationId) ?? null
      );
      setFindings(findingsResponse.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load findings");
    } finally {
      setLoading(false);
    }
  }, [integrationId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleSync() {
    setSyncing(true);
    try {
      const result = await forceSyncIntegration(integrationId);
      toast({
        title: "Sync triggered",
        description: `Ingested ${result.sync.eventsIngested} events, opened ${result.sync.findingsOpened} findings.`,
        tone: "success"
      });
      await load();
    } catch (err) {
      toast({
        title: "Sync failed",
        description: err instanceof Error ? err.message : "Unable to sync",
        tone: "error"
      });
    } finally {
      setSyncing(false);
    }
  }

  const summary = useMemo(() => {
    const open = findings.filter((f) => f.status === "OPEN");
    const totalRisk = open.reduce((sum, f) => sum + f.riskScore, 0);
    return {
      total: findings.length,
      open: open.length,
      risk: open.length === 0 ? 0 : Math.round(totalRisk / open.length)
    };
  }, [findings]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow={
          integration ? providerLabel(integration.provider) : "Integration"
        }
        title={integration?.displayName ?? "Integration"}
        description={
          integration
            ? `Mode: ${integration.mode === "REMEDIATION" ? "Read + remediate" : "Read-only"} · Last sync ${formatRelative(integration.lastSyncAt)}`
            : "Loading integration…"
        }
        actions={
          integration ? (
            <Button
              onClick={() => void handleSync()}
              loading={syncing}
              loadingText="Syncing…"
              variant="outline"
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
              Force sync
            </Button>
          ) : null
        }
      />

      <section className="grid gap-3 sm:grid-cols-3">
        <Stat label="Total findings" value={summary.total} />
        <Stat label="Open findings" value={summary.open} />
        <Stat label="Avg open risk" value={summary.risk} />
      </section>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-6">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
            </div>
          ) : error ? (
            <div className="p-6 text-sm text-destructive">{error}</div>
          ) : (
            <FindingsTable
              findings={findings}
              showApp={false}
              showStatusFilter
              emptyTitle="No findings for this integration"
              emptyDescription="When findings are detected, they will appear here."
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardContent className="p-5">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </p>
        <p className="mt-2 text-xl font-semibold text-foreground">{value}</p>
      </CardContent>
    </Card>
  );
}

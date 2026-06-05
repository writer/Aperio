"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowRight, Plus, Search } from "lucide-react";
import {
  fetchFindings,
  fetchIntegrations,
  type Finding,
  type IntegrationConnection,
  type Provider
} from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { EmptyState } from "../ui/empty-state";
import { Input } from "../ui/input";
import { Skeleton } from "../ui/skeleton";
import { AsyncSection } from "../ui/async-section";
import { cn } from "../../lib/utils";
import { formatRelative, providerLabel } from "../../lib/format";

type StatusFilter = "ALL" | IntegrationConnection["status"];

const STATUS_FILTERS: StatusFilter[] = ["ALL", "CONNECTED", "ERROR", "DISABLED"];

export function AppsPage() {
  const [integrations, setIntegrations] = useState<
    IntegrationConnection[] | null
  >(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("ALL");
  const [providerFilter, setProviderFilter] = useState<Provider | "ALL">("ALL");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [i, f] = await Promise.all([
        fetchIntegrations(),
        fetchFindings({ status: "OPEN", limit: 100 })
      ]);
      setIntegrations(i.data);
      setFindings(f.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load apps");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const findingsByIntegration = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const finding of findings) {
      const id = finding.integration.id ?? "unknown";
      if (!map.has(id)) map.set(id, []);
      map.get(id)!.push(finding);
    }
    return map;
  }, [findings]);

  const providerOptions = useMemo(() => {
    const set = new Set<Provider>();
    integrations?.forEach((i) => set.add(i.provider));
    return Array.from(set);
  }, [integrations]);

  const filtered = useMemo(() => {
    if (!integrations) return [];
    const q = query.trim().toLowerCase();
    return integrations.filter((i) => {
      if (status !== "ALL" && i.status !== status) return false;
      if (providerFilter !== "ALL" && i.provider !== providerFilter)
        return false;
      if (q) {
        const haystack =
          `${i.displayName} ${providerLabel(i.provider)} ${i.externalAccountId}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [integrations, query, status, providerFilter]);

  const filtersActive =
    query.length > 0 || status !== "ALL" || providerFilter !== "ALL";

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Apps"
        title="Connected apps"
        description="Risk per integration, with a link to its findings and evidence."
        actions={
          <Button asChild>
            <Link href="/connectors">
              <Plus className="h-4 w-4" aria-hidden />
              Connect app
            </Link>
          </Button>
        }
      />

      <AsyncSection
        data={integrations}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        errorTitle="Unable to load apps"
        skeleton={
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Card key={i}>
                <CardContent className="p-5">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="mt-3 h-5 w-40" />
                  <Skeleton className="mt-2 h-4 w-32" />
                </CardContent>
              </Card>
            ))}
          </div>
        }
      >
        {(rows) => (
          <>
            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card/60 px-4 py-3">
              <div className="relative w-full max-w-xs">
                <Search
                  className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search apps…"
                  aria-label="Search apps"
                  className="h-8 pl-7 text-xs"
                />
              </div>
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Status
              </span>
              <div className="flex items-center gap-1">
                {STATUS_FILTERS.map((s) => {
                  const active = status === s;
                  return (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setStatus(s)}
                      aria-pressed={active}
                      className={cn(
                        "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
                        active
                          ? "border-signal/40 bg-signal/15 text-signal"
                          : "border-border/80 bg-background text-muted-foreground hover:border-border hover:text-foreground"
                      )}
                    >
                      {s}
                    </button>
                  );
                })}
              </div>
              {providerOptions.length > 1 ? (
                <>
                  <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    Provider
                  </span>
                  <select
                    value={providerFilter}
                    onChange={(e) =>
                      setProviderFilter(e.target.value as Provider | "ALL")
                    }
                    aria-label="Filter by provider"
                    className="h-8 rounded-md border border-border/80 bg-background px-2 text-xs text-foreground"
                  >
                    <option value="ALL">All providers</option>
                    {providerOptions.map((p) => (
                      <option key={p} value={p}>
                        {providerLabel(p)}
                      </option>
                    ))}
                  </select>
                </>
              ) : null}
              <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
                {filtered.length} of {rows.length}
              </span>
              {filtersActive ? (
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-xs"
                  onClick={() => {
                    setQuery("");
                    setStatus("ALL");
                    setProviderFilter("ALL");
                  }}
                >
                  Clear
                </Button>
              ) : null}
            </div>

            {rows.length === 0 ? (
              <EmptyState
                title="No connected apps yet"
                description="Connect your first SaaS integration to start ingesting audit logs and detecting drift."
                action={
                  <Button asChild>
                    <Link href="/connectors">
                      <Plus className="h-4 w-4" aria-hidden />
                      Connect an app
                    </Link>
                  </Button>
                }
              />
            ) : filtered.length === 0 ? (
              <EmptyState
                title="No matches"
                description="No apps match the current filters. Clear them to see all connected apps."
                action={
                  <Button
                    variant="outline"
                    onClick={() => {
                      setQuery("");
                      setStatus("ALL");
                      setProviderFilter("ALL");
                    }}
                  >
                    Clear filters
                  </Button>
                }
              />
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {filtered.map((integration) => {
                  const integrationFindings =
                    findingsByIntegration.get(integration.id) ?? [];
                  const openCount = integrationFindings.length;
                  const criticalCount = integrationFindings.filter(
                    (f) => f.severity === "CRITICAL"
                  ).length;
                  const topRisk = integrationFindings.reduce(
                    (max, f) => (f.riskScore > max ? f.riskScore : max),
                    0
                  );
                  return (
                    <Link
                      key={integration.id}
                      href={`/apps/${integration.id}`}
                      className={cn(
                        "group relative overflow-hidden rounded-lg border border-border bg-card p-5 transition-all hover:-translate-y-0.5 hover:border-foreground/20 hover:bg-muted/30",
                        criticalCount > 0
                          ? "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-critical"
                          : ""
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                            {providerLabel(integration.provider)}
                          </p>
                          <p className="mt-1 truncate text-sm font-semibold text-foreground">
                            {integration.displayName}
                          </p>
                        </div>
                        <Badge
                          variant={
                            integration.status === "CONNECTED"
                              ? "success"
                              : integration.status === "ERROR"
                                ? "destructive"
                                : "secondary"
                          }
                        >
                          {integration.status}
                        </Badge>
                      </div>
                      <dl className="mt-4 grid grid-cols-3 gap-2 text-xs">
                        <Cell label="Open" value={openCount} />
                        <Cell
                          label="Critical"
                          value={criticalCount}
                          tone={criticalCount > 0 ? "critical" : "neutral"}
                        />
                        <Cell label="Top risk" value={topRisk} />
                      </dl>
                      <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
                        <span className="font-mono tabular-nums">
                          Synced {formatRelative(integration.lastSyncAt)}
                        </span>
                        <ArrowRight
                          className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5"
                          aria-hidden
                        />
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </>
        )}
      </AsyncSection>
    </div>
  );
}

function Cell({
  label,
  value,
  tone = "neutral"
}: {
  label: string;
  value: number;
  tone?: "neutral" | "critical";
}) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          "font-mono text-sm tabular-nums",
          tone === "critical" ? "text-critical" : "text-foreground"
        )}
      >
        {value}
      </dd>
    </div>
  );
}

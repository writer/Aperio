"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronsUpDown,
  Search
} from "lucide-react";
import {
  fetchSecurityOverview,
  type SecurityIdentity,
  type SecurityOverview
} from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { EmptyState } from "../ui/empty-state";
import { Input } from "../ui/input";
import { Skeleton } from "../ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { AsyncSection } from "../ui/async-section";
import { cn } from "../../lib/utils";
import { formatRelative, providerLabel } from "../../lib/format";

type SortKey = "name" | "role" | "riskScore" | "lastObservedAt";
type SortDir = "asc" | "desc";
type MfaFilter = "all" | "off" | "on" | "unknown";

const PAGE_SIZE = 25;

export function PrivilegedIdentitiesPage() {
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [mfa, setMfa] = useState<MfaFilter>("all");
  const [externalOnly, setExternalOnly] = useState(false);
  const [highRiskOnly, setHighRiskOnly] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("riskScore");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetchSecurityOverview();
      setOverview(response.data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load privileged identities"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const allPrivileged = useMemo<SecurityIdentity[]>(
    () => overview?.identities.filter((entry) => entry.privileged) ?? [],
    [overview]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let rows = allPrivileged;
    if (q) {
      rows = rows.filter((i) => {
        return (
          i.name.toLowerCase().includes(q) ||
          (i.email ?? "").toLowerCase().includes(q) ||
          i.role.toLowerCase().includes(q)
        );
      });
    }
    if (mfa !== "all") {
      rows = rows.filter((i) => {
        if (mfa === "off") return i.mfaEnabled === false;
        if (mfa === "on") return i.mfaEnabled === true;
        return i.mfaEnabled == null;
      });
    }
    if (externalOnly) rows = rows.filter((i) => i.isExternal);
    if (highRiskOnly) rows = rows.filter((i) => i.riskScore >= 80);

    const dir = sortDir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      switch (sortKey) {
        case "name":
          return a.name.localeCompare(b.name) * dir;
        case "role":
          return a.role.localeCompare(b.role) * dir;
        case "riskScore":
          return (a.riskScore - b.riskScore) * dir;
        case "lastObservedAt": {
          const at = a.lastObservedAt
            ? new Date(a.lastObservedAt).getTime()
            : 0;
          const bt = b.lastObservedAt
            ? new Date(b.lastObservedAt).getTime()
            : 0;
          return (at - bt) * dir;
        }
        default:
          return 0;
      }
    });
  }, [allPrivileged, query, mfa, externalOnly, highRiskOnly, sortKey, sortDir]);

  useEffect(() => {
    setPage(0);
  }, [query, mfa, externalOnly, highRiskOnly]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const visible = filtered.slice(
    safePage * PAGE_SIZE,
    safePage * PAGE_SIZE + PAGE_SIZE
  );

  const withoutMfa = allPrivileged.filter((i) => i.mfaEnabled === false).length;
  const external = allPrivileged.filter((i) => i.isExternal).length;
  const highRisk = allPrivileged.filter((i) => i.riskScore >= 80).length;

  function toggleSort(next: SortKey) {
    if (sortKey === next) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(next);
      setSortDir(next === "name" || next === "role" ? "asc" : "desc");
    }
  }

  const filtersActive =
    query.length > 0 || mfa !== "all" || externalOnly || highRiskOnly;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Security"
        title="Privileged identities"
        description="Every privileged identity discovered across connected SaaS apps, with role, MFA posture, external exposure, and current risk."
      />

      <AsyncSection
        data={overview}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        errorTitle="Unable to load privileged identities"
        skeleton={
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <SkeletonStat />
              <SkeletonStat />
              <SkeletonStat />
              <SkeletonStat />
            </div>
            <Card>
              <CardContent className="space-y-2 p-6">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
              </CardContent>
            </Card>
          </div>
        }
      >
        {() => (
          <>
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat label="Privileged" value={allPrivileged.length} />
              <Stat
                label="Without MFA"
                value={withoutMfa}
                tone={withoutMfa > 0 ? "critical" : "neutral"}
              />
              <Stat label="External" value={external} />
              <Stat
                label="High risk (≥80)"
                value={highRisk}
                tone={highRisk > 0 ? "critical" : "signal"}
              />
            </section>

            <Card>
              <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
                <div className="relative w-full max-w-xs">
                  <Search
                    className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                    aria-hidden
                  />
                  <Input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Search name, email, role…"
                    aria-label="Search privileged identities"
                    className="h-8 pl-7 text-xs"
                  />
                </div>
                <ChipGroup
                  label="MFA"
                  value={mfa}
                  options={[
                    { value: "all", label: "All" },
                    { value: "off", label: "Off" },
                    { value: "on", label: "On" },
                    { value: "unknown", label: "Unknown" }
                  ]}
                  onChange={(v) => setMfa(v as MfaFilter)}
                />
                <Toggle
                  label="External"
                  active={externalOnly}
                  onClick={() => setExternalOnly((p) => !p)}
                />
                <Toggle
                  label="High risk"
                  active={highRiskOnly}
                  tone="critical"
                  onClick={() => setHighRiskOnly((p) => !p)}
                />
                <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
                  {filtered.length} of {allPrivileged.length}
                </span>
                {filtersActive ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 px-2 text-xs"
                    onClick={() => {
                      setQuery("");
                      setMfa("all");
                      setExternalOnly(false);
                      setHighRiskOnly(false);
                    }}
                  >
                    Clear
                  </Button>
                ) : null}
              </div>

              <CardContent className="p-0">
                {filtered.length === 0 ? (
                  <EmptyState
                    title={
                      filtersActive
                        ? "No matches"
                        : "No privileged identities discovered"
                    }
                    description={
                      filtersActive
                        ? "No identities match the current filters. Clear them to see all results."
                        : "Once connectors finish syncing, privileged users and service accounts will appear here."
                    }
                    className="m-6"
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <SortableHead
                          label="Identity"
                          active={sortKey === "name"}
                          dir={sortDir}
                          onClick={() => toggleSort("name")}
                        />
                        <TableHead>Provider</TableHead>
                        <SortableHead
                          label="Role"
                          active={sortKey === "role"}
                          dir={sortDir}
                          onClick={() => toggleSort("role")}
                        />
                        <TableHead>MFA</TableHead>
                        <TableHead>External</TableHead>
                        <SortableHead
                          label="Risk"
                          align="right"
                          active={sortKey === "riskScore"}
                          dir={sortDir}
                          onClick={() => toggleSort("riskScore")}
                        />
                        <SortableHead
                          label="Observed"
                          align="right"
                          active={sortKey === "lastObservedAt"}
                          dir={sortDir}
                          onClick={() => toggleSort("lastObservedAt")}
                        />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {visible.map((identity) => (
                        <TableRow key={identity.id}>
                          <TableCell className="font-medium">
                            {identity.name}
                            {identity.email ? (
                              <p className="font-mono text-xs text-muted-foreground">
                                {identity.email}
                              </p>
                            ) : null}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {identity.provider
                              ? providerLabel(identity.provider)
                              : "—"}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {identity.role}
                          </TableCell>
                          <TableCell>
                            {identity.mfaEnabled == null ? (
                              <Badge variant="outline">unknown</Badge>
                            ) : identity.mfaEnabled ? (
                              <Badge variant="success">on</Badge>
                            ) : (
                              <Badge variant="destructive">off</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            {identity.isExternal ? (
                              <Badge variant="warning">external</Badge>
                            ) : (
                              <Badge variant="outline">internal</Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-right">
                            <Badge
                              variant={
                                identity.riskScore >= 80
                                  ? "critical"
                                  : identity.riskScore >= 50
                                    ? "warning"
                                    : "secondary"
                              }
                              className="font-mono tabular-nums"
                            >
                              {identity.riskScore}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs text-muted-foreground tabular-nums">
                            {formatRelative(identity.lastObservedAt)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {totalPages > 1 ? (
                  <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3 text-xs">
                    <span className="font-mono text-muted-foreground tabular-nums">
                      Page {safePage + 1} of {totalPages}
                    </span>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 px-2"
                        onClick={() => setPage((p) => Math.max(0, p - 1))}
                        disabled={safePage === 0}
                      >
                        Prev
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 px-2"
                        onClick={() =>
                          setPage((p) => Math.min(totalPages - 1, p + 1))
                        }
                        disabled={safePage >= totalPages - 1}
                      >
                        Next
                      </Button>
                    </div>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </>
        )}
      </AsyncSection>
    </div>
  );
}

type Tone = "neutral" | "signal" | "critical";

const toneRail: Record<Tone, string> = {
  neutral: "bg-border",
  signal: "bg-signal/70",
  critical: "bg-critical critical-pulse"
};

function Stat({
  label,
  value,
  tone = "neutral"
}: {
  label: string;
  value: number;
  tone?: Tone;
}) {
  return (
    <Card className="relative overflow-hidden animate-fade-in-up">
      <span
        aria-hidden
        className={`absolute left-0 top-0 h-full w-[3px] ${toneRail[tone]}`}
      />
      <CardContent className="p-5">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        <p className="mt-2 font-mono text-2xl font-semibold tracking-tight text-foreground tabular-nums">
          {value}
        </p>
      </CardContent>
    </Card>
  );
}

function SkeletonStat() {
  return (
    <Card>
      <CardContent className="space-y-2 p-5">
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-6 w-16" />
      </CardContent>
    </Card>
  );
}

function ChipGroup({
  label,
  value,
  options,
  onChange
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (next: string) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <div className="flex items-center gap-1">
        {options.map((opt) => {
          const active = value === opt.value;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onChange(opt.value)}
              aria-pressed={active}
              className={cn(
                "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
                active
                  ? "border-signal/40 bg-signal/15 text-signal"
                  : "border-border/80 bg-card text-muted-foreground hover:border-border hover:text-foreground"
              )}
            >
              {opt.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Toggle({
  label,
  active,
  onClick,
  tone = "signal"
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  tone?: "signal" | "critical";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
        active
          ? tone === "critical"
            ? "border-critical/40 bg-critical/15 text-critical"
            : "border-signal/40 bg-signal/15 text-signal"
          : "border-border/80 bg-card text-muted-foreground hover:border-border hover:text-foreground"
      )}
    >
      {label}
    </button>
  );
}

function SortableHead({
  label,
  active,
  dir,
  onClick,
  align = "left"
}: {
  label: string;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
  align?: "left" | "right";
}) {
  const Icon = active ? (dir === "asc" ? ArrowUp : ArrowDown) : ChevronsUpDown;
  return (
    <TableHead className={align === "right" ? "text-right" : undefined}>
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          active ? "text-foreground" : "text-muted-foreground"
        )}
        aria-label={`Sort by ${label}`}
      >
        <span>{label}</span>
        <Icon className="h-3 w-3" aria-hidden />
      </button>
    </TableHead>
  );
}

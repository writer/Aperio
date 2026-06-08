"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Download, FileText, Printer, RefreshCw } from "lucide-react";
import {
  fetchExecutiveReport,
  resolveReportArtifactUrl,
  type ExecutiveReportSummary
} from "../../lib/api";
import { useAuth } from "../auth/auth-shell";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { PageHeader } from "../layout/page-header";
import { Skeleton } from "../ui/skeleton";
import { formatDateTime } from "../../lib/format";

type Kpi = {
  findings?: {
    openTotal?: number;
    opened?: number;
    resolved?: number;
    openBySeverity?: Record<string, number>;
  };
  mttr?: { medianHours?: number; p90Hours?: number };
  coverage?: {
    mfaCoveragePercent?: number;
    privilegedIdentities?: number;
    dormantIdentities?: number;
    activeIntegrations?: number;
    totalAssets?: number;
    sensitiveDataAssets?: number;
    publicExposureAssets?: number;
  };
};

type AssessmentCategory = {
  key: string;
  label: string;
  score: number;
  status: "PASS" | "WARN" | "FAIL";
  summary?: string;
};

type AssessmentKpi = {
  template: "GOOGLE_WORKSPACE_ASSESSMENT";
  overallScore?: number;
  overallGrade?: string;
  categories?: AssessmentCategory[];
  scope?: {
    workspaces?: number;
    connectedWorkspaces?: number;
    identities?: number;
    oauthApps?: number;
    sensitiveDataAssets?: number;
    openFindings?: number;
    periodFindings?: number;
    auditEvents?: number;
  };
  recommendations?: string[];
};

export function ExecutiveReportDetailPage({ reportId }: { reportId: string }) {
  const { session } = useAuth();
  const canManage = session?.user.role === "OWNER" || session?.user.role === "ADMIN";

  const [report, setReport] = useState<ExecutiveReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchExecutiveReport(reportId);
      setReport(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load report");
    } finally {
      setLoading(false);
    }
  }, [reportId]);

  useEffect(() => {
    if (canManage) void load();
  }, [canManage, load]);

  useEffect(() => {
    if (!canManage) return;
    if (report?.status !== "GENERATING") return;
    const t = setInterval(() => {
      void load();
    }, 4_000);
    return () => clearInterval(t);
  }, [report?.status, canManage, load]);

  if (!canManage) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          You don&rsquo;t have permission to view executive reports.
        </CardContent>
      </Card>
    );
  }

  if (loading && !report) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-12" />
        <Skeleton className="h-80" />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex flex-col gap-4">
        <PageHeader
          eyebrow="Admin"
          title="Executive report"
          description="Unable to load this report."
          actions={
            <Button variant="outline" size="sm" onClick={() => void load()}>
              <RefreshCw className="h-3.5 w-3.5" />
              Retry
            </Button>
          }
        />
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            {error ?? "Report not found."}
          </CardContent>
        </Card>
      </div>
    );
  }

  const kpiRaw = (report.kpiSnapshot ?? {}) as Record<string, unknown>;
  const kpi = kpiRaw as Kpi;
  const assessmentRaw =
    report.template === "GOOGLE_WORKSPACE_ASSESSMENT"
      ? (kpiRaw as AssessmentKpi)
      : null;
  // An empty `{}` snapshot is truthy but renders as a misleading 0/100 FAIL
  // while the report is still GENERATING. Only render the assessment view
  // when the snapshot has real data.
  const assessment =
    assessmentRaw &&
    (assessmentRaw.overallScore != null ||
      (assessmentRaw.categories?.length ?? 0) > 0)
      ? assessmentRaw
      : null;
  const htmlUrl = resolveReportArtifactUrl(report, "html");
  const pdfUrl = resolveReportArtifactUrl(report, "pdf");

  return (
    <div className="flex flex-col gap-6">
      <Link
        href="/admin/reports"
        className="inline-flex w-fit items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3 w-3" />
        Back to reports
      </Link>

      <PageHeader
        eyebrow={report.period}
        title={report.title}
        description={
          report.summary ?? "Executive summary will appear when generation completes."
        }
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void load()}>
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
            {htmlUrl ? (
              <Button asChild variant="outline" size="sm">
                <a href={htmlUrl} target="_blank" rel="noreferrer">
                  <FileText className="h-3.5 w-3.5" />
                  View HTML
                </a>
              </Button>
            ) : null}
            {pdfUrl ? (
              <Button asChild size="sm">
                <a href={pdfUrl} target="_blank" rel="noreferrer">
                  <Download className="h-3.5 w-3.5" />
                  Download PDF
                </a>
              </Button>
            ) : htmlUrl ? (
              <Button
                size="sm"
                onClick={() => {
                  // Fallback when puppeteer is unavailable: open the HTML in a
                  // new tab and trigger the browser's print dialog so the user
                  // can save as PDF without leaving the product.
                  const win = window.open(htmlUrl, "_blank");
                  if (win) {
                    win.addEventListener("load", () => {
                      try {
                        win.print();
                      } catch {
                        // ignore — user can still print manually
                      }
                    });
                  }
                }}
              >
                <Printer className="h-3.5 w-3.5" />
                Print as PDF
              </Button>
            ) : null}
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge variant="outline">{report.status}</Badge>
        <span>
          Window: {formatDateTime(report.periodStart)} → {formatDateTime(report.periodEnd)}
        </span>
        {report.generatedAt ? (
          <span>· generated {formatDateTime(report.generatedAt)}</span>
        ) : null}
      </div>

      {error ? (
        <Card>
          <CardContent className="flex items-center justify-between gap-3 p-4 text-sm text-destructive">
            <span>Failed to refresh: {error}</span>
            <Button variant="outline" size="sm" onClick={() => void load()}>
              <RefreshCw className="h-3.5 w-3.5" />
              Retry
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {report.status === "GENERATING" ? (
        <Card>
          <CardContent className="p-6 text-sm text-muted-foreground">
            Generation in progress. This page auto-refreshes when the artifact is ready.
          </CardContent>
        </Card>
      ) : null}

      {report.status === "FAILED" ? (
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            {report.errorMessage ?? "Generation failed."}
          </CardContent>
        </Card>
      ) : null}

      {assessment ? (
        <AssessmentOverview assessment={assessment} />
      ) : kpi.findings || kpi.mttr || kpi.coverage ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
          <KpiCard
            label="Open findings"
            value={fmtNumber(kpi.findings?.openTotal)}
            sub={`${fmtNumber(kpi.findings?.openBySeverity?.CRITICAL ?? 0)} critical · ${fmtNumber(kpi.findings?.openBySeverity?.HIGH ?? 0)} high`}
          />
          <KpiCard
            label="Resolved this period"
            value={fmtNumber(kpi.findings?.resolved)}
            sub={`${fmtNumber(kpi.findings?.opened)} new opened`}
          />
          <KpiCard
            label="Median MTTR"
            value={fmtHours(kpi.mttr?.medianHours)}
            sub={`P90 ${fmtHours(kpi.mttr?.p90Hours)}`}
          />
          <KpiCard
            label="MFA coverage"
            value={fmtPercent(kpi.coverage?.mfaCoveragePercent)}
            sub={`${fmtNumber(kpi.coverage?.privilegedIdentities)} privileged · ${fmtNumber(kpi.coverage?.dormantIdentities)} dormant`}
          />
        </div>
      ) : null}

      {htmlUrl ? (
        <Card>
          <CardHeader>
            <CardTitle>Report preview</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <iframe
              src={htmlUrl}
              title={report.title}
              className="h-[1000px] w-full rounded-b-lg border-0 bg-white"
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function AssessmentOverview({ assessment }: { assessment: AssessmentKpi }) {
  const score = assessment.overallScore ?? 0;
  const grade = assessment.overallGrade ?? "—";
  const scope = assessment.scope ?? {};
  const categories = assessment.categories ?? [];
  const recommendations = assessment.recommendations ?? [];
  const gradeTone = toneFromStatus(statusForScore(score));
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-4 p-5">
          <div>
            <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Overall grade
            </div>
            <div className="mt-1 flex items-baseline gap-3">
              <span className={`text-4xl font-semibold ${gradeTone.text}`}>{grade}</span>
              <span className="text-sm text-muted-foreground">{score}/100</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <ScopeStat label="Workspaces" value={fmtNumber(scope.workspaces)} />
            <ScopeStat label="Identities" value={fmtNumber(scope.identities)} />
            <ScopeStat label="OAuth apps" value={fmtNumber(scope.oauthApps)} />
            <ScopeStat label="Open findings" value={fmtNumber(scope.openFindings)} />
          </div>
        </CardContent>
      </Card>

      {categories.length ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {categories.map((cat) => {
            const tone = toneFromStatus(cat.status);
            return (
              <Card key={cat.key}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-medium text-foreground">
                      {cat.label}
                    </div>
                    <Badge className={`${tone.badge}`}>{cat.status}</Badge>
                  </div>
                  <div className="mt-2 flex items-baseline gap-2">
                    <span className={`text-2xl font-semibold ${tone.text}`}>
                      {cat.score}
                    </span>
                    <span className="text-xs text-muted-foreground">/100</span>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className={`h-full ${tone.bar}`}
                      style={{ width: `${Math.max(0, Math.min(100, cat.score))}%` }}
                    />
                  </div>
                  {cat.summary ? (
                    <p className="mt-2 text-xs text-muted-foreground">{cat.summary}</p>
                  ) : null}
                </CardContent>
              </Card>
            );
          })}
        </div>
      ) : null}

      {recommendations.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Recommended actions</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-1 pl-5 text-sm text-foreground">
              {recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function ScopeStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className="text-base font-semibold text-foreground">{value}</span>
    </div>
  );
}

function statusForScore(score: number): "PASS" | "WARN" | "FAIL" {
  if (!Number.isFinite(score)) return "PASS";
  if (score >= 80) return "PASS";
  if (score >= 60) return "WARN";
  return "FAIL";
}

function toneFromStatus(status: "PASS" | "WARN" | "FAIL") {
  switch (status) {
    case "PASS":
      return {
        text: "text-emerald-600 dark:text-emerald-400",
        bar: "bg-emerald-500",
        badge:
          "border-transparent bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"
      };
    case "WARN":
      return {
        text: "text-amber-600 dark:text-amber-400",
        bar: "bg-amber-500",
        badge:
          "border-transparent bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200"
      };
    case "FAIL":
      return {
        text: "text-red-600 dark:text-red-400",
        bar: "bg-red-500",
        badge:
          "border-transparent bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200"
      };
  }
}

function KpiCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </div>
        <div className="mt-1 text-2xl font-semibold text-foreground">{value}</div>
        {sub ? <div className="mt-1 text-xs text-muted-foreground">{sub}</div> : null}
      </CardContent>
    </Card>
  );
}

function fmtNumber(value: number | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return value.toLocaleString("en-US");
}

function fmtPercent(value: number | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${value.toFixed(1)}%`;
}

function fmtHours(value: number | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  if (value < 1) return `${(value * 60).toFixed(0)}m`;
  if (value < 48) return `${value.toFixed(1)}h`;
  return `${(value / 24).toFixed(1)}d`;
}

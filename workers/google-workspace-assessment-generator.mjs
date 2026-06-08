// Google Workspace security assessment generator. Invoked when an operator
// creates a report with template = GOOGLE_WORKSPACE_ASSESSMENT. The shape
// differs from the executive summary: instead of cross-vendor KPIs, this
// report scores six Google-specific control families and renders a graded
// assessment suitable for sharing with Workspace admins or auditors.

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prisma } from "@aperio/db";
import {
  artifactRoot,
  escapeHtml,
  fmtNumber,
  fmtPercent,
  renderPdfFromHtml,
  scoreToGrade,
  statusForScore,
  STATUS_BG,
  STATUS_COLORS
} from "./report-utils.mjs";

// Rule ids the ingestion-worker emits when it processes Google Workspace
// audit logs. Keep this in lock-step with workers/ingestion-worker.ts; new
// detections should be added here so they participate in the assessment.
const GWS_RULES = {
  EXTERNAL_SHARING: "google_workspace.external_sharing_enabled",
  SUPER_ADMIN_GRANTED: "google_workspace.super_admin_granted",
  ADMIN_ROLE_GRANTED: "google_workspace.admin_role_granted",
  RISKY_OAUTH_GRANT: "google_workspace.risky_oauth_grant",
  ADMIN_MFA_NOT_ENFORCED: "google_workspace.admin_mfa_not_enforced",
  ADMIN_EXTERNAL_RECOVERY: "google_workspace.admin_external_recovery_email",
  FORWARDING_ENABLED: "google_workspace.email_forwarding_enabled",
  MAILBOX_DELEGATION: "google_workspace.mailbox_delegation_granted",
  LEGACY_MAIL_AUTH: "google_workspace.legacy_mail_auth_used",
  FORWARDING_DELEGATE_SEND_AS: "google_workspace.forwarding_delegate_send_as_combo"
};

const ALL_GWS_RULE_IDS = Object.values(GWS_RULES);

// Category weights for the composite overall score. Identity & admin controls
// dominate because compromised admin accounts cascade across every other
// control family.
const CATEGORY_WEIGHTS = {
  identity_mfa: 0.22,
  admin_privilege: 0.22,
  oauth_apps: 0.18,
  mailbox_security: 0.16,
  sharing_exposure: 0.12,
  domain_wide_delegation: 0.1
};

// Map a per-category open-finding count and severity mix to a 0-100 score.
// 100 = no open findings in the category, 0 = many criticals/highs. The curve
// gives the team a useful gradient — one HIGH should not flunk a category but
// should drop it out of PASS.
export function scoreFromFindings(findings) {
  if (!findings.length) return 100;
  let penalty = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "CRITICAL":
        penalty += 28;
        break;
      case "HIGH":
        penalty += 18;
        break;
      case "MEDIUM":
        penalty += 10;
        break;
      case "LOW":
        penalty += 5;
        break;
      case "INFO":
      default:
        penalty += 2;
        break;
    }
  }
  // Slight diminishing returns so a category with many low/info findings
  // doesn't collapse to 0 the way a couple of criticals correctly would.
  if (findings.length > 5) {
    penalty = Math.min(penalty, 80 + Math.log10(findings.length) * 6);
  }
  return Math.max(0, Math.min(100, 100 - penalty));
}

async function gatherWorkspaceData(report) {
  const { organizationId, periodStart, periodEnd } = report;

  const integrations = await prisma.integrationConnection.findMany({
    where: { organizationId, provider: "GOOGLE_WORKSPACE" },
    select: {
      id: true,
      provider: true,
      displayName: true,
      externalAccountId: true,
      status: true,
      mode: true,
      googleMailboxScanEnabled: true,
      googleMailboxScanClientEmail: true,
      lastSyncAt: true,
      createdAt: true
    }
  });

  const organization = await prisma.organization.findUnique({
    where: { id: organizationId }
  });
  if (!organization) {
    throw new Error(`organization ${organizationId} not found`);
  }

  const integrationIds = integrations.map((i) => i.id);

  const [openFindings, periodFindings, identities, oauthAssets, sensitiveAssets, auditCount] =
    await Promise.all([
      prisma.securityFinding.findMany({
        where: {
          organizationId,
          status: "OPEN",
          OR: [
            { ruleId: { in: ALL_GWS_RULE_IDS } },
            integrationIds.length ? { integrationId: { in: integrationIds } } : { id: "__never__" }
          ]
        },
        select: {
          id: true,
          title: true,
          description: true,
          severity: true,
          riskScore: true,
          ruleId: true,
          detectedAt: true,
          integrationId: true,
          integration: { select: { provider: true, displayName: true } }
        },
        orderBy: { riskScore: "desc" },
        take: 500
      }),
      prisma.securityFinding.findMany({
        where: {
          organizationId,
          detectedAt: { gte: periodStart, lte: periodEnd },
          OR: [
            { ruleId: { in: ALL_GWS_RULE_IDS } },
            integrationIds.length ? { integrationId: { in: integrationIds } } : { id: "__never__" }
          ]
        },
        select: { id: true, severity: true, status: true, ruleId: true }
      }),
      integrationIds.length
        ? prisma.saasIdentity.findMany({
            where: { organizationId, integrationId: { in: integrationIds } },
            select: {
              id: true,
              email: true,
              status: true,
              mfaEnabled: true,
              isPrivileged: true,
              isExternal: true,
              lastObservedAt: true
            }
          })
        : Promise.resolve([]),
      integrationIds.length
        ? prisma.securityAsset.findMany({
            where: {
              organizationId,
              integrationId: { in: integrationIds },
              type: "OAUTH_APP"
            },
            select: {
              id: true,
              name: true,
              exposureLevel: true,
              riskScore: true
            }
          })
        : Promise.resolve([]),
      integrationIds.length
        ? prisma.securityAsset.findMany({
            where: {
              organizationId,
              integrationId: { in: integrationIds },
              containsSensitiveData: true
            },
            select: {
              id: true,
              name: true,
              type: true,
              exposureLevel: true
            }
          })
        : Promise.resolve([]),
      prisma.tenantAuditLog.count({
        where: {
          organizationId,
          createdAt: { gte: periodStart, lte: periodEnd },
          targetType: { in: ["integration", "finding"] }
        }
      })
    ]);

  return {
    organization,
    integrations,
    openFindings,
    periodFindings,
    identities,
    oauthAssets,
    sensitiveAssets,
    auditCount
  };
}

function partitionFindings(openFindings, ruleIds) {
  const set = new Set(ruleIds);
  return openFindings.filter((f) => set.has(f.ruleId));
}

function describeFindings(findings, fallback) {
  if (!findings.length) return [fallback];
  // Cap detail rows so a noisy category doesn't blow up the page.
  return findings.slice(0, 5).map((f) => ({
    severity: f.severity,
    title: f.title,
    riskScore: f.riskScore
  }));
}

function buildCategories(data) {
  const { openFindings, integrations, identities, oauthAssets, sensitiveAssets } = data;

  // ─── Identity & MFA ────────────────────────────────────────────────────
  const activeIdentities = identities.filter((i) => i.status === "ACTIVE");
  const mfaCovered = activeIdentities.filter((i) => i.mfaEnabled === true).length;
  const mfaCoveragePercent = activeIdentities.length
    ? (mfaCovered / activeIdentities.length) * 100
    : 100;
  const dormantIdentities = identities.filter(
    (i) =>
      i.status === "DORMANT" ||
      (i.lastObservedAt &&
        Date.now() - new Date(i.lastObservedAt).getTime() > 1000 * 3600 * 24 * 90)
  ).length;
  const externalIdentities = identities.filter((i) => i.isExternal).length;
  const identityFindings = partitionFindings(openFindings, [GWS_RULES.ADMIN_MFA_NOT_ENFORCED]);
  const identityScoreFromFindings = scoreFromFindings(identityFindings);
  const mfaPenalty = activeIdentities.length
    ? Math.max(0, (95 - mfaCoveragePercent) * 1.5)
    : 0;
  const identityScore = Math.max(0, Math.min(100, identityScoreFromFindings - mfaPenalty));
  const identityCategory = {
    key: "identity_mfa",
    label: "Identity & MFA",
    icon: "👤",
    score: Math.round(identityScore),
    status: statusForScore(identityScore),
    summary: `${fmtNumber(activeIdentities.length)} active identities, ${fmtPercent(mfaCoveragePercent)} MFA coverage.`,
    metrics: [
      { label: "Total identities", value: fmtNumber(identities.length) },
      { label: "Active", value: fmtNumber(activeIdentities.length) },
      { label: "MFA coverage", value: fmtPercent(mfaCoveragePercent) },
      { label: "Dormant", value: fmtNumber(dormantIdentities) },
      { label: "External", value: fmtNumber(externalIdentities) }
    ],
    items: identityFindings.length
      ? describeFindings(identityFindings)
      : [
          {
            severity: "INFO",
            title:
              mfaCoveragePercent >= 95
                ? "MFA coverage meets the 95% target."
                : `${(activeIdentities.length - mfaCovered).toLocaleString("en-US")} active identities still missing MFA.`,
            riskScore: 0
          }
        ]
  };

  // ─── Admin & Privilege ─────────────────────────────────────────────────
  const adminFindings = partitionFindings(openFindings, [
    GWS_RULES.SUPER_ADMIN_GRANTED,
    GWS_RULES.ADMIN_ROLE_GRANTED,
    GWS_RULES.ADMIN_EXTERNAL_RECOVERY
  ]);
  const privilegedIdentities = identities.filter((i) => i.isPrivileged).length;
  const adminScore = scoreFromFindings(adminFindings);
  const adminCategory = {
    key: "admin_privilege",
    label: "Admin & Privilege",
    icon: "🛡️",
    score: Math.round(adminScore),
    status: statusForScore(adminScore),
    summary: `${fmtNumber(privilegedIdentities)} privileged identities; ${fmtNumber(adminFindings.length)} open admin findings.`,
    metrics: [
      { label: "Privileged identities", value: fmtNumber(privilegedIdentities) },
      { label: "Open admin findings", value: fmtNumber(adminFindings.length) }
    ],
    items: describeFindings(adminFindings, {
      severity: "INFO",
      title: "No outstanding admin-role or super-admin escalation findings.",
      riskScore: 0
    })
  };

  // ─── OAuth & Third-Party Apps ──────────────────────────────────────────
  const oauthFindings = partitionFindings(openFindings, [GWS_RULES.RISKY_OAUTH_GRANT]);
  const publicOauthApps = oauthAssets.filter((a) => a.exposureLevel === "PUBLIC").length;
  const oauthScore = scoreFromFindings(oauthFindings);
  const oauthCategory = {
    key: "oauth_apps",
    label: "OAuth & Third-Party Apps",
    icon: "🔌",
    score: Math.round(oauthScore),
    status: statusForScore(oauthScore),
    summary: `${fmtNumber(oauthAssets.length)} OAuth applications connected; ${fmtNumber(oauthFindings.length)} flagged.`,
    metrics: [
      { label: "OAuth apps tracked", value: fmtNumber(oauthAssets.length) },
      { label: "Risky grants", value: fmtNumber(oauthFindings.length) },
      { label: "Publicly accessible apps", value: fmtNumber(publicOauthApps) }
    ],
    items: describeFindings(oauthFindings, {
      severity: "INFO",
      title: "No risky OAuth grants detected this period.",
      riskScore: 0
    })
  };

  // ─── Mailbox Security ──────────────────────────────────────────────────
  const mailboxFindings = partitionFindings(openFindings, [
    GWS_RULES.FORWARDING_ENABLED,
    GWS_RULES.MAILBOX_DELEGATION,
    GWS_RULES.LEGACY_MAIL_AUTH,
    GWS_RULES.FORWARDING_DELEGATE_SEND_AS
  ]);
  const mailboxScore = scoreFromFindings(mailboxFindings);
  const mailboxCategory = {
    key: "mailbox_security",
    label: "Mailbox Security",
    icon: "✉️",
    score: Math.round(mailboxScore),
    status: statusForScore(mailboxScore),
    summary: `${fmtNumber(mailboxFindings.length)} open mailbox-state findings.`,
    metrics: [
      {
        label: "Forwarding rules",
        value: fmtNumber(
          partitionFindings(openFindings, [GWS_RULES.FORWARDING_ENABLED]).length
        )
      },
      {
        label: "Mailbox delegations",
        value: fmtNumber(
          partitionFindings(openFindings, [GWS_RULES.MAILBOX_DELEGATION]).length
        )
      },
      {
        label: "Legacy auth",
        value: fmtNumber(
          partitionFindings(openFindings, [GWS_RULES.LEGACY_MAIL_AUTH]).length
        )
      },
      {
        label: "Forward+delegate combos",
        value: fmtNumber(
          partitionFindings(openFindings, [GWS_RULES.FORWARDING_DELEGATE_SEND_AS]).length
        )
      }
    ],
    items: describeFindings(mailboxFindings, {
      severity: "INFO",
      title: "Mailbox configuration is clean — no forwarding/delegation/legacy-auth findings.",
      riskScore: 0
    })
  };

  // ─── Sharing & Data Exposure ───────────────────────────────────────────
  const sharingFindings = partitionFindings(openFindings, [GWS_RULES.EXTERNAL_SHARING]);
  const publicSensitive = sensitiveAssets.filter((a) => a.exposureLevel === "PUBLIC").length;
  const sharingPenalty = publicSensitive * 8;
  const sharingScore = Math.max(0, scoreFromFindings(sharingFindings) - sharingPenalty);
  const sharingCategory = {
    key: "sharing_exposure",
    label: "Sharing & Data Exposure",
    icon: "🔗",
    score: Math.round(sharingScore),
    status: statusForScore(sharingScore),
    summary: `${fmtNumber(sensitiveAssets.length)} sensitive-data assets tracked; ${fmtNumber(publicSensitive)} publicly exposed.`,
    metrics: [
      { label: "External-sharing findings", value: fmtNumber(sharingFindings.length) },
      { label: "Sensitive-data assets", value: fmtNumber(sensitiveAssets.length) },
      { label: "Publicly exposed sensitive", value: fmtNumber(publicSensitive) }
    ],
    items: describeFindings(sharingFindings, {
      severity: publicSensitive > 0 ? "MEDIUM" : "INFO",
      title:
        publicSensitive > 0
          ? `${publicSensitive} sensitive-data asset${publicSensitive === 1 ? "" : "s"} marked publicly exposed.`
          : "External-sharing posture is healthy.",
      riskScore: 0
    })
  };

  // ─── Domain-Wide Delegation ────────────────────────────────────────────
  const dwdConfigured = integrations.filter(
    (i) => !!(i.googleMailboxScanEnabled && i.googleMailboxScanClientEmail)
  );
  // DWD is a powerful capability with broad mailbox scopes; confirmed
  // configuration is fine, but operators should be aware it exists.
  const dwdScore = dwdConfigured.length === 0 ? 100 : 90 - Math.min(20, dwdConfigured.length * 4);
  const dwdCategory = {
    key: "domain_wide_delegation",
    label: "Domain-Wide Delegation",
    icon: "🗝️",
    score: Math.round(dwdScore),
    status: statusForScore(dwdScore),
    summary:
      dwdConfigured.length === 0
        ? "Domain-wide delegation is not configured."
        : `${fmtNumber(dwdConfigured.length)} workspace${dwdConfigured.length === 1 ? "" : "s"} have DWD configured for mailbox scanning.`,
    metrics: [
      { label: "Workspaces with DWD", value: fmtNumber(dwdConfigured.length) },
      { label: "Workspaces total", value: fmtNumber(integrations.length) }
    ],
    items: dwdConfigured.length
      ? dwdConfigured.map((i) => ({
          severity: "INFO",
          title: `${i.displayName} (${i.externalAccountId}) · ${i.googleMailboxScanClientEmail}`,
          riskScore: 0
        }))
      : [
          {
            severity: "INFO",
            title: "No domain-wide-delegation service account configured.",
            riskScore: 0
          }
        ]
  };

  return [
    identityCategory,
    adminCategory,
    oauthCategory,
    mailboxCategory,
    sharingCategory,
    dwdCategory
  ];
}

export function compositeScore(categories) {
  let weighted = 0;
  let weightSum = 0;
  for (const cat of categories) {
    const weight = CATEGORY_WEIGHTS[cat.key] ?? 0.1;
    weighted += cat.score * weight;
    weightSum += weight;
  }
  return weightSum === 0 ? 0 : Math.round(weighted / weightSum);
}

function buildRecommendations(categories) {
  const recs = [];
  for (const cat of categories) {
    if (cat.status === "FAIL") {
      recs.push(`Prioritize ${cat.label.toLowerCase()} — currently failing (${cat.score}/100).`);
    }
  }
  if (recs.length === 0) {
    for (const cat of categories) {
      if (cat.status === "WARN") {
        recs.push(`Review ${cat.label.toLowerCase()} to lift the score above 80.`);
      }
    }
  }
  if (recs.length === 0) {
    recs.push(
      "Posture is healthy across all six categories — maintain current cadence and re-run the assessment next period."
    );
  }
  return recs;
}

function renderCategoryCard(cat) {
  const color = STATUS_COLORS[cat.status] ?? "#475569";
  const bg = STATUS_BG[cat.status] ?? "#f1f5f9";
  const metrics = cat.metrics
    .map(
      (m) =>
        `<div class="metric"><div class="metric-label">${escapeHtml(m.label)}</div><div class="metric-value">${escapeHtml(m.value)}</div></div>`
    )
    .join("");
  const items = cat.items
    .map((it) => {
      const sevClass = `sev-${(it.severity ?? "info").toLowerCase()}`;
      return `<li>
        <span class="badge ${sevClass}">${escapeHtml(it.severity ?? "INFO")}</span>
        ${escapeHtml(it.title)}
        ${it.riskScore ? `<span class="muted small"> · risk ${it.riskScore}</span>` : ""}
      </li>`;
    })
    .join("");
  return `<section class="category-card">
    <header class="cat-head">
      <div class="cat-title">
        <span class="cat-icon">${cat.icon}</span>
        <h3>${escapeHtml(cat.label)}</h3>
      </div>
      <div class="cat-score" style="background:${bg};color:${color}">
        <strong>${cat.score}</strong><span class="muted">/100</span>
        <span class="cat-status">${cat.status}</span>
      </div>
    </header>
    <p class="cat-summary">${escapeHtml(cat.summary)}</p>
    <div class="metric-row">${metrics}</div>
    <ul class="cat-items">${items}</ul>
  </section>`;
}

function renderHtml(report, data, categories, overallScore, overallGrade, recommendations) {
  const { organization, integrations, openFindings, periodFindings } = data;
  const periodLabel = `${report.periodStart.toISOString().slice(0, 10)} → ${report.periodEnd.toISOString().slice(0, 10)}`;
  const workspaceRows =
    integrations.length === 0
      ? `<tr><td colspan="4" class="muted">No Google Workspace integrations connected.</td></tr>`
      : integrations
          .map(
            (i) => `<tr>
              <td>${escapeHtml(i.displayName)}</td>
              <td>${escapeHtml(i.externalAccountId)}</td>
              <td>${escapeHtml(i.status)}</td>
              <td>${escapeHtml(i.mode)}</td>
            </tr>`
          )
          .join("");

  const categoryCards = categories.map(renderCategoryCard).join("");
  const recList = recommendations
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");

  const periodFindingsBySeverity = periodFindings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const periodTotal = periodFindings.length;
  const openTotal = openFindings.length;

  const gradeColor = STATUS_COLORS[statusForScore(overallScore)] ?? "#475569";
  const gradeBg = STATUS_BG[statusForScore(overallScore)] ?? "#f1f5f9";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(report.title)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0; background: #f8fafc; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.5; }
  .container { max-width: 920px; margin: 0 auto; padding: 32px; }
  header.report-header { display: flex; align-items: center; justify-content: space-between; gap: 24px; border-bottom: 1px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 28px; }
  header.report-header h1 { margin: 0 0 4px; font-size: 24px; color: #0f172a; }
  header.report-header .meta { color: #475569; font-size: 13px; }
  .grade-pill { display: flex; flex-direction: column; align-items: center; padding: 14px 22px; border-radius: 12px; background: ${gradeBg}; color: ${gradeColor}; min-width: 110px; text-align: center; }
  .grade-pill .grade { font-size: 38px; font-weight: 700; line-height: 1; }
  .grade-pill .grade-score { font-size: 13px; margin-top: 6px; opacity: .85; }
  h2 { font-size: 16px; color: #0f172a; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: .05em; }
  h3 { font-size: 15px; color: #0f172a; margin: 0; }
  p, li { font-size: 13px; color: #334155; }
  .scope-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .scope-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; }
  .scope-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #64748b; margin-bottom: 4px; }
  .scope-card .value { font-size: 22px; font-weight: 600; color: #0f172a; }
  .scope-card .sub { font-size: 12px; color: #64748b; margin-top: 4px; }
  .categories { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .category-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
  .cat-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
  .cat-title { display: flex; align-items: center; gap: 10px; }
  .cat-icon { font-size: 20px; }
  .cat-score { display: flex; align-items: baseline; gap: 4px; padding: 6px 10px; border-radius: 999px; font-size: 14px; }
  .cat-score strong { font-size: 18px; line-height: 1; }
  .cat-score .cat-status { margin-left: 8px; font-weight: 600; letter-spacing: .04em; font-size: 11px; }
  .cat-summary { color: #475569; font-size: 12.5px; margin: 4px 0 12px; }
  .metric-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 8px; margin-bottom: 12px; }
  .metric { background: #f8fafc; border-radius: 6px; padding: 8px 10px; }
  .metric-label { font-size: 10.5px; color: #64748b; text-transform: uppercase; letter-spacing: .04em; }
  .metric-value { font-size: 15px; font-weight: 600; color: #0f172a; margin-top: 2px; }
  .cat-items { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; }
  .cat-items li { font-size: 12.5px; color: #334155; padding: 6px 8px; background: #f8fafc; border-radius: 6px; }
  .panel { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
  table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 12px; text-align: left; font-size: 12.5px; border-bottom: 1px solid #e2e8f0; }
  th { background: #f1f5f9; color: #475569; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; font-size: 11px; }
  tr:last-child td { border-bottom: none; }
  .muted { color: #94a3b8; }
  .small { font-size: 11px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; margin-right: 6px; }
  .sev-critical { background: #fee2e2; color: #991b1b; }
  .sev-high { background: #ffedd5; color: #9a3412; }
  .sev-medium { background: #fef3c7; color: #854d0e; }
  .sev-low { background: #ccfbf1; color: #115e59; }
  .sev-info { background: #e5e7eb; color: #374151; }
  ul { padding-left: 18px; margin: 6px 0 12px; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 11px; text-align: center; }
  @media print {
    body { background: white; }
    .container { padding: 16px; max-width: 100%; }
    .category-card, .scope-card, .panel, table { break-inside: avoid; }
    .categories { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="container">
  <header class="report-header">
    <div>
      <h1>${escapeHtml(report.title)}</h1>
      <div class="meta">
        <strong>${escapeHtml(organization.name)}</strong> · ${escapeHtml(periodLabel)} · generated ${new Date().toISOString().slice(0, 10)}
      </div>
    </div>
    <div class="grade-pill">
      <span class="grade">${overallGrade}</span>
      <span class="grade-score">${overallScore}/100</span>
    </div>
  </header>

  <h2>Workspaces in scope</h2>
  <table>
    <thead><tr><th>Workspace</th><th>Domain</th><th>Status</th><th>Mode</th></tr></thead>
    <tbody>${workspaceRows}</tbody>
  </table>

  <h2>Snapshot</h2>
  <div class="scope-grid">
    <div class="scope-card"><div class="label">Workspaces</div><div class="value">${fmtNumber(integrations.length)}</div><div class="sub">${fmtNumber(integrations.filter((i) => i.status === "CONNECTED").length)} connected</div></div>
    <div class="scope-card"><div class="label">Open findings</div><div class="value">${fmtNumber(openTotal)}</div><div class="sub">${fmtNumber(openFindings.filter((f) => f.severity === "CRITICAL").length)} critical · ${fmtNumber(openFindings.filter((f) => f.severity === "HIGH").length)} high</div></div>
    <div class="scope-card"><div class="label">New this period</div><div class="value">${fmtNumber(periodTotal)}</div><div class="sub">${fmtNumber(periodFindingsBySeverity.CRITICAL ?? 0)} critical · ${fmtNumber(periodFindingsBySeverity.HIGH ?? 0)} high</div></div>
    <div class="scope-card"><div class="label">Audit activity</div><div class="value">${fmtNumber(data.auditCount)}</div><div class="sub">tenant audit log entries</div></div>
  </div>

  <h2>Assessment</h2>
  <div class="categories">${categoryCards}</div>

  <h2>Recommended actions</h2>
  <div class="panel"><ul>${recList}</ul></div>

  <footer>
    Aperio · Google Workspace security assessment · ${escapeHtml(organization.name)}.
    Scores are computed from the open findings, identities, and asset metadata
    observed for each connected workspace. Re-run the assessment after taking action
    to see the new grade.
  </footer>
</div>
</body>
</html>`;
}

export async function generateGoogleWorkspaceAssessment(reportId) {
  const report = await prisma.executiveReport.findUnique({
    where: { id: reportId }
  });
  if (!report) {
    throw new Error(`executive_report ${reportId} not found`);
  }
  if (report.status === "READY") {
    return report;
  }

  const data = await gatherWorkspaceData(report);
  const categories = buildCategories(data);
  const overallScore = compositeScore(categories);
  const overallGrade = scoreToGrade(overallScore);
  const recommendations = buildRecommendations(categories);

  const summary = `Google Workspace assessment scored ${overallScore}/100 (${overallGrade}). ${categories.filter((c) => c.status === "FAIL").length} failing, ${categories.filter((c) => c.status === "WARN").length} at risk.`;
  const html = renderHtml(report, data, categories, overallScore, overallGrade, recommendations);

  const root = artifactRoot();
  await mkdir(root, { recursive: true });
  const htmlPath = join(root, `${report.id}.html`);
  const pdfPath = join(root, `${report.id}.pdf`);
  await writeFile(htmlPath, html, "utf-8");

  let pdfWritten = false;
  try {
    pdfWritten = await renderPdfFromHtml(htmlPath, pdfPath);
  } catch (err) {
    process.stderr.write(`pdf render failed: ${err.message ?? err}\n`);
  }

  const kpiSnapshot = {
    template: "GOOGLE_WORKSPACE_ASSESSMENT",
    overallScore,
    overallGrade,
    categories: categories.map((c) => ({
      key: c.key,
      label: c.label,
      score: c.score,
      status: c.status,
      summary: c.summary
    })),
    scope: {
      workspaces: data.integrations.length,
      connectedWorkspaces: data.integrations.filter((i) => i.status === "CONNECTED").length,
      identities: data.identities.length,
      oauthApps: data.oauthAssets.length,
      sensitiveDataAssets: data.sensitiveAssets.length,
      openFindings: data.openFindings.length,
      periodFindings: data.periodFindings.length,
      auditEvents: data.auditCount
    },
    recommendations
  };

  await prisma.executiveReport.update({
    where: { id: report.id },
    data: {
      status: "READY",
      htmlPath,
      pdfPath: pdfWritten ? pdfPath : null,
      summary,
      kpiSnapshot,
      generatedAt: new Date(),
      errorMessage: null
    }
  });

  return { reportId: report.id, htmlPath, pdfPath: pdfWritten ? pdfPath : null };
}

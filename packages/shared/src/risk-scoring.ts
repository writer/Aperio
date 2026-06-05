import type { Severity } from "./types";

type RiskEvidence = Record<string, unknown> | null | undefined;

export type RiskScoreFindingLike = {
  riskScore: number;
  severity: Severity;
  status?: string | null;
  detectedAt?: string | Date | null;
  evidence?: RiskEvidence;
  provider?: string | null;
  integration?: {
    provider?: string | null;
  } | null;
};

const severityFloor: Record<Severity, number> = {
  CRITICAL: 88,
  HIGH: 68,
  MEDIUM: 45,
  LOW: 25,
  INFO: 10
};

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function valueAsString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function valueAsBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function valueAsNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function valueAsStringArray(value: unknown): string[] {
  if (typeof value === "string") {
    return value.trim().length > 0 ? [value] : [];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((entry) => valueAsString(entry))
    .filter((entry): entry is string => Boolean(entry));
}

function domainFromEmail(email: string | null | undefined) {
  if (!email) {
    return null;
  }

  const [, domain] = email.toLowerCase().split("@");
  return domain ?? null;
}

function parseDetectedAt(value: string | Date | null | undefined) {
  if (!value) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function providerFromFinding(finding: RiskScoreFindingLike) {
  const evidence =
    finding.evidence && typeof finding.evidence === "object"
      ? (finding.evidence as Record<string, unknown>)
      : null;

  return (
    finding.integration?.provider ??
    finding.provider ??
    valueAsString(evidence?.provider)
  );
}

function externalEmailCount(evidence: Record<string, unknown>) {
  const anchorEmail =
    valueAsString(evidence.mailbox) ??
    valueAsString(evidence.user) ??
    valueAsString(evidence.actor) ??
    valueAsString(evidence.target);
  const anchorDomain = domainFromEmail(anchorEmail);
  const emailCandidates = [
    ...valueAsStringArray(evidence.delegates),
    ...valueAsStringArray(evidence.sendAsAliases),
    ...valueAsStringArray(evidence.externalSendAsAliases),
    valueAsString(evidence.forwardedTo),
    valueAsString(evidence.recoveryEmail),
    valueAsString(evidence.externalActor),
    valueAsString(evidence.delegate)
  ].filter((entry): entry is string => Boolean(entry));

  const external = emailCandidates.filter((email) => {
    const domain = domainFromEmail(email);
    if (!domain || !anchorDomain) {
      return false;
    }
    return domain !== anchorDomain;
  });

  return new Set(external).size;
}

export function calculateFindingRiskScore(input: {
  baseRiskScore: number;
  severity: Severity;
  evidence?: RiskEvidence;
  detectedAt?: string | Date | null;
}) {
  const evidence =
    input.evidence && typeof input.evidence === "object"
      ? (input.evidence as Record<string, unknown>)
      : {};
  let score = Math.max(
    clamp(Math.round(input.baseRiskScore), 0, 100),
    severityFloor[input.severity]
  );
  let bonus = 0;

  const grantedRole = (
    valueAsString(evidence.grantedRole) ?? valueAsString(evidence.role) ?? ""
  ).toLowerCase();
  if (grantedRole.includes("super admin")) {
    bonus += 10;
  } else if (grantedRole.includes("admin")) {
    bonus += 6;
  }

  if (valueAsBoolean(evidence.delegatedAdmin) === true) {
    bonus += 4;
  }

  if (valueAsBoolean(evidence.mfaEnrolled) === false) {
    bonus += 10;
  }
  if (valueAsBoolean(evidence.mfaEnforced) === false) {
    bonus += 8;
  }

  const visibility = (
    valueAsString(evidence.visibility) ?? valueAsString(evidence.exposureLevel) ?? ""
  ).toLowerCase();
  if (
    visibility.includes("public") ||
    visibility.includes("anyone") ||
    visibility.includes("shared_externally")
  ) {
    bonus += 10;
  } else if (visibility.includes("external")) {
    bonus += 6;
  }

  const riskReason = (valueAsString(evidence.riskReason) ?? "").toLowerCase();
  if (riskReason.includes("full mailbox") || riskReason.includes("mailbox-settings")) {
    bonus += 8;
  } else if (riskReason.includes("mailbox")) {
    bonus += 4;
  }

  const scopeCount =
    valueAsNumber(evidence.scopeCount) ?? valueAsStringArray(evidence.scopes).length;
  bonus += Math.min(8, Math.max(0, scopeCount - 1));

  const delegateCount =
    valueAsNumber(evidence.delegateCount) ??
    valueAsStringArray(evidence.delegates).length;
  const sendAsCount =
    valueAsNumber(evidence.sendAsCount) ??
    valueAsStringArray(evidence.sendAsAliases).length;
  bonus += Math.min(8, delegateCount * 2 + sendAsCount * 2);

  if (valueAsStringArray(evidence.comboKinds).length > 1) {
    bonus += 8;
  }

  bonus += Math.min(12, externalEmailCount(evidence) * 3);

  const detectedAt = parseDetectedAt(input.detectedAt);
  if (detectedAt) {
    const ageMs = Date.now() - detectedAt.getTime();
    if (ageMs <= 24 * 60 * 60 * 1000) {
      bonus += 4;
    } else if (ageMs <= 7 * 24 * 60 * 60 * 1000) {
      bonus += 2;
    } else if (ageMs > 90 * 24 * 60 * 60 * 1000) {
      bonus -= 8;
    } else if (ageMs > 30 * 24 * 60 * 60 * 1000) {
      bonus -= 4;
    }
  }

  score += bonus;
  return clamp(Math.round(score), 0, 100);
}

export function aggregateRiskScore(findings: RiskScoreFindingLike[]) {
  const activeFindings = findings.filter((finding) => finding.status !== "RESOLVED" && finding.status !== "MUTED");

  if (activeFindings.length === 0) {
    return 0;
  }

  const sortedScores = [...activeFindings]
    .map((finding) => clamp(Math.round(finding.riskScore), 0, 100))
    .sort((left, right) => right - left);
  const highest = sortedScores[0] ?? 0;
  const residual = sortedScores
    .slice(1)
    .reduce(
      (sum, score, index) =>
        sum + score * ([0.2, 0.12, 0.08, 0.05][index] ?? 0.03),
      0
    );
  const criticalCount = activeFindings.filter(
    (finding) => finding.severity === "CRITICAL"
  ).length;
  const highCount = activeFindings.filter(
    (finding) => finding.severity === "HIGH"
  ).length;
  const recentHighCount = activeFindings.filter((finding) => {
    const detectedAt = parseDetectedAt(finding.detectedAt);
    return (
      finding.riskScore >= 70 &&
      detectedAt !== null &&
      Date.now() - detectedAt.getTime() <= 7 * 24 * 60 * 60 * 1000
    );
  }).length;
  const providerCount = new Set(
    activeFindings
      .map((finding) => providerFromFinding(finding))
      .filter((provider): provider is string => Boolean(provider))
  ).size;

  return clamp(
    Math.round(
      highest * 0.72 +
        residual +
        Math.min(14, criticalCount * 6 + highCount * 2) +
        Math.min(8, Math.max(0, providerCount - 1) * 2) +
        Math.min(8, recentHighCount * 2)
    ),
    0,
    100
  );
}

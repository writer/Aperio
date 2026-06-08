// Shared helpers for report generators (executive summary, vendor
// assessments). Keeps formatting, HTML escaping, artifact paths, and the
// optional Puppeteer-based PDF rasterizer in one place so each generator can
// stay focused on its own data gathering and narrative shape.

import { resolve } from "node:path";

export function artifactRoot() {
  const fromEnv = (process.env.APERIO_REPORT_EXPORT_DIR ?? "").trim();
  return resolve(fromEnv || "./generated/reports");
}

export function escapeHtml(value) {
  if (value == null) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function fmtPercent(value) {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${value.toFixed(1)}%`;
}

export function fmtNumber(value) {
  if (value == null || !Number.isFinite(value)) return "—";
  return value.toLocaleString("en-US");
}

export function fmtHours(value) {
  if (value == null || !Number.isFinite(value)) return "—";
  if (value < 1) return `${(value * 60).toFixed(0)}m`;
  if (value < 48) return `${value.toFixed(1)}h`;
  return `${(value / 24).toFixed(1)}d`;
}

export function percentDelta(current, previous) {
  if (previous === 0 && current === 0) return 0;
  if (previous === 0) return 100;
  return ((current - previous) / previous) * 100;
}

export async function renderPdfFromHtml(htmlPath, pdfPath) {
  let puppeteer;
  try {
    puppeteer = await import("puppeteer");
  } catch (err) {
    process.stderr.write(
      `puppeteer not available, skipping PDF render: ${err.message ?? err}\n`
    );
    return false;
  }
  const browser = await puppeteer.default.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });
  try {
    const page = await browser.newPage();
    await page.goto(`file://${htmlPath}`, { waitUntil: "networkidle0" });
    await page.pdf({
      path: pdfPath,
      format: "Letter",
      printBackground: true,
      margin: { top: "0.6in", bottom: "0.6in", left: "0.5in", right: "0.5in" }
    });
    return true;
  } finally {
    await browser.close();
  }
}

// Composite letter grade from a 0-100 score. Used by assessment-style reports
// so executives have a quick top-of-page signal without needing to read the
// underlying category breakdown.
export function scoreToGrade(score) {
  if (!Number.isFinite(score)) return "—";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

// Status classification for individual assessment categories: PASS for healthy
// signals, WARN for issues worth addressing but not urgent, FAIL for issues
// the operator should action this period.
export function statusForScore(score) {
  if (!Number.isFinite(score)) return "PASS";
  if (score >= 80) return "PASS";
  if (score >= 60) return "WARN";
  return "FAIL";
}

export const STATUS_COLORS = {
  PASS: "#15803d",
  WARN: "#b45309",
  FAIL: "#b91c1c"
};

export const STATUS_BG = {
  PASS: "#dcfce7",
  WARN: "#fef3c7",
  FAIL: "#fee2e2"
};

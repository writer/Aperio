#!/usr/bin/env node
// Thin CLI shim invoked by the Go service: `node workers/executive-report-cli.mjs <reportId>`.
// Loads the report row, dispatches to the appropriate generator based on the
// stored template, and persists FAILED on errors so the UI never gets stuck on
// GENERATING.

import { generateExecutiveReport } from "./executive-report-generator.mjs";
import { generateGoogleWorkspaceAssessment } from "./google-workspace-assessment-generator.mjs";
import { prisma } from "../packages/db/src/client.mjs";

async function runForReport(reportId) {
  const row = await prisma.executiveReport.findUnique({
    where: { id: reportId },
    select: { template: true }
  });
  if (!row) {
    throw new Error(`executive_report ${reportId} not found`);
  }
  switch (row.template) {
    case "GOOGLE_WORKSPACE_ASSESSMENT":
      return generateGoogleWorkspaceAssessment(reportId);
    case "EXECUTIVE_SUMMARY":
    default:
      return generateExecutiveReport(reportId);
  }
}

async function main() {
  const reportId = process.argv[2];
  if (!reportId) {
    process.stderr.write("usage: executive-report-cli.mjs <reportId>\n");
    process.exit(2);
  }

  try {
    const result = await runForReport(reportId);
    process.stdout.write(JSON.stringify(result) + "\n");
    await prisma.$disconnect();
    process.exit(0);
  } catch (err) {
    const message = err?.message ?? String(err);
    process.stderr.write(`executive-report-cli failed: ${message}\n`);
    try {
      await prisma.executiveReport.update({
        where: { id: reportId },
        data: {
          status: "FAILED",
          errorMessage: message.slice(0, 1000),
          generatedAt: new Date()
        }
      });
    } catch {
      // Best-effort error persistence; the Go side also has its own fallback.
    }
    await prisma.$disconnect();
    process.exit(1);
  }
}

void main();

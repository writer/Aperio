#!/usr/bin/env node
import {
  appendStepSummary,
  parseArgs,
  readJSON,
  redact,
  requestGitHubJSON,
  truncate,
  writeJSON,
  writeText,
} from "./droid-common.mjs";

const args = parseArgs();
const preflightPath = args["preflight-json"] || process.env.DROID_PREFLIGHT_JSON_OUT || "tmp/droid-preflight.json";
const sastPath = args["sast-json"] || process.env.DROID_SAST_JSON_OUT || "tmp/droid-sast-context.json";
const ciPath = args["ci-json"] || process.env.DROID_CI_JSON_OUT || "tmp/droid-ci-context.json";
const jsonOut = args["json-out"] || process.env.DROID_CONTEXT_JSON_OUT || "tmp/droid-review-context.json";
const markdownOut = args["markdown-out"] || process.env.DROID_CONTEXT_OUT || "tmp/droid-review-context.md";

const preflight = readJSON(preflightPath, {});
const sast = readJSON(sastPath, {});
const ci = readJSON(ciPath, {});

const context = {
  preflight,
  sast,
  ci,
  generated_at: new Date().toISOString(),
};

function section(title, lines) {
  return [`## ${title}`, "", ...lines, ""].join("\n");
}

const riskLines = (preflight.risk_categories || []).map((category) => (
  `- ${category.label || category.id}: ${category.file_count || 0} file(s)`
));
const probeLines = (preflight.probe_plan || []).map((item) => `- ${item}`);
const sastLines = (sast.findings || []).slice(0, 20).map((finding) => (
  `- [${finding.severity}] ${finding.file}:${finding.line} \`${finding.rule}\` — ${finding.message}`
));
const semgrepLines = (sast.semgrep?.results || []).slice(0, 10).map((finding) => (
  `- [${finding.extra?.severity || "INFO"}] ${finding.path}:${finding.start?.line || 1} \`${finding.check_id}\` — ${finding.extra?.message || "Semgrep finding"}`
));
const ciLines = (ci.interesting || []).slice(0, 20).map((run) => (
  `- ${run.name}: ${run.status}${run.conclusion ? `/${run.conclusion}` : ""}${run.details_url ? ` — ${run.details_url}` : ""}`
));

const markdown = redact([
  "<!-- droid-review-context -->",
  "# Droid Recursive Review Context",
  "",
  section("Preflight", [
    `- Run Droid review: ${preflight.run_droid_review ?? "unknown"}`,
    `- Review model: \`${preflight.review_model ?? "unknown"}\``,
    `- Reason: ${preflight.review_reason ?? "unknown"}`,
    `- Changed files: ${preflight.changed_file_count ?? 0}`,
    "",
    "### Risk categories",
    "",
    ...(riskLines.length ? riskLines : ["- none"]),
    "",
    "### Probe plan",
    "",
    ...(probeLines.length ? probeLines : ["- none"]),
  ]),
  section("SAST Context", [
    `- Lightweight findings: ${sast.finding_count ?? 0}`,
    `- Semgrep status: ${sast.semgrep?.status ?? "unknown"}`,
    "",
    "### Lightweight findings",
    "",
    ...(sastLines.length ? sastLines : ["- none"]),
    "",
    "### Semgrep findings",
    "",
    ...(semgrepLines.length ? semgrepLines : ["- none"]),
  ]),
  section("CI Context", [
    `- Status: ${ci.status ?? "unknown"}`,
    `- Check runs: ${ci.total_count ?? 0}`,
    "",
    "### Non-success or pending checks",
    "",
    ...(ciLines.length ? ciLines : ["- none"]),
  ]),
].join("\n"));

async function upsertComment(body) {
  const repository = process.env.GITHUB_REPOSITORY;
  const prNumber = process.env.PR_NUMBER || process.env.DROID_PR;
  if (!repository || !prNumber || !(process.env.GH_TOKEN || process.env.GITHUB_TOKEN)) {
    return;
  }
  const comments = await requestGitHubJSON("GET", `/repos/${repository}/issues/${prNumber}/comments?per_page=100`);
  const existing = (comments || []).find((comment) => String(comment.body || "").includes("<!-- droid-review-context -->"));
  const boundedBody = truncate(body, 60000);
  if (existing) {
    await requestGitHubJSON("PATCH", `/repos/${repository}/issues/comments/${existing.id}`, { body: boundedBody });
    return;
  }
  await requestGitHubJSON("POST", `/repos/${repository}/issues/${prNumber}/comments`, { body: boundedBody });
}

writeJSON(jsonOut, context);
writeText(markdownOut, markdown);
appendStepSummary(markdown);

if (args["post-comment"] === "true" || process.env.DROID_CONTEXT_POST_COMMENT === "true") {
  await upsertComment(markdown);
}

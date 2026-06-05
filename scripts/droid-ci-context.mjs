#!/usr/bin/env node
import {
  appendStepSummary,
  parseArgs,
  redact,
  requestGitHubJSON,
  truncate,
  writeJSON,
  writeText,
} from "./droid-common.mjs";

const args = parseArgs();
const head = args.head || process.env.DROID_REVIEW_HEAD || process.env.GITHUB_SHA || "HEAD";
const repository = args.repository || process.env.GITHUB_REPOSITORY || "";
const jsonOut = args["json-out"] || process.env.DROID_CI_JSON_OUT || "tmp/droid-ci-context.json";
const markdownOut = args["markdown-out"] || process.env.DROID_CI_OUT || "tmp/droid-ci-context.md";

async function collect() {
  if (!repository || !process.env.GH_TOKEN && !process.env.GITHUB_TOKEN) {
    return {
      status: "unavailable",
      reason: "GITHUB_REPOSITORY and GH_TOKEN are required",
      head,
      check_runs: [],
    };
  }

  const response = await requestGitHubJSON("GET", `/repos/${repository}/commits/${head}/check-runs?per_page=100`);
  const checkRuns = response.check_runs || [];
  const interesting = checkRuns.filter((run) => (
    run.status !== "completed" ||
    !["success", "skipped", "neutral"].includes(run.conclusion || "")
  ));

  const annotations = [];
  for (const run of interesting.filter((item) => item.conclusion && item.conclusion !== "success").slice(0, 10)) {
    try {
      const runAnnotations = await requestGitHubJSON("GET", `/repos/${repository}/check-runs/${run.id}/annotations?per_page=20`);
      for (const annotation of runAnnotations || []) {
        annotations.push({
          check_name: run.name,
          path: annotation.path,
          start_line: annotation.start_line,
          annotation_level: annotation.annotation_level,
          message: truncate(redact(annotation.message), 500),
        });
      }
    } catch (error) {
      annotations.push({
        check_name: run.name,
        annotation_level: "notice",
        message: `Could not fetch annotations: ${redact(error.message)}`,
      });
    }
  }

  return {
    status: "ok",
    head,
    total_count: checkRuns.length,
    check_runs: checkRuns.map((run) => ({
      name: run.name,
      status: run.status,
      conclusion: run.conclusion,
      details_url: run.details_url,
      started_at: run.started_at,
      completed_at: run.completed_at,
    })),
    interesting: interesting.map((run) => ({
      name: run.name,
      status: run.status,
      conclusion: run.conclusion,
      details_url: run.details_url,
    })),
    annotations,
  };
}

const result = await collect();
const completed = result.check_runs?.filter((run) => run.status === "completed").length || 0;
const failed = result.check_runs?.filter((run) => run.status === "completed" && !["success", "skipped", "neutral"].includes(run.conclusion || "")).length || 0;
const pending = result.check_runs?.filter((run) => run.status !== "completed").length || 0;
const interestingLines = (result.interesting || []).slice(0, 25).map((run) => (
  `- ${run.name}: ${run.status}${run.conclusion ? `/${run.conclusion}` : ""}${run.details_url ? ` — ${run.details_url}` : ""}`
));
const annotationLines = (result.annotations || []).slice(0, 20).map((annotation) => (
  `- ${annotation.check_name}: ${annotation.path || "n/a"}:${annotation.start_line || 1} — ${annotation.message}`
));
const markdown = [
  "### Droid CI Context",
  "",
  `- Status: ${result.status}${result.reason ? ` (${result.reason})` : ""}`,
  `- Check runs: ${result.total_count || 0}`,
  `- Completed: ${completed}`,
  `- Failed/actionable: ${failed}`,
  `- Pending: ${pending}`,
  "",
  interestingLines.length ? ["#### Non-success or pending checks", "", ...interestingLines].join("\n") : "#### Non-success or pending checks\n\n- none",
  "",
  annotationLines.length ? ["#### Check annotations", "", ...annotationLines].join("\n") : "#### Check annotations\n\n- none",
].join("\n");

writeJSON(jsonOut, result);
writeText(markdownOut, markdown);
appendStepSummary(markdown);

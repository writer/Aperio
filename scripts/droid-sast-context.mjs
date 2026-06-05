#!/usr/bin/env node
import fs from "node:fs";
import {
  appendStepSummary,
  gitChangedFiles,
  parseArgs,
  readJSON,
  redact,
  run,
  truncate,
  writeJSON,
  writeText,
} from "./droid-common.mjs";

const args = parseArgs();
const base = args.base || process.env.DROID_REVIEW_BASE || "";
const head = args.head || process.env.DROID_REVIEW_HEAD || process.env.GITHUB_SHA || "HEAD";
const jsonOut = args["json-out"] || process.env.DROID_SAST_JSON_OUT || "tmp/droid-sast-context.json";
const markdownOut = args["markdown-out"] || process.env.DROID_SAST_OUT || "tmp/droid-sast-context.md";
const preflight = readJSON(args["preflight-json"] || process.env.DROID_PREFLIGHT_JSON_OUT || "tmp/droid-preflight.json", {});
const changedFiles = preflight.changed_files?.length ? preflight.changed_files : gitChangedFiles(base, head);

const sourceExtensions = /\.(?:cjs|cts|js|jsx|mjs|mts|ts|tsx|ya?ml|json|prisma)$/i;
const findings = [];

function addFinding(file, line, rule, severity, message, excerpt) {
  findings.push({
    file,
    line,
    rule,
    severity,
    message,
    excerpt: truncate(redact(excerpt), 300),
  });
}

function scanSourceFile(file) {
  if (file.startsWith(".semgrep/")) {
    return;
  }
  if (!sourceExtensions.test(file) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    return;
  }
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    if (/\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/.test(line)) {
      addFinding(file, lineNumber, "unsafe-prisma-raw", "high", "Unsafe Prisma raw query API touched.", line);
    }
    if (/\b(?:eval|Function)\s*\(/.test(line)) {
      addFinding(file, lineNumber, "dynamic-code-execution", "high", "Dynamic code execution primitive touched.", line);
    }
    if (/\b(?:exec|execSync)\s*\(/.test(line) || /shell\s*:\s*true/.test(line)) {
      addFinding(file, lineNumber, "command-execution", "medium", "Command execution path touched; validate input handling.", line);
    }
    if (/console\.(?:log|info|warn|error)\s*\(.*(?:secret|token|password|api[_-]?key|authorization)/i.test(line)) {
      addFinding(file, lineNumber, "credential-logging", "high", "Potential credential logging path touched.", line);
    }
    if (file.startsWith("apps/web/") && /process\.env\.(?!NEXT_PUBLIC_|NODE_ENV\b)[A-Z0-9_]+/.test(line)) {
      addFinding(file, lineNumber, "client-env-secret", "medium", "Non-public environment variable referenced from web app path.", line);
    }
    if (/origin\s*:\s*["']\*["']/.test(line)) {
      addFinding(file, lineNumber, "wildcard-cors", "medium", "Wildcard CORS origin touched.", line);
    }
    if (/(?:secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*["']none["'])/.test(line)) {
      addFinding(file, lineNumber, "cookie-hardening", "medium", "Cookie hardening-sensitive setting touched.", line);
    }
    if (file.startsWith(".github/workflows/")) {
      const usesMatch = line.match(/uses:\s*([^#\s]+)/);
      if (usesMatch) {
        const ref = usesMatch[1].split("@")[1] || "";
        if (!/^[a-f0-9]{40}$/i.test(ref)) {
          addFinding(file, lineNumber, "unpinned-github-action", "medium", "GitHub Action is not pinned to a full commit SHA.", line);
        }
      }
      if (/permissions:\s*write-all/.test(line) || /contents:\s*write/.test(line)) {
        addFinding(file, lineNumber, "workflow-write-permission", "low", "Workflow write permission touched; verify it is required.", line);
      }
    }
  });
}

for (const file of changedFiles) {
  scanSourceFile(file);
}

function runSemgrep() {
  if (!fs.existsSync(".semgrep/aperio.yml")) {
    return { status: "unavailable", reason: ".semgrep/aperio.yml not found", results: [] };
  }
  const targets = changedFiles.filter((file) => !file.startsWith(".semgrep/") && sourceExtensions.test(file) && fs.existsSync(file));
  if (targets.length === 0) {
    return { status: "skipped", reason: "no changed Semgrep-supported files", results: [] };
  }
  const version = run("semgrep", ["--version"]);
  if (version.status !== 0) {
    return { status: "unavailable", reason: "semgrep is not installed", results: [] };
  }
  const result = run("semgrep", ["--config", ".semgrep/aperio.yml", "--json", "--quiet", ...targets], { maxBuffer: 20 * 1024 * 1024 });
  const parsed = result.stdout ? JSON.parse(result.stdout) : {};
  return {
    status: result.status === 0 ? "ok" : "findings_or_error",
    reason: result.stderr ? truncate(redact(result.stderr), 1000) : "",
    results: (parsed.results || []).map((finding) => ({
      check_id: finding.check_id,
      path: finding.path,
      start: finding.start,
      extra: {
        message: finding.extra?.message,
        severity: finding.extra?.severity,
      },
    })),
  };
}

let semgrep;
try {
  semgrep = runSemgrep();
} catch (error) {
  semgrep = { status: "error", reason: redact(error.message), results: [] };
}

const result = {
  base,
  head,
  changed_file_count: changedFiles.length,
  finding_count: findings.length,
  findings,
  semgrep,
};

const findingLines = findings.slice(0, 30).map((finding) => (
  `- [${finding.severity}] ${finding.file}:${finding.line} \`${finding.rule}\` — ${finding.message}`
));
const semgrepLines = (semgrep.results || []).slice(0, 20).map((finding) => (
  `- [${finding.extra?.severity || "INFO"}] ${finding.path}:${finding.start?.line || 1} \`${finding.check_id}\` — ${finding.extra?.message || "Semgrep finding"}`
));
const markdown = [
  "### Droid SAST Context",
  "",
  `- Changed files scanned: ${changedFiles.filter((file) => sourceExtensions.test(file)).length}`,
  `- Lightweight findings: ${findings.length}`,
  `- Semgrep status: ${semgrep.status}${semgrep.reason ? ` (${semgrep.reason})` : ""}`,
  "",
  findingLines.length ? ["#### Lightweight findings", "", ...findingLines].join("\n") : "#### Lightweight findings\n\n- none",
  "",
  semgrepLines.length ? ["#### Semgrep findings", "", ...semgrepLines].join("\n") : "#### Semgrep findings\n\n- none",
].join("\n");

writeJSON(jsonOut, result);
writeText(markdownOut, markdown);
appendStepSummary(markdown);

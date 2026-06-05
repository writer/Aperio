import { spawnSync } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";

export function parseArgs(argv = process.argv.slice(2)) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index];
    if (!raw.startsWith("--")) {
      continue;
    }
    const [key, inlineValue] = raw.slice(2).split("=", 2);
    if (inlineValue !== undefined) {
      args[key] = inlineValue;
      continue;
    }
    const next = argv[index + 1];
    if (next && !next.startsWith("--")) {
      args[key] = next;
      index += 1;
    } else {
      args[key] = "true";
    }
  }
  return args;
}

export function run(command, args = [], options = {}) {
  return spawnSync(command, args, {
    cwd: options.cwd ?? process.cwd(),
    encoding: "utf8",
    env: options.env ?? process.env,
    maxBuffer: options.maxBuffer ?? 10 * 1024 * 1024,
  });
}

export function gitChangedFiles(base, head) {
  const candidates = [];
  if (base && head) {
    candidates.push(["diff", "--name-only", "--diff-filter=ACMRTUXB", base, head]);
  }
  if (head) {
    candidates.push(["diff", "--name-only", "--diff-filter=ACMRTUXB", `${head}^`, head]);
  }
  candidates.push(["diff", "--name-only", "--diff-filter=ACMRTUXB", "HEAD~1", "HEAD"]);

  for (const args of candidates) {
    const result = run("git", args);
    if (result.status === 0) {
      return uniqueLines(result.stdout);
    }
  }
  return [];
}

export function gitDiff(base, head, file) {
  const args = ["diff", "--no-ext-diff", "--unified=0"];
  if (base && head) {
    args.push(base, head);
  } else {
    args.push("HEAD~1", "HEAD");
  }
  if (file) {
    args.push("--", file);
  }
  const result = run("git", args, { maxBuffer: 20 * 1024 * 1024 });
  return result.status === 0 ? result.stdout : "";
}

export function uniqueLines(value) {
  return Array.from(new Set(String(value ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean)));
}

export function ensureParentDir(filePath) {
  if (!filePath) {
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

export function writeJSON(filePath, data) {
  if (!filePath) {
    return;
  }
  ensureParentDir(filePath);
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`);
}

export function readJSON(filePath, fallback = null) {
  if (!filePath || !fs.existsSync(filePath)) {
    return fallback;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

export function writeText(filePath, text) {
  if (!filePath) {
    return;
  }
  ensureParentDir(filePath);
  fs.writeFileSync(filePath, `${String(text ?? "").trimEnd()}\n`);
}

export function appendStepSummary(markdown) {
  if (!process.env.GITHUB_STEP_SUMMARY) {
    return;
  }
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${String(markdown ?? "").trimEnd()}\n`);
}

export function writeGitHubOutputs(outputs) {
  if (!process.env.GITHUB_OUTPUT) {
    return;
  }
  const lines = [];
  for (const [key, value] of Object.entries(outputs)) {
    lines.push(`${key}=${String(value ?? "").replace(/\r?\n/g, " ")}`);
  }
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join("\n")}\n`);
}

export function redact(value) {
  return String(value ?? "")
    .replace(/\b(gh[opsu]_[A-Za-z0-9_]{20,})\b/g, "[redacted-token]")
    .replace(/\b(xox[baprs]-[A-Za-z0-9-]{20,})\b/g, "[redacted-token]")
    .replace(/\b(sk-[A-Za-z0-9_-]{20,})\b/g, "[redacted-token]")
    .replace(/\b(AKIA[0-9A-Z]{16})\b/g, "[redacted-access-key]")
    .replace(/((?:api[_-]?key|secret|token|password|authorization|bearer)\s*[:=]\s*)["']?[^"'\s,;]+/gi, "$1[redacted]");
}

export function truncate(value, max = 4000) {
  const text = String(value ?? "");
  if (text.length <= max) {
    return text;
  }
  return `${text.slice(0, max)}\n...[truncated ${text.length - max} chars]`;
}

export function requestGitHubJSON(method, apiPath, token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN, body = null) {
  return new Promise((resolve, reject) => {
    if (!token) {
      reject(new Error("GH_TOKEN is required"));
      return;
    }
    const payload = body == null ? null : JSON.stringify(body);
    const request = https.request(
      {
        hostname: "api.github.com",
        path: apiPath.startsWith("/") ? apiPath : `/${apiPath}`,
        method,
        headers: {
          "Accept": "application/vnd.github+json",
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
          "User-Agent": "aperio-droid-review-context",
          "X-GitHub-Api-Version": "2022-11-28",
          ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
        },
      },
      (response) => {
        let data = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          data += chunk;
        });
        response.on("end", () => {
          if (response.statusCode >= 200 && response.statusCode < 300) {
            resolve(data.trim() ? JSON.parse(data) : null);
            return;
          }
          reject(new Error(`GitHub API ${method} ${apiPath} failed with ${response.statusCode}: ${truncate(data, 500)}`));
        });
      },
    );
    request.on("error", reject);
    if (payload) {
      request.write(payload);
    }
    request.end();
  });
}

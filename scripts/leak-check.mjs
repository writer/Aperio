import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const ignoredDirs = new Set([
  ".git",
  ".next",
  "node_modules",
  "dist",
  "coverage",
  "gen",
  ".turbo"
]);
const ignoredFiles = new Set([".env.example"]);
const ignoredExtensions = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf"]);
const patterns = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key block"],
  [/AKIA[0-9A-Z]{16}/, "AWS access key"],
  [/(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{24,}["']/i, "hardcoded credential"]
];

const findings = [];

function walk(directory) {
  for (const entry of readdirSync(directory)) {
    if (ignoredDirs.has(entry)) continue;
    const path = join(directory, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      walk(path);
      continue;
    }
    if (!stat.isFile()) continue;
    const relativePath = path.slice(root.endsWith("/") ? root.length : root.length + 1);
    if (ignoredFiles.has(relativePath)) continue;
    if (ignoredExtensions.has(path.slice(path.lastIndexOf(".")).toLowerCase())) continue;
    const content = readFileSync(path, "utf8");
    const lines = content.split(/\r?\n/);
    for (const [pattern, label] of patterns) {
      for (const [index, line] of lines.entries()) {
        const normalized = line.toLowerCase();
        if (
          normalized.includes("placeholder") ||
          normalized.includes("example") ||
          normalized.includes("development-demo")
        ) {
          continue;
        }
        if (pattern.test(line)) {
          findings.push({ path: `${relativePath}:${index + 1}`, label });
        }
      }
    }
  }
}

walk(root);

if (findings.length > 0) {
  console.error("Potential secret leaks found:");
  for (const finding of findings) {
    console.error(`- ${finding.path}: ${finding.label}`);
  }
  process.exit(1);
}

console.log("No obvious secret leaks found.");

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function loadDevEnv() {
  const defaulted = new Set();
  loadEnvFile(path.join(root, ".env"));
  loadEnvFile(path.join(root, ".env.local"));
  applyDevDefaults(defaulted);
  return { defaulted };
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }
  for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const parsed = parseEnvLine(line);
    if (parsed && process.env[parsed.key] === undefined) {
      process.env[parsed.key] = parsed.value;
    }
  }
}

function parseEnvLine(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return null;
  }
  const withoutExport = trimmed.startsWith("export ") ? trimmed.slice("export ".length).trim() : trimmed;
  const equals = withoutExport.indexOf("=");
  if (equals <= 0) {
    return null;
  }
  const key = withoutExport.slice(0, equals).trim();
  let value = withoutExport.slice(equals + 1).trim();
  if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }
  return { key, value };
}

function applyDevDefaults(defaulted) {
  const webPort = process.env.APERIO_WEB_PORT ?? "3000";
  const defaults = {
    DATABASE_URL: "postgresql://aperio:aperio@127.0.0.1:5432/aperio?schema=public",
    APERIO_CONNECT_ADDR: ":4100",
    APERIO_WEB_ORIGIN: `http://localhost:${webPort}`,
    NEXT_PUBLIC_CONNECT_API_BASE_URL: "http://localhost:4100",
    APERIO_SESSION_IDLE_MINUTES: "120",
    APERIO_ENCRYPTION_KEY: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    APERIO_AUTH_SECRET: "development-demo-auth-secret-not-for-production",
    APERIO_EVENT_BUS: "noop",
    APERIO_NATS_URL: "nats://127.0.0.1:4222",
    APERIO_NATS_STREAM: "CEREBRO_EVENTS"
  };
  for (const [key, value] of Object.entries(defaults)) {
    if (!process.env[key]) {
      process.env[key] = value;
      defaulted.add(key);
    }
  }
}

async function main() {
  loadDevEnv();
  const [command, ...args] = process.argv.slice(2);
  if (!command) {
    console.error("usage: node scripts/dev-env.mjs <command> [...args]");
    process.exit(2);
  }
  const child = spawn(command, args, {
    cwd: root,
    env: process.env,
    stdio: "inherit",
    shell: process.platform === "win32"
  });
  child.on("error", (error) => {
    console.error(error.message);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    }
    process.exit(code ?? 1);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}

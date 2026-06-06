import { spawn } from "node:child_process";
import net from "node:net";
import readline from "node:readline";
import { loadDevEnv, root } from "./dev-env.mjs";

const devEnv = loadDevEnv();

const setupOnly = process.argv.includes("--setup-only");
const skipDocker = process.env.APERIO_DEV_SKIP_DOCKER === "1";
const skipMigrate = process.env.APERIO_DEV_SKIP_MIGRATE === "1";
const webPort = process.env.APERIO_WEB_PORT ?? "3000";

await avoidDefaultPortConflicts(devEnv.defaulted);
await setupInfra();
await run("npm", ["run", "db:generate"]);
if (!skipMigrate) {
  await run("npx", ["prisma", "migrate", "deploy", "--schema", "packages/db/prisma/schema.prisma"]);
}

if (setupOnly) {
  process.exit(0);
}

const children = [
  start("connect", "go", ["run", "./cmd/aperio"]),
  start("web", "npx", ["next", "dev", "apps/web", "-p", webPort])
];

let shuttingDown = false;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => shutdown(0));
}

async function avoidDefaultPortConflicts(defaulted) {
  if (skipDocker) {
    return;
  }
  if (defaulted.has("DATABASE_URL") && (await canConnect("127.0.0.1", 5432))) {
    const port = await freePort();
    process.env.APERIO_POSTGRES_PORT = String(port);
    process.env.DATABASE_URL = `postgresql://aperio:aperio@127.0.0.1:${port}/aperio?schema=public`;
    console.warn(`[dev] 127.0.0.1:5432 is in use; starting Aperio Postgres on ${port}`);
  }
  if (defaulted.has("APERIO_NATS_URL") && (await canConnect("127.0.0.1", 4222))) {
    const port = await freePort();
    process.env.APERIO_NATS_PORT = String(port);
    process.env.APERIO_NATS_URL = `nats://127.0.0.1:${port}`;
    console.warn(`[dev] 127.0.0.1:4222 is in use; starting Aperio NATS on ${port}`);
  }
  if (!process.env.APERIO_NATS_MONITOR_PORT && (await canConnect("127.0.0.1", 8222))) {
    process.env.APERIO_NATS_MONITOR_PORT = String(await freePort());
  }
}

async function setupInfra() {
  const services = [];
  if (!(await canConnect(databaseHost(), databasePort()))) {
    services.push("postgres");
  }
  if (!(await canConnect(natsHost(), natsPort()))) {
    services.push("nats");
  }
  if (!skipDocker && services.length > 0 && (await commandExists("docker"))) {
    await run("docker", ["compose", "up", "-d", ...services]);
  } else if (!skipDocker) {
    const reason = services.length === 0 ? "Postgres and NATS are already reachable" : "docker is not available";
    console.warn(`[dev] ${reason}; skipping docker compose startup`);
  }
  await waitForTcp("postgres", databaseHost(), databasePort(), 30_000);
  await waitForTcp("nats", natsHost(), natsPort(), 30_000);
}

function databaseHost() {
  return parsedURL(process.env.DATABASE_URL)?.hostname ?? "127.0.0.1";
}

function databasePort() {
  return Number(parsedURL(process.env.DATABASE_URL)?.port || 5432);
}

function natsHost() {
  return parsedURL(process.env.APERIO_NATS_URL)?.hostname ?? "127.0.0.1";
}

function natsPort() {
  return Number(parsedURL(process.env.APERIO_NATS_URL)?.port || 4222);
}

function parsedURL(value) {
  try {
    return value ? new URL(value) : null;
  } catch {
    return null;
  }
}

async function commandExists(command) {
  return new Promise((resolve) => {
    const probe = spawn(command, ["--version"], { stdio: "ignore" });
    probe.on("error", () => resolve(false));
    probe.on("exit", (code) => resolve(code === 0));
  });
}

async function waitForTcp(label, host, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await canConnect(host, port)) {
      console.log(`[dev] ${label} is reachable at ${host}:${port}`);
      return;
    }
    await sleep(500);
  }
  throw new Error(`${label} was not reachable at ${host}:${port}`);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address && typeof address === "object") {
          resolve(address.port);
        } else {
          reject(new Error("could not allocate a free local port"));
        }
      });
    });
  });
}

function canConnect(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 1000 });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(false));
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, env: process.env, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}`));
      }
    });
  });
}

function start(label, command, args) {
  const child = spawn(command, args, { cwd: root, env: process.env, stdio: ["ignore", "pipe", "pipe"] });
  pipe(label, child.stdout);
  pipe(label, child.stderr);
  child.on("exit", (code, signal) => {
    if (!shuttingDown) {
      console.error(`[${label}] exited with ${signal ?? code}`);
      shutdown(code ?? 1);
    }
  });
  child.on("error", (error) => {
    if (!shuttingDown) {
      console.error(`[${label}] ${error.message}`);
      shutdown(1);
    }
  });
  return child;
}

function pipe(label, stream) {
  readline.createInterface({ input: stream }).on("line", (line) => {
    console.log(`[${label}] ${line}`);
  });
}

function shutdown(exitCode) {
  shuttingDown = true;
  for (const child of children) {
    if (!child.killed) {
      child.kill("SIGTERM");
    }
  }
  setTimeout(() => process.exit(exitCode), 750).unref();
}

// Local-development configuration helper used by the Makefile.
//
// It is intentionally dependency-free (Node built-ins only) so it runs before
// `npm ci`, and it treats the canonical connection strings (DATABASE_URL and
// APERIO_NATS_URL) as the single source of truth for local infrastructure.
//
// Subcommands:
//   go-database-url        Print a pgx-safe DSN derived from DATABASE_URL.
//   db-host | db-port      Print the Postgres host/port from DATABASE_URL.
//   nats-port              Print the NATS client port from APERIO_NATS_URL.
//   nats-monitor-port      Print the NATS monitoring port.
//   wait <name> <target> [timeoutMs]
//                          Poll a TCP endpoint until reachable (target may be a
//                          URL or host:port). Exit 0 on success, 1 on timeout.
import net from "node:net";
import { loadDevEnv } from "./dev-env.mjs";

loadDevEnv();

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

function fail(message) {
  process.stderr.write(`dev-config: ${message}\n`);
  process.exit(1);
}

function parseURL(value, label) {
  const raw = (value ?? "").trim();
  if (!raw) {
    fail(`${label} is not set`);
  }
  try {
    return new URL(raw);
  } catch {
    return fail(`${label} is not a valid URL: ${raw}`);
  }
}

function databaseURL() {
  return parseURL(process.env.DATABASE_URL, "DATABASE_URL");
}

function natsURL() {
  return parseURL(process.env.APERIO_NATS_URL, "APERIO_NATS_URL");
}

// goDatabaseURL reconciles the Prisma connection string with what pgx accepts.
// Prisma encodes `?schema=public`, which Postgres rejects as an unknown startup
// parameter, and local Postgres has no TLS, so default `sslmode=prefer` errors.
function goDatabaseURL() {
  const url = databaseURL();
  url.searchParams.delete("schema");
  url.searchParams.delete("connection_limit");
  url.searchParams.delete("pgbouncer");
  if (!url.searchParams.has("sslmode") && LOCAL_HOSTS.has(url.hostname)) {
    url.searchParams.set("sslmode", "disable");
  }
  return url.toString();
}

function hostPort(url, defaultPort) {
  return {
    host: url.hostname || "127.0.0.1",
    port: Number(url.port || defaultPort)
  };
}

function resolveTarget(target) {
  if (target.includes("://")) {
    const url = parseURL(target, "target");
    return hostPort(url, 0);
  }
  const lastColon = target.lastIndexOf(":");
  if (lastColon === -1) {
    fail(`target must be a URL or host:port, got: ${target}`);
  }
  return {
    host: target.slice(0, lastColon) || "127.0.0.1",
    port: Number(target.slice(lastColon + 1))
  };
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

async function waitForTcp(name, target, timeoutMs) {
  const { host, port } = resolveTarget(target);
  if (!Number.isInteger(port) || port <= 0) {
    fail(`could not determine a port for ${name} from ${target}`);
  }
  // Stability check: docker-published Postgres briefly accepts on the
  // bound port during the image's init phase, then closes that socket
  // and rebinds. A single TCP-connect success therefore races against
  // the next caller (e.g. `prisma migrate deploy` against `127.0.0.1:5433`).
  // Requiring N consecutive successes spaced ~250ms apart bridges that
  // window without adding a pg client dependency. The cost for an
  // already-healthy service is <1s.
  const REQUIRED_CONSECUTIVE = 3;
  const POLL_INTERVAL_MS = 250;
  const deadline = Date.now() + timeoutMs;
  let consecutive = 0;
  for (;;) {
    if (await canConnect(host, port)) {
      consecutive += 1;
      if (consecutive >= REQUIRED_CONSECUTIVE) {
        process.stdout.write(`${name} is reachable at ${host}:${port}\n`);
        return;
      }
    } else {
      consecutive = 0;
    }
    if (Date.now() >= deadline) {
      fail(`${name} was not reachable at ${host}:${port} within ${timeoutMs}ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
}

const [command, ...args] = process.argv.slice(2);

switch (command) {
  case "go-database-url":
    process.stdout.write(`${goDatabaseURL()}\n`);
    break;
  case "db-host":
    process.stdout.write(`${hostPort(databaseURL(), 5432).host}\n`);
    break;
  case "db-port":
    process.stdout.write(`${hostPort(databaseURL(), 5432).port}\n`);
    break;
  case "nats-port":
    process.stdout.write(`${hostPort(natsURL(), 4222).port}\n`);
    break;
  case "nats-monitor-port":
    process.stdout.write(
      `${(process.env.APERIO_NATS_MONITOR_PORT ?? "8222").trim() || "8222"}\n`
    );
    break;
  case "wait": {
    const [name, target, timeout] = args;
    if (!name || !target) {
      fail("usage: wait <name> <url-or-host:port> [timeoutMs]");
    }
    await waitForTcp(name, target, Number(timeout) > 0 ? Number(timeout) : 30000);
    break;
  }
  default:
    fail(
      `unknown command: ${command ?? "(none)"}\n` +
        "expected one of: go-database-url, db-host, db-port, nats-port, nats-monitor-port, wait"
    );
}

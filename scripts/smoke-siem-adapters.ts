import { spawn } from "node:child_process";
import { createServer, type IncomingMessage } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { prisma } from "../packages/db/src/client";
import { encryptString } from "../packages/security/src/crypto";

type SiemKind =
  | "SPLUNK_HEC"
  | "PANTHER"
  | "PANOPTICON"
  | "ELASTIC"
  | "DATADOG"
  | "GENERIC_WEBHOOK"
  | "CEREBRO_CLAIMS"
  | "JSON_FILE";

type CapturedRequest = {
  method: string;
  url: string;
  headers: Record<string, string[]>;
  bodyBase64: string;
};

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);

const siemKinds: SiemKind[] = [
  "SPLUNK_HEC",
  "PANTHER",
  "PANOPTICON",
  "ELASTIC",
  "DATADOG",
  "GENERIC_WEBHOOK",
  "CEREBRO_CLAIMS",
  "JSON_FILE"
];

function randomID() {
  return Math.random().toString(36).slice(2, 10);
}

function hostFor(kind: SiemKind) {
  return `${kind.toLowerCase().replaceAll("_", "-")}.aperio.test`;
}

function endpointFor(kind: SiemKind) {
  if (kind === "ELASTIC") return `https://${hostFor(kind)}/_bulk`;
  if (kind === "CEREBRO_CLAIMS") return `https://${hostFor(kind)}/cerebro`;
  return `https://${hostFor(kind)}/ingest`;
}

function tokenAAD(organizationId: string, destinationId: string) {
  return `${organizationId}:siem:${destinationId}:token`;
}

function headerValue(request: CapturedRequest, name: string) {
  const needle = name.toLowerCase();
  const entry = Object.entries(request.headers).find(
    ([key]) => key.toLowerCase() === needle
  );
  return entry?.[1]?.[0] ?? "";
}

function bodyText(request: CapturedRequest) {
  return Buffer.from(request.bodyBase64, "base64").toString("utf8");
}

async function readRequestBody(req: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function startCaptureServer() {
  const requests: CapturedRequest[] = [];
  const server = createServer(async (req, res) => {
    try {
      if (req.method !== "POST" || req.url !== "/capture") {
        res.writeHead(404);
        res.end();
        return;
      }
      const raw = await readRequestBody(req);
      requests.push(JSON.parse(raw) as CapturedRequest);
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    } catch (error) {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end(error instanceof Error ? error.message : "capture failed");
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("capture server did not expose a TCP address");
  }
  return {
    requests,
    url: `http://127.0.0.1:${address.port}/capture`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      )
  };
}

async function runWorker(captureURL: string, exportRoot: string, organizationId: string, limit: number) {
  const env = {
    ...process.env,
    APERIO_EVENT_BUS: "noop",
    APERIO_SIEM_EXPORT_DIR: exportRoot,
    APERIO_SIEM_LOCAL_CAPTURE_URL: captureURL
  };
  delete env.DOCKER_HOST;
  const child = spawn(
    "npm",
    [
      "run",
      "worker:siem",
      "--",
      "-once",
      "-limit",
      String(limit),
      "-organization",
      organizationId
    ],
    {
      cwd: repoRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"]
    }
  );
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const exitCode = await new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  });
  if (exitCode !== 0) {
    throw new Error(
      `npm run worker:siem failed with exit ${exitCode}\nstdout:\n${stdout.slice(-4000)}\nstderr:\n${stderr.slice(-4000)}`
    );
  }
  if (!/SIEM drain processed=8 delivered=8 failed=0/.test(stderr)) {
    throw new Error(
      `worker did not report the expected bounded drain result\nstdout:\n${stdout.slice(-2000)}\nstderr:\n${stderr.slice(-2000)}`
    );
  }
  return { stdout, stderr };
}

function assertCapturedRequests(requests: CapturedRequest[], runID: string) {
  const networkKinds = siemKinds.filter((kind) => kind !== "JSON_FILE");
  for (const kind of networkKinds) {
    const matching = requests.filter((request) =>
      request.url.includes(hostFor(kind))
    );
    const expectedCount = kind === "CEREBRO_CLAIMS" ? 2 : 1;
    if (matching.length !== expectedCount) {
      throw new Error(`${kind} captured ${matching.length} requests, want ${expectedCount}`);
    }
    for (const request of matching) {
      const body = bodyText(request);
      if (body.includes(`token-${kind}-${runID}`)) {
        throw new Error(`${kind} leaked plaintext token in request body`);
      }
    }
  }

  const splunk = requests.find((request) => request.url.includes(hostFor("SPLUNK_HEC")));
  if (!splunk || !headerValue(splunk, "authorization").startsWith("Splunk ")) {
    throw new Error("SPLUNK_HEC request missing HEC authorization");
  }
  const panther = requests.find((request) => request.url.includes(hostFor("PANTHER")));
  if (!panther || !headerValue(panther, "x-api-key")) {
    throw new Error("PANTHER request missing x-api-key");
  }
  const panopticon = requests.find((request) => request.url.includes(hostFor("PANOPTICON")));
  if (!panopticon || !headerValue(panopticon, "authorization").startsWith("Bearer ")) {
    throw new Error("PANOPTICON request missing bearer authorization");
  }
  const elastic = requests.find((request) => request.url.includes(hostFor("ELASTIC")));
  if (!elastic || !headerValue(elastic, "authorization").startsWith("ApiKey ")) {
    throw new Error("ELASTIC request missing API key authorization");
  }
  if (!elastic || !bodyText(elastic).endsWith("\n")) {
    throw new Error("ELASTIC request missing NDJSON trailing newline");
  }
  const datadog = requests.find((request) => request.url.includes(hostFor("DATADOG")));
  if (!datadog || !headerValue(datadog, "dd-api-key")) {
    throw new Error("DATADOG request missing DD-API-KEY");
  }
  const webhook = requests.find((request) => request.url.includes(hostFor("GENERIC_WEBHOOK")));
  if (!webhook || !headerValue(webhook, "x-aperio-signature")) {
    throw new Error("GENERIC_WEBHOOK request missing HMAC signature");
  }
  const cerebro = requests.filter((request) => request.url.includes(hostFor("CEREBRO_CLAIMS")));
  if (
    cerebro[0]?.method !== "GET" ||
    cerebro[1]?.method !== "POST" ||
    !cerebro.every((request) =>
      headerValue(request, "authorization").startsWith("Bearer ")
    )
  ) {
    throw new Error("CEREBRO_CLAIMS did not perform runtime check and claim write");
  }
}

async function seedSmokeRows(runID: string) {
  const organizationId = `org_siem_smoke_${runID}`;
  await prisma.organization.create({
    data: {
      id: organizationId,
      name: "SIEM Adapter Smoke",
      slug: `siem-smoke-${runID}`
    }
  });

  const deliveryIds: string[] = [];
  for (const kind of siemKinds) {
    const destinationId = `dst_siem_smoke_${kind.toLowerCase()}_${runID}`;
    const filePath = kind === "JSON_FILE" ? `${kind.toLowerCase()}-${runID}.jsonl` : null;
    const token = `token-${kind}-${runID}`;
    await prisma.siemDestination.create({
      data: {
        id: destinationId,
        organizationId,
        kind,
        name: `${kind} smoke destination`,
        endpointUrl: kind === "JSON_FILE" ? null : endpointFor(kind),
        filePath,
        index:
          kind === "ELASTIC"
            ? `aperio-smoke-${runID}`
            : kind === "CEREBRO_CLAIMS"
              ? `runtime-smoke-${runID}`
              : kind === "SPLUNK_HEC"
                ? `splunk-smoke-${runID}`
                : null,
        encryptedToken:
          kind === "JSON_FILE" ? null : encryptString(token, tokenAAD(organizationId, destinationId)),
        tokenKeyVersion: "v1",
        streams: ["FINDINGS"],
        status: "ACTIVE"
      }
    });
    const payload = {
      kind: "finding",
      organizationId,
      occurredAt: "2026-06-07T00:00:00.000Z",
      record: {
        findingId: `fnd_${kind.toLowerCase()}_${runID}`,
        dedupeKey: `dedupe_${kind.toLowerCase()}_${runID}`,
        sourceEventId: `evt_${kind.toLowerCase()}_${runID}`,
        status: "OPEN",
        title: `${kind} smoke finding`,
        severity: "HIGH",
        provider: "APERIO",
        integrationId: "int_siem_smoke"
      }
    };
    const deliveryId = `sdel_siem_smoke_${kind.toLowerCase()}_${runID}`;
    deliveryIds.push(deliveryId);
    await prisma.siemDelivery.create({
      data: {
        id: deliveryId,
        organizationId,
        destinationId,
        stream: "FINDINGS",
        dedupeKey: `smoke:${kind}:${runID}`,
        payload,
        status: "PENDING",
        attempts: 0,
        maxAttempts: 2
      }
    });
  }
  return { organizationId, deliveryIds };
}

async function assertDelivered(organizationId: string, deliveryIds: string[]) {
  const deliveries = await prisma.siemDelivery.findMany({
    where: { id: { in: deliveryIds } },
    select: {
      id: true,
      status: true,
      attempts: true,
      deliveredAt: true,
      lastError: true,
      destination: { select: { kind: true, deliveriesOk: true, deliveriesFail: true } }
    }
  });
  if (deliveries.length !== deliveryIds.length) {
    throw new Error(`found ${deliveries.length} deliveries, want ${deliveryIds.length}`);
  }
  for (const delivery of deliveries) {
    if (
      delivery.status !== "DELIVERED" ||
      delivery.attempts !== 1 ||
      !delivery.deliveredAt ||
      delivery.lastError ||
      delivery.destination?.deliveriesOk !== 1 ||
      delivery.destination?.deliveriesFail !== 0
    ) {
      throw new Error(`unexpected delivery state for ${delivery.id}: ${JSON.stringify(delivery)}`);
    }
  }
  const lingering = await prisma.siemDelivery.count({
    where: {
      organizationId,
      status: "PROCESSING"
    }
  });
  if (lingering !== 0) {
    throw new Error(`found ${lingering} lingering PROCESSING deliveries`);
  }
}

async function assertJSONFile(exportRoot: string, runID: string, organizationId: string) {
  const relativePath = `json_file-${runID}.jsonl`;
  const raw = await readFile(path.join(exportRoot, relativePath), "utf8");
  const lines = raw.trim().split("\n");
  if (lines.length !== 1) {
    throw new Error(`JSON_FILE wrote ${lines.length} lines, want 1`);
  }
  const envelope = JSON.parse(lines[0]) as Record<string, unknown>;
  if (
    envelope.schema_version !== "aperio.finding.v1" ||
    envelope.organization_id !== organizationId ||
    envelope.destination_id !== `dst_siem_smoke_json_file_${runID}`
  ) {
    throw new Error(`JSON_FILE envelope mismatch: ${JSON.stringify(envelope)}`);
  }
}

async function main() {
  const runID = randomID();
  const capture = await startCaptureServer();
  const exportRoot = await mkdtemp(path.join(tmpdir(), "aperio-siem-smoke-"));
  let organizationId: string | null = null;
  try {
    const seeded = await seedSmokeRows(runID);
    organizationId = seeded.organizationId;
    await runWorker(capture.url, exportRoot, organizationId, siemKinds.length);
    await assertDelivered(organizationId, seeded.deliveryIds);
    assertCapturedRequests(capture.requests, runID);
    await assertJSONFile(exportRoot, runID, organizationId);
    console.log(
      `SIEM adapter smoke delivered ${siemKinds.length} adapters through npm run worker:siem`
    );
  } finally {
    if (organizationId) {
      await prisma.organization.delete({ where: { id: organizationId } }).catch(() => undefined);
    }
    await prisma.$disconnect();
    await capture.close().catch(() => undefined);
    await rm(exportRoot, { recursive: true, force: true }).catch(() => undefined);
  }
}

main().catch(async (error) => {
  await prisma.$disconnect().catch(() => undefined);
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

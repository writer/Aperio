import { createHmac } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";
import type {
  Prisma,
  SiemDelivery,
  SiemDestination,
  SiemStreamType
} from "@prisma/client";
import { prisma } from "@aperio/db";
import { decryptString } from "@aperio/security";
import {
  assertSafeSiemEndpointUrl,
  normalizeSiemFilePath
} from "@aperio/shared/siem-security";

export type SiemEnvelopeKind = "finding" | "event" | "audit_log";
export type SiemEvelopeKind = SiemEnvelopeKind;

export type SiemPayload = {
  kind: SiemEnvelopeKind;
  organizationId: string;
  occurredAt: string;
  record: Record<string, unknown>;
};

type DispatcherResult = {
  destinationId: string;
  ok: boolean;
  message: string;
};

type SiemDispatchEnvelope = {
  schema_version: string;
  source: "aperio";
  producer: "aperio.sspm";
  destination_id: string;
  organization_id: string;
  kind: SiemEnvelopeKind;
  occurred_at: string;
  record: Record<string, unknown>;
};

type CerebroEntityRef = {
  urn: string;
  entity_type: string;
  label: string;
};

export type CerebroClaim = {
  id?: string;
  subject_urn: string;
  subject_ref: CerebroEntityRef;
  predicate: string;
  object_urn?: string;
  object_ref?: CerebroEntityRef;
  object_value?: string;
  claim_type: "existence" | "attribute" | "relation";
  status: "asserted";
  source_event_id?: string;
  observed_at: string;
  attributes?: Record<string, string>;
};

type OutboxDrainResult = {
  processed: number;
  delivered: number;
  failed: number;
};

function streamForKind(kind: SiemEnvelopeKind): SiemStreamType {
  if (kind === "finding") return "FINDINGS";
  if (kind === "event") return "EVENTS";
  return "AUDIT_LOGS";
}

function schemaVersion(kind: SiemEnvelopeKind): string {
  if (kind === "finding") return "aperio.finding.v1";
  if (kind === "event") return "aperio.event.v1";
  return "aperio.audit_log.v1";
}

function buildEnvelope(
  destination: SiemDestination,
  payload: SiemPayload
): SiemDispatchEnvelope {
  return {
    schema_version: schemaVersion(payload.kind),
    source: "aperio",
    producer: "aperio.sspm",
    destination_id: destination.id,
    organization_id: payload.organizationId,
    kind: payload.kind,
    occurred_at: payload.occurredAt,
    record: payload.record
  };
}

function jsonSafe(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function decryptToken(destination: SiemDestination): string | undefined {
  if (!destination.encryptedToken) return undefined;
  const aad = `${destination.organizationId}:siem:${destination.id}:token`;
  return decryptString(destination.encryptedToken, aad);
}

async function sendJsonFile(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.filePath) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "file_path is not configured"
    };
  }
  try {
    const normalizedFilePath = normalizeSiemFilePath(destination.filePath);
    if ("error" in normalizedFilePath) {
      return {
        destinationId: destination.id,
        ok: false,
        message: normalizedFilePath.error ?? "Invalid SIEM export path"
      };
    }

    await mkdir(dirname(normalizedFilePath.absolutePath), { recursive: true });
    await appendFile(
      normalizedFilePath.absolutePath,
      `${JSON.stringify(buildEnvelope(destination, payload))}\n`,
      {
        encoding: "utf8"
      }
    );
    return {
      destinationId: destination.id,
      ok: true,
      message: `appended to ${normalizedFilePath.absolutePath}`
    };
  } catch (error) {
    return {
      destinationId: destination.id,
      ok: false,
      message: error instanceof Error ? error.message : "file write failed"
    };
  }
}

async function postJson(
  url: string,
  headers: Record<string, string>,
  body: string,
  timeoutMs = 4000
): Promise<{ ok: boolean; status: number; message: string }> {
  const endpointError = await assertSafeSiemEndpointUrl(url);
  if (endpointError) {
    return {
      ok: false,
      status: 0,
      message: endpointError
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body,
      signal: controller.signal
    });
    return {
      ok: response.ok,
      status: response.status,
      message: response.ok
        ? `delivered (${response.status})`
        : `${response.status} ${response.statusText}`
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      message: error instanceof Error ? error.message : "network error"
    };
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(
  url: string,
  headers: Record<string, string>,
  timeoutMs = 4000
): Promise<{ ok: boolean; status: number; message: string }> {
  const endpointError = await assertSafeSiemEndpointUrl(url);
  if (endpointError) {
    return {
      ok: false,
      status: 0,
      message: endpointError
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json", ...headers },
      signal: controller.signal
    });
    return {
      ok: response.ok,
      status: response.status,
      message: response.ok
        ? `loaded (${response.status})`
        : `${response.status} ${response.statusText}`
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      message: error instanceof Error ? error.message : "network error"
    };
  } finally {
    clearTimeout(timer);
  }
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
}

function stringValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

function entityRef(
  organizationId: string,
  runtimeId: string,
  entityType: string,
  externalId: string,
  label: string
): CerebroEntityRef {
  const encodedExternalId = encodeURIComponent(externalId).replace(/%20/g, "-");
  return {
    urn: [
      "urn",
      "cerebro",
      organizationId,
      "runtime",
      runtimeId,
      entityType,
      encodedExternalId
    ].join(":"),
    entity_type: entityType,
    label
  };
}

function claimBase(
  payload: SiemPayload,
  attributes?: Record<string, string>
) {
  return {
    status: "asserted" as const,
    source_event_id: stringValue(payload.record.sourceEventId),
    observed_at: payload.occurredAt,
    attributes
  };
}

function existsClaim(
  subject: CerebroEntityRef,
  payload: SiemPayload,
  attributes?: Record<string, string>
): CerebroClaim {
  return {
    subject_urn: subject.urn,
    subject_ref: subject,
    predicate: "exists",
    claim_type: "existence",
    ...claimBase(payload, attributes)
  };
}

function attrClaim(
  subject: CerebroEntityRef,
  predicate: string,
  value: string,
  payload: SiemPayload
): CerebroClaim {
  return {
    subject_urn: subject.urn,
    subject_ref: subject,
    predicate,
    object_value: value,
    claim_type: "attribute",
    ...claimBase(payload)
  };
}

function relClaim(
  subject: CerebroEntityRef,
  predicate: string,
  object: CerebroEntityRef,
  payload: SiemPayload
): CerebroClaim {
  return {
    subject_urn: subject.urn,
    subject_ref: subject,
    predicate,
    object_urn: object.urn,
    object_ref: object,
    claim_type: "relation",
    ...claimBase(payload)
  };
}

export function buildCerebroClaims(
  destination: Pick<SiemDestination, "organizationId" | "index">,
  payload: SiemPayload
): CerebroClaim[] {
  const runtimeId = destination.index?.trim();
  if (!runtimeId) {
    throw new Error("Cerebro source runtime ID is not configured");
  }

  const record = payload.record;
  const provider = stringValue(record.provider) ?? "APERIO";
  const title = stringValue(record.title) ?? `${payload.kind} from Aperio`;
  const findingId =
    stringValue(record.dedupeKey) ??
    stringValue(record.sourceEventId) ??
    createHmac("sha256", destination.organizationId)
      .update(JSON.stringify(record))
      .digest("hex");
  const targetLabel = stringValue(record.target) ?? title;
  const integrationId = stringValue(record.integrationId) ?? "aperio";
  const finding = entityRef(
    destination.organizationId,
    runtimeId,
    "finding",
    findingId,
    title
  );
  const target = entityRef(
    destination.organizationId,
    runtimeId,
    "asset",
    `${provider}:${targetLabel}`,
    targetLabel
  );
  const integration = entityRef(
    destination.organizationId,
    runtimeId,
    "integration",
    integrationId,
    provider
  );
  const attributes: Record<string, string> = {
    aperio_schema: schemaVersion(payload.kind),
    aperio_kind: payload.kind
  };
  for (const key of ["ruleId", "dedupeKey", "sourceEventId", "source", "eventType"]) {
    const value = stringValue(record[key]);
    if (value) attributes[key] = value;
  }

  const claims: CerebroClaim[] = [
    existsClaim(finding, payload, attributes),
    existsClaim(target, payload, { provider }),
    existsClaim(integration, payload, { provider }),
    relClaim(finding, "affects", target, payload),
    relClaim(finding, "observed_by", integration, payload),
    attrClaim(finding, "title", title, payload),
    attrClaim(finding, "provider", provider, payload)
  ];

  for (const key of ["severity", "riskScore", "status", "ruleId"]) {
    const value = stringValue(record[key]);
    if (value) claims.push(attrClaim(finding, key, value, payload));
  }

  const description = stringValue(record.description);
  if (description) claims.push(attrClaim(finding, "description", description, payload));

  return claims;
}

async function sendCerebroClaims(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl || !destination.index) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "Cerebro API URL or source runtime ID missing"
    };
  }
  const token = decryptToken(destination);
  if (!token) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "missing Cerebro API token"
    };
  }

  const runtimePath = `/source-runtimes/${encodeURIComponent(destination.index)}`;
  const headers = { authorization: `Bearer ${token}` };
  const runtime = await getJson(joinUrl(destination.endpointUrl, runtimePath), headers);
  if (!runtime.ok) {
    return {
      destinationId: destination.id,
      ok: false,
      message: `Cerebro runtime check failed: ${runtime.message}`
    };
  }

  const claims = buildCerebroClaims(destination, payload);
  const res = await postJson(
    joinUrl(destination.endpointUrl, `${runtimePath}/claims`),
    headers,
    JSON.stringify({
      runtime_id: destination.index,
      claims
    })
  );
  return {
    destinationId: destination.id,
    ok: res.ok,
    message: res.ok ? `wrote ${claims.length} Cerebro claims` : res.message
  };
}

async function sendSplunk(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "endpoint not configured"
    };
  }
  const token = decryptToken(destination);
  if (!token) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "missing HEC token"
    };
  }
  const body = JSON.stringify({
    event: buildEnvelope(destination, payload),
    sourcetype: `aperio:${payload.kind}`,
    source: "aperio",
    index: destination.index ?? undefined,
    time: Math.floor(Date.parse(payload.occurredAt) / 1000) || undefined
  });
  const res = await postJson(
    destination.endpointUrl,
    { authorization: `Splunk ${token}` },
    body
  );
  return { destinationId: destination.id, ok: res.ok, message: res.message };
}

async function sendPanther(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "endpoint not configured"
    };
  }
  const token = decryptToken(destination);
  const headers: Record<string, string> = {};
  if (token) {
    headers["x-api-key"] = token;
  }
  const res = await postJson(
    destination.endpointUrl,
    headers,
    JSON.stringify(buildEnvelope(destination, payload))
  );
  return { destinationId: destination.id, ok: res.ok, message: res.message };
}

async function sendPanopticon(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "endpoint not configured"
    };
  }
  const token = decryptToken(destination);
  const headers: Record<string, string> = {};
  if (token) {
    headers.authorization = `Bearer ${token}`;
  }
  const res = await postJson(
    destination.endpointUrl,
    headers,
    JSON.stringify(buildEnvelope(destination, payload))
  );
  return { destinationId: destination.id, ok: res.ok, message: res.message };
}

async function sendElastic(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl || !destination.index) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "endpoint or index missing"
    };
  }
  const token = decryptToken(destination);
  const headers: Record<string, string> = {
    "content-type": "application/x-ndjson"
  };
  if (token) {
    headers.authorization = `ApiKey ${token}`;
  }
  const body =
    JSON.stringify({ index: { _index: destination.index } }) +
    "\n" +
    JSON.stringify(buildEnvelope(destination, payload)) +
    "\n";
  const res = await postJson(destination.endpointUrl, headers, body);
  return { destinationId: destination.id, ok: res.ok, message: res.message };
}

async function sendDatadog(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "endpoint not configured"
    };
  }
  const token = decryptToken(destination);
  if (!token) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "missing DD-API-KEY"
    };
  }
  const body = JSON.stringify([
    {
      ddsource: "aperio",
      service: `aperio-${payload.kind}`,
      ddtags: `org:${destination.organizationId}`,
      message: buildEnvelope(destination, payload)
    }
  ]);
  const res = await postJson(
    destination.endpointUrl,
    { "DD-API-KEY": token },
    body
  );
  return { destinationId: destination.id, ok: res.ok, message: res.message };
}

async function sendWebhook(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  if (!destination.endpointUrl) {
    return {
      destinationId: destination.id,
      ok: false,
      message: "endpoint not configured"
    };
  }
  const body = JSON.stringify(buildEnvelope(destination, payload));
  const headers: Record<string, string> = {};
  const token = decryptToken(destination);
  if (token) {
    headers["x-aperio-signature"] = createHmac("sha256", token)
      .update(body)
      .digest("hex");
  }
  const res = await postJson(destination.endpointUrl, headers, body);
  return { destinationId: destination.id, ok: res.ok, message: res.message };
}

async function sendOne(
  destination: SiemDestination,
  payload: SiemPayload
): Promise<DispatcherResult> {
  switch (destination.kind) {
    case "JSON_FILE":
      return sendJsonFile(destination, payload);
    case "SPLUNK_HEC":
      return sendSplunk(destination, payload);
    case "PANTHER":
      return sendPanther(destination, payload);
    case "PANOPTICON":
      return sendPanopticon(destination, payload);
    case "ELASTIC":
      return sendElastic(destination, payload);
    case "DATADOG":
      return sendDatadog(destination, payload);
    case "GENERIC_WEBHOOK":
      return sendWebhook(destination, payload);
    case "CEREBRO_CLAIMS":
      return sendCerebroClaims(destination, payload);
    default:
      return {
        destinationId: destination.id,
        ok: false,
        message: `unsupported kind ${destination.kind}`
      };
  }
}

async function recordResult(result: DispatcherResult): Promise<void> {
  try {
    await prisma.siemDestination.update({
      where: { id: result.destinationId },
      data: result.ok
        ? {
            lastDeliveryAt: new Date(),
            deliveriesOk: { increment: 1 },
            lastError: null,
            status: "ACTIVE"
          }
        : {
            deliveriesFail: { increment: 1 },
            lastError: result.message.slice(0, 500),
            status: "ERROR"
          }
    });
  } catch {
    // best-effort bookkeeping
  }
}

function parseDeliveryPayload(value: unknown): SiemPayload | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as SiemPayload;
  if (
    (candidate.kind === "finding" ||
      candidate.kind === "event" ||
      candidate.kind === "audit_log") &&
    typeof candidate.organizationId === "string" &&
    typeof candidate.occurredAt === "string" &&
    candidate.record &&
    typeof candidate.record === "object"
  ) {
    return candidate;
  }
  return null;
}

function nextRetryAt(attempt: number): Date {
  const delaySeconds = Math.min(60 * 30, 2 ** Math.max(0, attempt - 1) * 30);
  return new Date(Date.now() + delaySeconds * 1000);
}

async function finishDelivery(
  delivery: SiemDelivery,
  result: DispatcherResult
): Promise<void> {
  const attempts = delivery.attempts + 1;
  if (result.ok) {
    await prisma.siemDelivery.update({
      where: { id: delivery.id },
      data: {
        status: "DELIVERED",
        attempts,
        deliveredAt: new Date(),
        lastError: null
      }
    });
    return;
  }
  await prisma.siemDelivery.update({
    where: { id: delivery.id },
    data: {
      status: attempts >= delivery.maxAttempts ? "DEAD_LETTER" : "FAILED",
      attempts,
      nextAttemptAt: nextRetryAt(attempts),
      lastError: result.message.slice(0, 500)
    }
  });
}

async function processDelivery(delivery: SiemDelivery): Promise<DispatcherResult> {
  const claimed = await prisma.siemDelivery.updateMany({
    where: {
      id: delivery.id,
      status: { in: ["PENDING", "FAILED"] }
    },
    data: { status: "PROCESSING" }
  });
  if (claimed.count === 0) {
    return {
      destinationId: delivery.destinationId ?? "unknown",
      ok: false,
      message: "delivery already claimed"
    };
  }

  const payload = parseDeliveryPayload(delivery.payload);
  if (!payload || !delivery.destinationId) {
    const result = {
      destinationId: delivery.destinationId ?? "unknown",
      ok: false,
      message: "invalid delivery payload"
    };
    await finishDelivery(delivery, result);
    return result;
  }

  const destination = await prisma.siemDestination.findFirst({
    where: {
      id: delivery.destinationId,
      organizationId: delivery.organizationId,
      status: { in: ["ACTIVE", "ERROR"] }
    }
  });
  if (!destination) {
    const result = {
      destinationId: delivery.destinationId,
      ok: false,
      message: "destination not active"
    };
    await finishDelivery(delivery, result);
    return result;
  }

  const result = await sendOne(destination, payload);
  await Promise.all([recordResult(result), finishDelivery(delivery, result)]);
  return result;
}

export async function enqueueSiemDeliveries(
  payload: SiemPayload
): Promise<number> {
  const targetStream = streamForKind(payload.kind);
  const destinations = await prisma.siemDestination.findMany({
    where: {
      organizationId: payload.organizationId,
      status: { in: ["ACTIVE", "ERROR"] },
      streams: { has: targetStream }
    },
    select: { id: true }
  });
  if (destinations.length === 0) {
    return 0;
  }
  await prisma.siemDelivery.createMany({
    data: destinations.map((destination) => ({
      organizationId: payload.organizationId,
      destinationId: destination.id,
      stream: targetStream,
      payload: jsonSafe(payload)
    }))
  });
  return destinations.length;
}

export async function drainSiemDeliveries(
  limit = 25
): Promise<OutboxDrainResult> {
  const deliveries = await prisma.siemDelivery.findMany({
    where: {
      status: { in: ["PENDING", "FAILED"] },
      nextAttemptAt: { lte: new Date() }
    },
    orderBy: { createdAt: "asc" },
    take: limit
  });
  let delivered = 0;
  let failed = 0;
  for (const delivery of deliveries) {
    if (delivery.attempts >= delivery.maxAttempts) {
      await prisma.siemDelivery.update({
        where: { id: delivery.id },
        data: { status: "DEAD_LETTER" }
      });
      failed += 1;
      continue;
    }
    const result = await processDelivery(delivery);
    if (result.ok) delivered += 1;
    else failed += 1;
  }
  return { processed: deliveries.length, delivered, failed };
}

export async function dispatchToSiemDestinations(
  payload: SiemPayload
): Promise<DispatcherResult[]> {
  const targetStream = streamForKind(payload.kind);
  const destinations = await prisma.siemDestination.findMany({
    where: {
      organizationId: payload.organizationId,
      status: { in: ["ACTIVE", "ERROR"] },
      streams: { has: targetStream }
    }
  });
  if (destinations.length === 0) {
    return [];
  }
  const results = await Promise.all(
    destinations.map((destination) => sendOne(destination, payload))
  );
  await Promise.all(results.map((result) => recordResult(result)));
  return results;
}

export function startSiemDispatcher(intervalMs = 15_000): NodeJS.Timeout {
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void drainSiemDeliveries().finally(() => {
      running = false;
    });
  };
  void tick();
  return setInterval(tick, intervalMs);
}

export async function dispatchTestPing(
  destinationId: string,
  organizationId: string
): Promise<DispatcherResult> {
  const destination = await prisma.siemDestination.findFirst({
    where: { id: destinationId, organizationId }
  });
  if (!destination) {
    return {
      destinationId,
      ok: false,
      message: "destination not found"
    };
  }
  const payload: SiemPayload = {
    kind: "finding",
    organizationId,
    occurredAt: new Date().toISOString(),
    record: {
      test: true,
      id: `test-${Date.now()}`,
      title: "Aperio SIEM connectivity test",
      severity: "INFO",
      provider: "APERIO"
    }
  };
  const result = await sendOne(destination, payload);
  await recordResult(result);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startSiemDispatcher();
  console.log("Aperio SIEM dispatcher is draining the durable outbox.");
}

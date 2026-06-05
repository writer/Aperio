import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";

export const APERIO_EVENT_SOURCE_ID = "aperio";
export const APERIO_NATS_SUBJECT_PREFIX = "events";

export const APERIO_EVENT_KINDS = {
  ingestionQueued: "aperio.ingestion_job.queued",
  ingestionRunning: "aperio.ingestion_job.running",
  ingestionSucceeded: "aperio.ingestion_job.succeeded",
  ingestionFailed: "aperio.ingestion_job.failed",
  claimFanoutDelivered: "aperio.claim_fanout.delivered",
  claimFanoutFailed: "aperio.claim_fanout.failed",
  findingOpened: "aperio.finding.opened",
  findingReopened: "aperio.finding.reopened",
  findingResolved: "aperio.finding.resolved",
  findingMuted: "aperio.finding.muted"
} as const;

export const APERIO_SCHEMA_REFS = {
  ingestionJob: "aperio/ingestion_job/v1",
  claimFanout: "aperio/claim_fanout/v1",
  findingLifecycle: "aperio/finding_lifecycle/v1"
} as const;

const EVENT_KIND_PATTERN = /^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$/;
const SCHEMA_REF_PATTERN = /^[a-z][a-z0-9_-]*\/[a-z][a-z0-9_-]*\/v[0-9]+$/;

const REQUIRED_ATTRIBUTES_BY_SCHEMA_REF: Record<string, string[]> = {
  [APERIO_SCHEMA_REFS.ingestionJob]: ["job_id", "integration_id", "provider"],
  [APERIO_SCHEMA_REFS.claimFanout]: [
    "delivery_id",
    "destination_id",
    "source_runtime_id"
  ],
  [APERIO_SCHEMA_REFS.findingLifecycle]: [
    "finding_id",
    "previous_status",
    "next_status",
    "status_source"
  ]
};

type TimestampLike = Date | string | number;

export type CerebroEntityRefContract = {
  urn: string;
  entity_type: string;
  label: string;
};

export type CerebroClaimContract = {
  id?: string;
  subject_urn: string;
  subject_ref: CerebroEntityRefContract;
  predicate: string;
  object_urn?: string;
  object_ref?: CerebroEntityRefContract;
  object_value?: string;
  claim_type: "existence" | "attribute" | "relation" | string;
  status?: string;
  source_event_id?: string;
  observed_at?: string;
  valid_from?: string;
  valid_to?: string;
  attributes?: Record<string, string>;
};

export type IngestionJobEventInput = {
  jobId: string;
  organizationId: string;
  integrationId: string;
  provider: string;
  eventType: string;
  source: string;
  actor?: string | null;
  occurredAt: TimestampLike;
  status: "queued" | "running" | "succeeded" | "failed";
  attempts: number;
  sourceEventId?: string;
  payload: Record<string, unknown>;
};

export type CerebroClaimsFanoutEventInput = {
  deliveryId: string;
  organizationId: string;
  destinationId: string;
  runtimeId: string;
  findingId?: string;
  dedupeKey?: string;
  occurredAt: TimestampLike;
  claims: CerebroClaimContract[];
  status: "delivered" | "failed";
  error?: string;
};

export type FindingLifecycleEventInput = {
  findingId: string;
  organizationId: string;
  integrationId: string;
  previousStatus: "OPEN" | "RESOLVED" | "MUTED" | string;
  nextStatus: "OPEN" | "RESOLVED" | "MUTED" | string;
  actorUserId?: string | null;
  statusSource: "user" | "system" | "agent" | string;
  occurredAt: TimestampLike;
  resolutionNote?: string | null;
};

export type EncodedAperioEvent = {
  id: string;
  kind: string;
  schemaRef: string;
  sourceId: string;
  subject: string;
  tenantId: string;
  occurredAt: string;
  payload: Uint8Array;
  attributes: Record<string, string>;
};

const encoder = new TextEncoder();
let rootPromise: Promise<protobuf.Root> | null = null;

function protoPath(relativePath: string) {
  return fileURLToPath(new URL(`../../../${relativePath}`, import.meta.url));
}

function protobufRoot() {
  if (!rootPromise) {
    const root = new protobuf.Root();
    root.resolvePath = (_origin, target) =>
      target.startsWith("/")
        ? target
        : target.startsWith("google/")
        ? target
        : protoPath(`proto/${target.replace(/^proto\//, "")}`);
    rootPromise = root
      .load([
        protoPath("proto/cerebro/v1/primitives.proto"),
        protoPath("proto/aperio/contracts/v1/events.proto")
      ])
      .then(() => root.resolveAll() as protobuf.Root);
  }
  return rootPromise;
}

function timestamp(value: TimestampLike) {
  const date = value instanceof Date ? value : new Date(value);
  const millis = date.getTime();
  if (Number.isNaN(millis)) {
    throw new Error("Invalid protobuf timestamp");
  }
  return {
    seconds: Math.floor(millis / 1000),
    nanos: (millis % 1000) * 1_000_000
  };
}

function jsonBytes(value: unknown) {
  return encoder.encode(JSON.stringify(value));
}

function natsSubject(kind: string) {
  return `${APERIO_NATS_SUBJECT_PREFIX}.${kind}`;
}

function compactAttributes(attributes: Record<string, string | undefined>) {
  return Object.fromEntries(
    Object.entries(attributes).filter(
      (entry): entry is [string, string] => Boolean(entry[1])
    )
  );
}

async function encodeEnvelope(input: {
  tenantId: string;
  kind: string;
  schemaRef: string;
  occurredAt: TimestampLike;
  payload: Uint8Array;
  attributes: Record<string, string>;
}) {
  const root = await protobufRoot();
  const EventEnvelope = root.lookupType("cerebro.v1.EventEnvelope");
  const id = randomUUID();
  const occurredAt = timestamp(input.occurredAt);
  const message = EventEnvelope.create({
    id,
    tenantId: input.tenantId,
    sourceId: APERIO_EVENT_SOURCE_ID,
    kind: input.kind,
    occurredAt,
    schemaRef: input.schemaRef,
    payload: input.payload,
    attributes: input.attributes
  });

  return validateEncodedAperioEvent({
    id,
    kind: input.kind,
    schemaRef: input.schemaRef,
    sourceId: APERIO_EVENT_SOURCE_ID,
    subject: natsSubject(input.kind),
    tenantId: input.tenantId,
    occurredAt: new Date(
      Number(occurredAt.seconds) * 1000 + Math.floor(occurredAt.nanos / 1_000_000)
    ).toISOString(),
    payload: EventEnvelope.encode(message).finish(),
    attributes: input.attributes
  });
}

export function validateEncodedAperioEvent(
  event: EncodedAperioEvent
): EncodedAperioEvent {
  const requiredStringFields = {
    id: event.id,
    kind: event.kind,
    schemaRef: event.schemaRef,
    sourceId: event.sourceId,
    subject: event.subject,
    tenantId: event.tenantId,
    occurredAt: event.occurredAt
  };
  for (const [field, value] of Object.entries(requiredStringFields)) {
    if (!value || value.trim() !== value) {
      throw new Error(`Invalid event envelope ${field}`);
    }
  }
  if (event.sourceId !== APERIO_EVENT_SOURCE_ID) {
    throw new Error("Invalid event envelope sourceId");
  }
  if (!EVENT_KIND_PATTERN.test(event.kind)) {
    throw new Error("Invalid event envelope kind");
  }
  if (!SCHEMA_REF_PATTERN.test(event.schemaRef)) {
    throw new Error("Invalid event envelope schemaRef");
  }
  if (event.subject !== natsSubject(event.kind)) {
    throw new Error("Invalid event envelope subject");
  }
  if (Number.isNaN(new Date(event.occurredAt).getTime())) {
    throw new Error("Invalid event envelope occurredAt");
  }
  if (event.payload.byteLength === 0) {
    throw new Error("Invalid event envelope payload");
  }
  for (const [key, value] of Object.entries(event.attributes)) {
    if (!key || key.trim() !== key || value.trim() !== value) {
      throw new Error("Invalid event envelope attribute");
    }
  }
  for (const required of REQUIRED_ATTRIBUTES_BY_SCHEMA_REF[event.schemaRef] ?? []) {
    if (!event.attributes[required]) {
      throw new Error(`Missing event envelope attribute ${required}`);
    }
  }
  return event;
}

export async function encodeIngestionJobEvent(
  input: IngestionJobEventInput
): Promise<EncodedAperioEvent> {
  const root = await protobufRoot();
  const IngestionJobEvent = root.lookupType("aperio.contracts.v1.IngestionJobEvent");
  const payload = IngestionJobEvent.encode(
    IngestionJobEvent.create({
      jobId: input.jobId,
      organizationId: input.organizationId,
      integrationId: input.integrationId,
      provider: input.provider,
      eventType: input.eventType,
      source: input.source,
      actor: input.actor ?? "",
      occurredAt: timestamp(input.occurredAt),
      status: input.status,
      attempts: input.attempts,
      sourceEventId: input.sourceEventId ?? "",
      payloadJson: jsonBytes(input.payload)
    })
  ).finish();
  const kind =
    input.status === "queued"
      ? APERIO_EVENT_KINDS.ingestionQueued
      : input.status === "running"
        ? APERIO_EVENT_KINDS.ingestionRunning
        : input.status === "succeeded"
          ? APERIO_EVENT_KINDS.ingestionSucceeded
          : APERIO_EVENT_KINDS.ingestionFailed;

  return encodeEnvelope({
    tenantId: input.organizationId,
    kind,
    schemaRef: APERIO_SCHEMA_REFS.ingestionJob,
    occurredAt: input.occurredAt,
    payload,
    attributes: compactAttributes({
      job_id: input.jobId,
      integration_id: input.integrationId,
      provider: input.provider,
      event_type: input.eventType,
      source_event_id: input.sourceEventId
    })
  });
}

function claimToProto(claim: CerebroClaimContract) {
  return {
    id: claim.id ?? "",
    subjectUrn: claim.subject_urn,
    subjectRef: {
      urn: claim.subject_ref.urn,
      entityType: claim.subject_ref.entity_type,
      label: claim.subject_ref.label
    },
    predicate: claim.predicate,
    objectUrn: claim.object_urn ?? "",
    objectRef: claim.object_ref
      ? {
          urn: claim.object_ref.urn,
          entityType: claim.object_ref.entity_type,
          label: claim.object_ref.label
        }
      : undefined,
    objectValue: claim.object_value ?? "",
    claimType: claim.claim_type,
    status: claim.status ?? "asserted",
    sourceEventId: claim.source_event_id ?? "",
    observedAt: claim.observed_at ? timestamp(claim.observed_at) : undefined,
    validFrom: claim.valid_from ? timestamp(claim.valid_from) : undefined,
    validTo: claim.valid_to ? timestamp(claim.valid_to) : undefined,
    attributes: claim.attributes ?? {}
  };
}

export async function encodeCerebroClaimsFanoutEvent(
  input: CerebroClaimsFanoutEventInput
): Promise<EncodedAperioEvent> {
  const root = await protobufRoot();
  const FanoutEvent = root.lookupType("aperio.contracts.v1.CerebroClaimsFanoutEvent");
  const payload = FanoutEvent.encode(
    FanoutEvent.create({
      deliveryId: input.deliveryId,
      organizationId: input.organizationId,
      destinationId: input.destinationId,
      runtimeId: input.runtimeId,
      findingId: input.findingId ?? "",
      dedupeKey: input.dedupeKey ?? "",
      occurredAt: timestamp(input.occurredAt),
      claims: input.claims.map(claimToProto),
      status: input.status,
      error: input.error ?? ""
    })
  ).finish();
  const kind =
    input.status === "delivered"
      ? APERIO_EVENT_KINDS.claimFanoutDelivered
      : APERIO_EVENT_KINDS.claimFanoutFailed;

  return encodeEnvelope({
    tenantId: input.organizationId,
    kind,
    schemaRef: APERIO_SCHEMA_REFS.claimFanout,
    occurredAt: input.occurredAt,
    payload,
    attributes: compactAttributes({
      delivery_id: input.deliveryId,
      destination_id: input.destinationId,
      source_runtime_id: input.runtimeId,
      finding_id: input.findingId,
      dedupe_key: input.dedupeKey
    })
  });
}

export async function encodeFindingLifecycleEvent(
  input: FindingLifecycleEventInput
): Promise<EncodedAperioEvent> {
  const root = await protobufRoot();
  const FindingLifecycleEvent = root.lookupType(
    "aperio.contracts.v1.FindingLifecycleEvent"
  );
  const payload = FindingLifecycleEvent.encode(
    FindingLifecycleEvent.create({
      findingId: input.findingId,
      organizationId: input.organizationId,
      integrationId: input.integrationId,
      previousStatus: input.previousStatus,
      nextStatus: input.nextStatus,
      actorUserId: input.actorUserId ?? "",
      statusSource: input.statusSource,
      occurredAt: timestamp(input.occurredAt),
      resolutionNote: input.resolutionNote ?? ""
    })
  ).finish();
  const kind =
    input.previousStatus === "RESOLVED" && input.nextStatus === "OPEN"
      ? APERIO_EVENT_KINDS.findingReopened
      : input.nextStatus === "OPEN"
        ? APERIO_EVENT_KINDS.findingOpened
        : input.nextStatus === "MUTED"
          ? APERIO_EVENT_KINDS.findingMuted
          : APERIO_EVENT_KINDS.findingResolved;

  return encodeEnvelope({
    tenantId: input.organizationId,
    kind,
    schemaRef: APERIO_SCHEMA_REFS.findingLifecycle,
    occurredAt: input.occurredAt,
    payload,
    attributes: compactAttributes({
      finding_id: input.findingId,
      integration_id: input.integrationId,
      previous_status: input.previousStatus,
      next_status: input.nextStatus,
      actor_user_id: input.actorUserId ?? undefined,
      status_source: input.statusSource
    })
  });
}

export async function decodeCerebroEventEnvelope(payload: Uint8Array) {
  const root = await protobufRoot();
  const EventEnvelope = root.lookupType("cerebro.v1.EventEnvelope");
  return EventEnvelope.toObject(EventEnvelope.decode(payload), {
    bytes: Uint8Array,
    longs: String
  }) as Record<string, unknown>;
}

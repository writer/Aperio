import assert from "node:assert/strict";
import test from "node:test";
import {
  APERIO_EVENT_KINDS,
  APERIO_SCHEMA_REFS,
  decodeCerebroEventEnvelope,
  encodeCerebroClaimsFanoutEvent,
  encodeFindingLifecycleEvent,
  encodeIngestionJobEvent,
  validateEncodedAperioEvent
} from "@aperio/shared/protobuf-contracts";

test("encodes ingestion events in the Cerebro envelope contract", async () => {
  const encoded = await encodeIngestionJobEvent({
    jobId: "job_123",
    organizationId: "org_123",
    integrationId: "int_123",
    provider: "GITHUB",
    eventType: "repository.publicized",
    source: "github.audit",
    actor: "owner@example.test",
    occurredAt: "2026-06-05T21:00:00.000Z",
    status: "queued",
    attempts: 0,
    sourceEventId: "evt_123",
    payload: {
      repository: {
        full_name: "writer/public-demo"
      }
    }
  });

  assert.equal(encoded.kind, APERIO_EVENT_KINDS.ingestionQueued);
  assert.equal(encoded.schemaRef, APERIO_SCHEMA_REFS.ingestionJob);
  assert.equal(encoded.sourceId, "aperio");
  assert.equal(encoded.tenantId, "org_123");
  assert.equal(encoded.subject, "events.aperio.ingestion_job.queued");

  const envelope = await decodeCerebroEventEnvelope(encoded.payload);
  assert.equal(envelope.tenantId, "org_123");
  assert.equal(envelope.sourceId, "aperio");
  assert.equal(envelope.kind, APERIO_EVENT_KINDS.ingestionQueued);
  assert.equal(envelope.schemaRef, APERIO_SCHEMA_REFS.ingestionJob);
  assert.ok(envelope.payload instanceof Uint8Array);
});

test("rejects malformed event envelope metadata before publish", async () => {
  const encoded = await encodeIngestionJobEvent({
    jobId: "job_123",
    organizationId: "org_123",
    integrationId: "int_123",
    provider: "GITHUB",
    eventType: "repository.publicized",
    source: "github.audit",
    occurredAt: "2026-06-05T21:00:00.000Z",
    status: "queued",
    attempts: 0,
    payload: {}
  });

  assert.throws(
    () =>
      validateEncodedAperioEvent({
        ...encoded,
        kind: "Aperio.Bad Kind",
        subject: "events.Aperio.Bad Kind"
      }),
    /kind/
  );
  assert.throws(
    () =>
      validateEncodedAperioEvent({
        ...encoded,
        attributes: { ...encoded.attributes, job_id: "" }
      }),
    /job_id/
  );
});

test("encodes Cerebro claim fanout events with stable claim fields", async () => {
  const encoded = await encodeCerebroClaimsFanoutEvent({
    deliveryId: "del_123",
    organizationId: "org_123",
    destinationId: "dst_123",
    runtimeId: "writer-aperio-sspm",
    findingId: "finding_123",
    dedupeKey: "dedupe_123",
    occurredAt: "2026-06-05T21:00:00.000Z",
    status: "delivered",
    claims: [
      {
        subject_urn:
          "urn:cerebro:org_123:runtime:writer-aperio-sspm:finding:dedupe_123",
        subject_ref: {
          urn: "urn:cerebro:org_123:runtime:writer-aperio-sspm:finding:dedupe_123",
          entity_type: "finding",
          label: "Public repository"
        },
        predicate: "exists",
        claim_type: "existence",
        status: "asserted",
        observed_at: "2026-06-05T21:00:00.000Z"
      }
    ]
  });

  assert.equal(encoded.kind, APERIO_EVENT_KINDS.claimFanoutDelivered);
  assert.equal(encoded.schemaRef, APERIO_SCHEMA_REFS.claimFanout);
  assert.equal(encoded.subject, "events.aperio.claim_fanout.delivered");

  const envelope = await decodeCerebroEventEnvelope(encoded.payload);
  assert.equal(envelope.tenantId, "org_123");
  assert.equal(envelope.attributes?.["source_runtime_id"], "writer-aperio-sspm");
  assert.ok(envelope.payload instanceof Uint8Array);
});

test("encodes finding lifecycle events for durable status changes", async () => {
  const encoded = await encodeFindingLifecycleEvent({
    findingId: "finding_123",
    organizationId: "org_123",
    integrationId: "int_123",
    previousStatus: "OPEN",
    nextStatus: "RESOLVED",
    actorUserId: "user_123",
    statusSource: "user",
    occurredAt: "2026-06-05T21:00:00.000Z",
    resolutionNote: "Reviewed"
  });

  assert.equal(encoded.kind, APERIO_EVENT_KINDS.findingResolved);
  assert.equal(encoded.schemaRef, APERIO_SCHEMA_REFS.findingLifecycle);
  assert.equal(encoded.attributes.finding_id, "finding_123");
  assert.equal(encoded.attributes.status_source, "user");

  const envelope = await decodeCerebroEventEnvelope(encoded.payload);
  assert.equal(envelope.tenantId, "org_123");
  assert.equal(envelope.schemaRef, APERIO_SCHEMA_REFS.findingLifecycle);
  assert.ok(envelope.payload instanceof Uint8Array);
});

// Structured "wide event" emission for the background workers. The shape
// mirrors internal/telemetry.EmitWide on the Go side (kind, event_name,
// service, occurred_at, organization_id, plus low-cardinality dimensions and
// numeric measurements) so the ingestion and SIEM pipelines emit telemetry that
// downstream tooling can treat uniformly with the API's per-RPC events.

export type WideEvent = {
  name: string;
  service: string;
  organizationId?: string;
  dimensions?: Record<string, string | undefined>;
  measurements?: Record<string, number | undefined>;
};

type Sink = (line: string) => void;

const defaultSink: Sink = (line) => {
  process.stderr.write(line + "\n");
};

let sink: Sink = defaultSink;

// setTelemetrySink redirects emitted events and returns a restore function. It
// exists so tests can capture and assert on the JSON; production writes to
// stderr. Passing null restores the default sink.
export function setTelemetrySink(next: Sink | null): () => void {
  const previous = sink;
  sink = next ?? defaultSink;
  return () => {
    sink = previous;
  };
}

export function emitWideEvent(event: WideEvent): void {
  const payload: Record<string, unknown> = {
    kind: "wide_event",
    event_name: event.name,
    service: event.service,
    occurred_at: new Date().toISOString()
  };
  if (event.organizationId && event.organizationId.trim() !== "") {
    payload.organization_id = event.organizationId;
  }
  // Empty strings and non-finite numbers are dropped so the emitted event keeps
  // the same "non-empty only" contract as the Go collector.
  for (const [key, value] of Object.entries(event.dimensions ?? {})) {
    if (typeof value === "string" && value.trim() !== "") {
      payload[key] = value;
    }
  }
  for (const [key, value] of Object.entries(event.measurements ?? {})) {
    if (typeof value === "number" && Number.isFinite(value)) {
      payload[key] = value;
    }
  }
  try {
    sink(JSON.stringify(payload));
  } catch {
    // Telemetry is best-effort; a serialization or write failure must never
    // interrupt the unit of work that produced the event.
  }
}

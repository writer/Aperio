import {
  validateEncodedAperioEvent,
  type EncodedAperioEvent
} from "@aperio/shared/protobuf-contracts";

type EventPublisher = {
  publish(event: EncodedAperioEvent): Promise<void>;
  close(): Promise<void>;
};

class NoopEventPublisher implements EventPublisher {
  async publish(): Promise<void> {}
  async close(): Promise<void> {}
}

class NatsJetStreamPublisher implements EventPublisher {
  private connectionPromise: Promise<{
    connection: import("nats").NatsConnection;
    jetstream: import("nats").JetStreamClient;
  }> | null = null;

  constructor(
    private readonly servers: string,
    private readonly streamName: string
  ) {}

  private async connect() {
    if (!this.connectionPromise) {
      // Load NATS lazily so test and noop-worker paths do not require a live
      // broker or pay module initialization cost.
      this.connectionPromise = (async () => {
        const { connect } = await import("nats");
        const connection = await connect({
          servers: this.servers.split(",").map((server) => server.trim())
        });
        await ensureStream(connection, this.streamName);
        return {
          connection,
          jetstream: connection.jetstream()
        };
      })().catch((error) => {
        // Allow a later publish to retry connection setup after transient broker
        // or DNS failures.
        this.connectionPromise = null;
        throw error;
      });
    }
    return this.connectionPromise;
  }

  async publish(event: EncodedAperioEvent): Promise<void> {
    const { jetstream } = await this.connect();
    // msgID aligns with Go publishing and gives JetStream duplicate suppression
    // for retrying the same encoded envelope.
    await jetstream.publish(event.subject, event.payload, {
      msgID: event.id
    });
  }

  async close(): Promise<void> {
    if (!this.connectionPromise) return;
    const { connection } = await this.connectionPromise;
    await connection.drain();
    this.connectionPromise = null;
  }
}

async function ensureStream(
  connection: import("nats").NatsConnection,
  streamName: string
) {
  const manager = await connection.jetstreamManager();
  try {
    await manager.streams.info(streamName);
  } catch {
    // Workers can bootstrap local/CI streams; production operators may still
    // pre-provision the stream with stricter retention and replicas.
    await manager.streams.add({
      name: streamName,
      subjects: ["events.>"]
    });
  }
}

let publisher: EventPublisher | null = null;

export function getEventPublisher(): EventPublisher {
  if (publisher) return publisher;
  const backend = process.env.APERIO_EVENT_BUS?.trim().toLowerCase() ?? "noop";
  if (backend === "nats") {
    const servers = process.env.APERIO_NATS_URL?.trim() || "nats://127.0.0.1:4222";
    const streamName = process.env.APERIO_NATS_STREAM?.trim() || "CEREBRO_EVENTS";
    publisher = new NatsJetStreamPublisher(servers, streamName);
  } else {
    // Noop is the default so ingestion and SIEM tests do not depend on NATS.
    publisher = new NoopEventPublisher();
  }
  return publisher;
}

export async function publishAperioEvent(event: EncodedAperioEvent): Promise<void> {
  try {
    // Validate before publish to catch contract drift at the producer boundary
    // rather than after consumers receive an invalid protobuf envelope.
    validateEncodedAperioEvent(event);
    await getEventPublisher().publish(event);
  } catch (error) {
    // Event delivery is observability/fanout, not the source of truth. Warn and
    // continue so queue processing does not fail solely because the bus is down.
    console.warn(
      "event_bus.publish_failed",
      error instanceof Error ? error.message : "unknown error"
    );
  }
}

export async function closeEventPublisher(): Promise<void> {
  if (!publisher) return;
  // drain() flushes in-flight NATS publishes during graceful worker shutdown.
  await publisher.close();
  publisher = null;
}

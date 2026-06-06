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
        this.connectionPromise = null;
        throw error;
      });
    }
    return this.connectionPromise;
  }

  async publish(event: EncodedAperioEvent): Promise<void> {
    const { jetstream } = await this.connect();
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
    publisher = new NoopEventPublisher();
  }
  return publisher;
}

export async function publishAperioEvent(event: EncodedAperioEvent): Promise<void> {
  try {
    validateEncodedAperioEvent(event);
    await getEventPublisher().publish(event);
  } catch (error) {
    console.warn(
      "event_bus.publish_failed",
      error instanceof Error ? error.message : "unknown error"
    );
  }
}

export async function closeEventPublisher(): Promise<void> {
  if (!publisher) return;
  await publisher.close();
  publisher = null;
}

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);

export function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

export function readJsonFixture<T>(relativePath: string): T {
  return JSON.parse(readRepoFile(relativePath)) as T;
}

export function packageScripts() {
  return readJsonFixture<{ scripts: Record<string, string> }>("package.json")
    .scripts;
}

export function makeTargetBlock(makefile: string, target: string) {
  const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = makefile.match(new RegExp(`^${escapedTarget}:.*(?:\\n\\t.*)*`, "m"));
  if (!match) {
    throw new Error(`expected Makefile target ${target}`);
  }
  return match[0];
}

export type RuntimeClassification =
  | "typescript-ingestion-reference"
  | "typescript-siem-reference"
  | "typescript-mcp-reference"
  | "go-ingestion"
  | "go-siem"
  | "go-mcp"
  | "go-api"
  | "validation-or-tooling";

export function classifyRuntimeCommand(command: string): RuntimeClassification {
  const normalized = command.replace(/\s+/g, " ");
  if (/\btsx\b.*workers\/ingestion-worker\.ts/.test(normalized)) {
    return "typescript-ingestion-reference";
  }
  if (/\btsx\b.*workers\/siem-dispatcher\.ts/.test(normalized)) {
    return "typescript-siem-reference";
  }
  if (/\btsx\b.*apps\/mcp\/src\/server\.ts/.test(normalized)) {
    return "typescript-mcp-reference";
  }
  if (/go run \.\/cmd\/ingestion-worker/.test(normalized)) {
    return "go-ingestion";
  }
  if (/npm run worker:ingestion --/.test(normalized)) {
    return "go-ingestion";
  }
  if (/go run \.\/cmd\/siem-dispatcher/.test(normalized)) {
    return "go-siem";
  }
  if (/npm run worker:siem --/.test(normalized)) {
    return "go-siem";
  }
  if (/go run \.\/cmd\/mcp-broker/.test(normalized)) {
    return "go-mcp";
  }
  if (/go run \.\/cmd\/aperio/.test(normalized)) {
    return "go-api";
  }
  return "validation-or-tooling";
}

export type IngestionJobFixture = {
  organizationId: string;
  integrationId: string;
  provider: string;
  eventType: string;
  source: string;
  actor: string;
  occurredAt: string;
  payload: Record<string, unknown>;
};

export function buildIngestionJobFixture(
  input: IngestionJobFixture
): IngestionJobFixture & { occurredAtDate: Date } {
  const occurredAtDate = new Date(input.occurredAt);
  if (Number.isNaN(occurredAtDate.valueOf())) {
    throw new Error(`invalid fixture occurredAt: ${input.occurredAt}`);
  }
  return {
    ...input,
    occurredAtDate
  };
}

export type CapturedRequest = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
};

export function assertLocalOnlyEndpoint(endpointUrl: string) {
  const parsed = new URL(endpointUrl);
  const host = parsed.hostname.toLowerCase();
  const localHost =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.endsWith(".test");
  if (!localHost) {
    throw new Error(`fixture endpoint must be local or .test, got ${endpointUrl}`);
  }
}

export function createLocalRequestCapture(endpointUrl: string) {
  assertLocalOnlyEndpoint(endpointUrl);
  const requests: CapturedRequest[] = [];
  return {
    endpointUrl,
    requests,
    record(request: CapturedRequest) {
      assertLocalOnlyEndpoint(request.url);
      if (request.url !== endpointUrl) {
        throw new Error(`unexpected capture URL ${request.url}; want ${endpointUrl}`);
      }
      requests.push({
        method: request.method,
        url: request.url,
        headers: { ...request.headers },
        body: JSON.parse(JSON.stringify(request.body)) as unknown
      });
    }
  };
}

export function assertNoPlaintext(
  value: unknown,
  forbiddenPlaintexts: string[]
) {
  const encoded = typeof value === "string" ? value : JSON.stringify(value);
  for (const plaintext of forbiddenPlaintexts) {
    if (plaintext && encoded.includes(plaintext)) {
      throw new Error(`captured fixture output leaked plaintext sentinel ${plaintext}`);
    }
  }
}

export function encodeMcpFrame(message: unknown) {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
}

export function decodeMcpFrames(input: string | Buffer) {
  let buffer = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  const messages: unknown[] = [];

  while (buffer.length > 0) {
    const separator = buffer.indexOf("\r\n\r\n");
    if (separator === -1) {
      break;
    }
    const header = buffer.subarray(0, separator).toString("utf8");
    const match = /content-length:\s*(\d+)/i.exec(header);
    if (!match) {
      throw new Error(`missing Content-Length header in ${header}`);
    }
    const length = Number(match[1]);
    const bodyStart = separator + 4;
    const bodyEnd = bodyStart + length;
    if (buffer.length < bodyEnd) {
      break;
    }
    const body = buffer.subarray(bodyStart, bodyEnd).toString("utf8");
    messages.push(JSON.parse(body));
    buffer = buffer.subarray(bodyEnd);
  }

  return {
    messages,
    remaining: buffer.toString("utf8")
  };
}

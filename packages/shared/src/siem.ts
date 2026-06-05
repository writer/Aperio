import { z } from "zod";

export type SiemKindKey =
  | "SPLUNK_HEC"
  | "PANTHER"
  | "PANOPTICON"
  | "ELASTIC"
  | "DATADOG"
  | "GENERIC_WEBHOOK"
  | "JSON_FILE";

export type SiemStreamKey = "FINDINGS" | "EVENTS" | "AUDIT_LOGS";

export const siemStreams: SiemStreamKey[] = [
  "FINDINGS",
  "EVENTS",
  "AUDIT_LOGS"
];

export type SiemField = {
  key: "endpointUrl" | "token" | "filePath" | "index";
  label: string;
  placeholder?: string;
  helper?: string;
  type: "text" | "password" | "url";
  required: boolean;
  secret: boolean;
};

export type SiemDestinationDefinition = {
  kind: SiemKindKey;
  name: string;
  vendor: string;
  description: string;
  category: "Cloud SIEM" | "Hosted Search" | "Observability" | "Generic";
  docsUrl: string;
  defaultStreams: SiemStreamKey[];
  fields: SiemField[];
};

const splunkFields: SiemField[] = [
  {
    key: "endpointUrl",
    label: "HEC Endpoint",
    placeholder: "https://splunk.example.com:8088/services/collector",
    type: "url",
    required: true,
    secret: false
  },
  {
    key: "token",
    label: "HEC Token",
    placeholder: "00000000-0000-0000-0000-000000000000",
    helper:
      "Token is encrypted with AES-256-GCM before storage and decrypted only inside the dispatcher.",
    type: "password",
    required: true,
    secret: true
  },
  {
    key: "index",
    label: "Index (optional)",
    placeholder: "aperio",
    type: "text",
    required: false,
    secret: false
  }
];

const pantherFields: SiemField[] = [
  {
    key: "endpointUrl",
    label: "Panther HTTP Log Source URL",
    placeholder:
      "https://logs.runpanther.io/http/source/...",
    type: "url",
    required: true,
    secret: false
  },
  {
    key: "token",
    label: "Shared secret / Bearer token",
    type: "password",
    required: true,
    secret: true
  }
];

const panopticonFields: SiemField[] = [
  {
    key: "endpointUrl",
    label: "Panopticon ingest URL",
    placeholder: "https://panopticon.example.com/api/aperio/findings",
    type: "url",
    required: true,
    secret: false
  },
  {
    key: "token",
    label: "Bearer token / shared secret",
    helper:
      "Panopticon is treated as a schema-flexible JSON destination until its private ingestion contract is available.",
    type: "password",
    required: false,
    secret: true
  }
];

const elasticFields: SiemField[] = [
  {
    key: "endpointUrl",
    label: "Elasticsearch _bulk URL",
    placeholder: "https://es.example.com:9200/_bulk",
    type: "url",
    required: true,
    secret: false
  },
  {
    key: "token",
    label: "API key (base64)",
    type: "password",
    required: true,
    secret: true
  },
  {
    key: "index",
    label: "Index",
    placeholder: "aperio-findings",
    type: "text",
    required: true,
    secret: false
  }
];

const datadogFields: SiemField[] = [
  {
    key: "endpointUrl",
    label: "Datadog Logs intake URL",
    placeholder: "https://http-intake.logs.datadoghq.com/api/v2/logs",
    type: "url",
    required: true,
    secret: false
  },
  {
    key: "token",
    label: "DD-API-KEY",
    type: "password",
    required: true,
    secret: true
  }
];

const webhookFields: SiemField[] = [
  {
    key: "endpointUrl",
    label: "Webhook URL",
    placeholder: "https://siem.example.com/aperio",
    type: "url",
    required: true,
    secret: false
  },
  {
    key: "token",
    label: "HMAC signing secret (optional)",
    helper: "If provided, each payload is signed with HMAC-SHA256.",
    type: "password",
    required: false,
    secret: true
  }
];

const fileFields: SiemField[] = [
  {
    key: "filePath",
    label: "Export file path",
    placeholder: "tenant-a/findings.jsonl",
    helper:
      "Findings are appended one JSON object per line inside the server's dedicated SIEM export directory.",
    type: "text",
    required: true,
    secret: false
  }
];

export const siemCatalog: SiemDestinationDefinition[] = [
  {
    kind: "SPLUNK_HEC",
    name: "Splunk HEC",
    vendor: "Splunk",
    category: "Cloud SIEM",
    description:
      "Ship findings to Splunk via the HTTP Event Collector. Supports custom index and source type.",
    docsUrl:
      "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
    defaultStreams: ["FINDINGS"],
    fields: splunkFields
  },
  {
    kind: "PANTHER",
    name: "Panther",
    vendor: "Panther Labs",
    category: "Cloud SIEM",
    description:
      "Stream findings into a Panther HTTP Log Source for detection-as-code workflows.",
    docsUrl: "https://docs.panther.com/data-onboarding/data-transports/http",
    defaultStreams: ["FINDINGS", "EVENTS"],
    fields: pantherFields
  },
  {
    kind: "PANOPTICON",
    name: "Panopticon",
    vendor: "Panopticon",
    category: "Cloud SIEM",
    description:
      "Stream canonical Aperio findings into a Panopticon-compatible JSON ingest endpoint.",
    docsUrl: "https://github.com/search?q=panopticon+siem&type=repositories",
    defaultStreams: ["FINDINGS", "EVENTS"],
    fields: panopticonFields
  },
  {
    kind: "ELASTIC",
    name: "Elasticsearch",
    vendor: "Elastic",
    category: "Hosted Search",
    description:
      "Bulk index findings into Elasticsearch. Supply the target index and an API key.",
    docsUrl:
      "https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html",
    defaultStreams: ["FINDINGS"],
    fields: elasticFields
  },
  {
    kind: "DATADOG",
    name: "Datadog Logs",
    vendor: "Datadog",
    category: "Observability",
    description:
      "Forward findings into Datadog Logs with the standard logs intake.",
    docsUrl: "https://docs.datadoghq.com/api/latest/logs/",
    defaultStreams: ["FINDINGS"],
    fields: datadogFields
  },
  {
    kind: "GENERIC_WEBHOOK",
    name: "Generic Webhook",
    vendor: "Custom",
    category: "Generic",
    description:
      "POST findings as JSON to any HTTPS endpoint. Optional HMAC-SHA256 signature header.",
    docsUrl: "https://en.wikipedia.org/wiki/Webhook",
    defaultStreams: ["FINDINGS"],
    fields: webhookFields
  },
  {
    kind: "JSON_FILE",
    name: "JSON Lines File",
    vendor: "Local",
    category: "Generic",
    description:
      "Append findings to a local JSONL file. Useful for development, air-gapped audits, or downstream filebeat-style shippers.",
    docsUrl: "https://jsonlines.org/",
    defaultStreams: ["FINDINGS"],
    fields: fileFields
  }
];

export function findSiemDefinition(
  kind: SiemKindKey
): SiemDestinationDefinition | undefined {
  return siemCatalog.find((definition) => definition.kind === kind);
}

const siemKindSchema = z.enum([
  "SPLUNK_HEC",
  "PANTHER",
  "PANOPTICON",
  "ELASTIC",
  "DATADOG",
  "GENERIC_WEBHOOK",
  "JSON_FILE"
]);

export const siemStreamSchema = z.enum(["FINDINGS", "EVENTS", "AUDIT_LOGS"]);

export const createSiemDestinationSchema = z
  .object({
    kind: siemKindSchema,
    name: z.string().trim().min(1).max(160),
    endpointUrl: z.string().trim().url().max(500).optional(),
    filePath: z.string().trim().min(1).max(500).optional(),
    index: z.string().trim().min(1).max(120).optional(),
    token: z.string().trim().min(1).max(8192).optional(),
    streams: z.array(siemStreamSchema).min(1).default(["FINDINGS"])
  })
  .strict();

export type CreateSiemDestinationInput = z.infer<
  typeof createSiemDestinationSchema
>;

export function validateSiemPayload(
  input: CreateSiemDestinationInput
): string | null {
  const definition = findSiemDefinition(input.kind);
  if (!definition) {
    return `Unsupported SIEM kind ${input.kind}`;
  }
  for (const field of definition.fields) {
    if (!field.required) continue;
    if (field.key === "endpointUrl" && !input.endpointUrl) {
      return `${field.label} is required`;
    }
    if (field.key === "token" && !input.token) {
      return `${field.label} is required`;
    }
    if (field.key === "filePath" && !input.filePath) {
      return `${field.label} is required`;
    }
    if (field.key === "index" && !input.index) {
      return `${field.label} is required`;
    }
  }
  return null;
}

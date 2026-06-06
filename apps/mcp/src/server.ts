import type { Prisma } from "@prisma/client";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { prisma } from "@aperio/db";
import {
  agentTaskStatusSchema,
  createAgentProposalSchema,
  createAgentTaskSchema,
  enqueueSiemPayloadSchema,
  registerAgentSchema,
  sendAgentMessageSchema
} from "@aperio/shared/a2a";
import {
  drainSiemDeliveries,
  enqueueSiemDeliveries
} from "../../../workers/siem-dispatcher";

type RpcId = string | number | null;
type RpcMessage = {
  jsonrpc?: "2.0";
  id?: RpcId;
  method?: string;
  params?: unknown;
};

const organizationScopedSchema = z.object({
  organizationId: z.string().trim().min(1),
  authToken: z.string().trim().min(1).optional()
});

function jsonSafe(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

async function getAgentId(organizationId: string, key?: string) {
  if (!key) return null;
  const agent = await prisma.agent.findUnique({
    where: { organizationId_key: { organizationId, key } },
    select: { id: true }
  });
  if (!agent) {
    throw new Error(`Agent not found: ${key}`);
  }
  return agent.id;
}

async function ensureTaskId(organizationId: string, taskId?: string | null) {
  if (!taskId) return null;
  const task = await prisma.agentTask.findFirst({
    where: { id: taskId, organizationId },
    select: { id: true }
  });
  if (!task) {
    throw new Error(`Task not found: ${taskId}`);
  }
  return task.id;
}

async function ensureFindingId(
  organizationId: string,
  findingId?: string | null
) {
  if (!findingId) return null;
  const finding = await prisma.securityFinding.findFirst({
    where: { id: findingId, organizationId },
    select: { id: true }
  });
  if (!finding) {
    throw new Error(`Finding not found: ${findingId}`);
  }
  return finding.id;
}

function safeEqual(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function assertMcpScope(input: { organizationId: string; authToken?: string }) {
  const allowedOrganizationId = process.env.APERIO_MCP_ORGANIZATION_ID?.trim();
  if (
    allowedOrganizationId &&
    input.organizationId !== allowedOrganizationId
  ) {
    throw new Error("Organization is not allowed for this MCP broker");
  }
  const sharedSecret = process.env.APERIO_MCP_SHARED_SECRET?.trim();
  if (sharedSecret && !safeEqual(input.authToken ?? "", sharedSecret)) {
    throw new Error("Invalid MCP broker token");
  }
}

function sendFrame(message: unknown) {
  const body = JSON.stringify(message);
  process.stdout.write(
    `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`
  );
}

function respond(id: RpcId | undefined, result: unknown) {
  if (id === undefined) return;
  sendFrame({ jsonrpc: "2.0", id, result });
}

function respondError(id: RpcId | undefined, code: number, message: string) {
  if (id === undefined) return;
  sendFrame({ jsonrpc: "2.0", id, error: { code, message } });
}

const tools = [
  {
    name: "aperio.register_agent",
    description: "Register or heartbeat an A2A-capable agent in Aperio.",
    inputSchema: {
      type: "object",
      required: ["organizationId", "key", "name"],
      properties: {
        organizationId: { type: "string" },
        authToken: { type: "string" },
        key: { type: "string" },
        name: { type: "string" },
        kind: { type: "string" },
        capabilities: { type: "array", items: { type: "string" } },
        endpointUrl: { type: "string" },
        mcpServerUrl: { type: "string" },
        status: { type: "string" }
      }
    }
  },
  {
    name: "aperio.create_task",
    description: "Create an ADLC task for an agent or sub-agent.",
    inputSchema: {
      type: "object",
      required: ["organizationId", "taskType", "title"],
      properties: {
        organizationId: { type: "string" },
        authToken: { type: "string" },
        taskType: { type: "string" },
        title: { type: "string" },
        input: { type: "object" },
        createdByAgentKey: { type: "string" },
        assignedAgentKey: { type: "string" },
        parentTaskId: { type: "string" }
      }
    }
  },
  {
    name: "aperio.send_message",
    description: "Send a task-scoped A2A message between registered agents.",
    inputSchema: {
      type: "object",
      required: ["organizationId", "content"],
      properties: {
        organizationId: { type: "string" },
        authToken: { type: "string" },
        taskId: { type: "string" },
        fromAgentKey: { type: "string" },
        toAgentKey: { type: "string" },
        role: { type: "string" },
        messageType: { type: "string" },
        correlationId: { type: "string" },
        content: { type: "object" }
      }
    }
  },
  {
    name: "aperio.list_tasks",
    description: "List recent ADLC tasks by status or assigned agent.",
    inputSchema: {
      type: "object",
      required: ["organizationId"],
      properties: {
        organizationId: { type: "string" },
        authToken: { type: "string" },
        status: { type: "string" },
        assignedAgentKey: { type: "string" }
      }
    }
  },
  {
    name: "aperio.propose_remediation",
    description: "Create a human-gated remediation proposal from an agent.",
    inputSchema: {
      type: "object",
      required: ["organizationId", "action", "rationale", "payload"],
      properties: {
        organizationId: { type: "string" },
        authToken: { type: "string" },
        taskId: { type: "string" },
        findingId: { type: "string" },
        proposedByAgentKey: { type: "string" },
        action: { type: "string" },
        rationale: { type: "string" },
        payload: { type: "object" }
      }
    }
  },
  {
    name: "aperio.enqueue_siem_payload",
    description: "Durably enqueue a canonical Aperio SIEM payload.",
    inputSchema: {
      type: "object",
      required: ["organizationId", "record"],
      properties: {
        organizationId: { type: "string" },
        authToken: { type: "string" },
        kind: { type: "string" },
        occurredAt: { type: "string" },
        record: { type: "object" }
      }
    }
  }
];

async function callTool(name: string, args: unknown) {
  if (name === "aperio.register_agent") {
    const scoped = organizationScopedSchema.merge(registerAgentSchema).parse(args);
    assertMcpScope(scoped);
    const agent = await prisma.agent.upsert({
      where: {
        organizationId_key: {
          organizationId: scoped.organizationId,
          key: scoped.key
        }
      },
      create: {
        organizationId: scoped.organizationId,
        key: scoped.key,
        name: scoped.name,
        kind: scoped.kind,
        capabilities: scoped.capabilities,
        endpointUrl: scoped.endpointUrl ?? null,
        mcpServerUrl: scoped.mcpServerUrl ?? null,
        status: scoped.status,
        lastSeenAt: new Date()
      },
      update: {
        name: scoped.name,
        kind: scoped.kind,
        capabilities: scoped.capabilities,
        endpointUrl: scoped.endpointUrl ?? null,
        mcpServerUrl: scoped.mcpServerUrl ?? null,
        status: scoped.status,
        lastSeenAt: new Date()
      }
    });
    return { agentId: agent.id, key: agent.key, status: agent.status };
  }

  if (name === "aperio.create_task") {
    const scoped = organizationScopedSchema.merge(createAgentTaskSchema).parse(args);
    assertMcpScope(scoped);
    const [createdByAgentId, assignedAgentId] = await Promise.all([
      getAgentId(scoped.organizationId, scoped.createdByAgentKey),
      getAgentId(scoped.organizationId, scoped.assignedAgentKey)
    ]);
    const parentTaskId = await ensureTaskId(
      scoped.organizationId,
      scoped.parentTaskId
    );
    const task = await prisma.agentTask.create({
      data: {
        organizationId: scoped.organizationId,
        taskType: scoped.taskType,
        title: scoped.title,
        input: jsonSafe(scoped.input),
        createdByAgentId,
        assignedAgentId,
        parentTaskId
      }
    });
    return { taskId: task.id, status: task.status };
  }

  if (name === "aperio.send_message") {
    const scoped = organizationScopedSchema.merge(sendAgentMessageSchema).parse(args);
    assertMcpScope(scoped);
    const [fromAgentId, toAgentId] = await Promise.all([
      getAgentId(scoped.organizationId, scoped.fromAgentKey),
      getAgentId(scoped.organizationId, scoped.toAgentKey)
    ]);
    const taskId = await ensureTaskId(scoped.organizationId, scoped.taskId);
    const message = await prisma.agentMessage.create({
      data: {
        organizationId: scoped.organizationId,
        taskId,
        fromAgentId,
        toAgentId,
        role: scoped.role,
        messageType: scoped.messageType,
        correlationId: scoped.correlationId ?? null,
        content: jsonSafe(scoped.content)
      }
    });
    return { messageId: message.id, createdAt: message.createdAt.toISOString() };
  }

  if (name === "aperio.list_tasks") {
    const parsed = organizationScopedSchema
      .extend({
        status: agentTaskStatusSchema.optional(),
        assignedAgentKey: z.string().trim().min(2).max(120).optional()
      })
      .parse(args);
    assertMcpScope(parsed);
    const assignedAgentId = await getAgentId(
      parsed.organizationId,
      parsed.assignedAgentKey
    );
    const tasks = await prisma.agentTask.findMany({
      where: {
        organizationId: parsed.organizationId,
        status: parsed.status,
        assignedAgentId: assignedAgentId ?? undefined
      },
      include: {
        assignedAgent: { select: { key: true, name: true, kind: true } },
        createdByAgent: { select: { key: true, name: true, kind: true } }
      },
      orderBy: { createdAt: "desc" },
      take: 50
    });
    return { tasks };
  }

  if (name === "aperio.propose_remediation") {
    const scoped = organizationScopedSchema
      .merge(createAgentProposalSchema)
      .parse(args);
    assertMcpScope(scoped);
    const proposedByAgentId = await getAgentId(
      scoped.organizationId,
      scoped.proposedByAgentKey
    );
    const [taskId, findingId] = await Promise.all([
      ensureTaskId(scoped.organizationId, scoped.taskId),
      ensureFindingId(scoped.organizationId, scoped.findingId)
    ]);
    const proposal = await prisma.agentProposal.create({
      data: {
        organizationId: scoped.organizationId,
        taskId,
        findingId,
        proposedByAgentId,
        action: scoped.action,
        rationale: scoped.rationale,
        payload: jsonSafe(scoped.payload)
      }
    });
    return { proposalId: proposal.id, status: proposal.status };
  }

  if (name === "aperio.enqueue_siem_payload") {
    const parsed = organizationScopedSchema.merge(enqueueSiemPayloadSchema).parse(args);
    assertMcpScope(parsed);
    const count = await enqueueSiemDeliveries({
      kind: parsed.kind,
      organizationId: parsed.organizationId,
      occurredAt: parsed.occurredAt ?? new Date().toISOString(),
      record: parsed.record
    });
    void drainSiemDeliveries().catch(() => undefined);
    return { enqueued: count };
  }

  throw new Error(`Unknown tool: ${name}`);
}

async function handleMessage(message: RpcMessage) {
  if (message.method === "initialize") {
    respond(message.id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "aperio-a2a-broker", version: "0.1.0" }
    });
    return;
  }
  if (message.method === "notifications/initialized") {
    return;
  }
  if (message.method === "ping") {
    respond(message.id, {});
    return;
  }
  if (message.method === "tools/list") {
    respond(message.id, { tools });
    return;
  }
  if (message.method === "tools/call") {
    try {
      const params = z
        .object({
          name: z.string(),
          arguments: z.unknown().default({})
        })
        .parse(message.params);
      const result = await callTool(params.name, params.arguments);
      respond(message.id, {
        content: [{ type: "text", text: JSON.stringify(result) }]
      });
    } catch (error) {
      respond(message.id, {
        isError: true,
        content: [
          {
            type: "text",
            text: error instanceof Error ? error.message : "Tool failed"
          }
        ]
      });
    }
    return;
  }
  respondError(message.id, -32601, `Method not found: ${message.method}`);
}

let buffer = Buffer.alloc(0);

process.stdin.on("data", (chunk: Buffer) => {
  buffer = Buffer.concat([buffer, chunk]);
  while (true) {
    const separator = buffer.indexOf("\r\n\r\n");
    if (separator === -1) return;
    const header = buffer.subarray(0, separator).toString("utf8");
    const match = /content-length:\s*(\d+)/i.exec(header);
    if (!match) {
      buffer = buffer.subarray(separator + 4);
      continue;
    }
    const length = Number(match[1]);
    const start = separator + 4;
    const end = start + length;
    if (buffer.length < end) return;
    const body = buffer.subarray(start, end).toString("utf8");
    buffer = buffer.subarray(end);
    try {
      const message = JSON.parse(body) as RpcMessage;
      void handleMessage(message).catch((error) => {
        respondError(
          message.id ?? null,
          -32603,
          error instanceof Error ? error.message : "Internal error"
        );
      });
    } catch (error) {
      respondError(
        null,
        -32700,
        error instanceof Error ? error.message : "Invalid JSON"
      );
    }
  }
});

process.on("SIGINT", () => {
  void prisma.$disconnect().finally(() => process.exit(0));
});

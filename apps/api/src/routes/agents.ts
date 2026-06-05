import {
  Router,
  type NextFunction,
  type RequestHandler,
  type Response
} from "express";
import type { Prisma } from "@prisma/client";
import { prisma } from "@aperio/db";
import {
  agentTaskStatusSchema,
  createAgentProposalSchema,
  createAgentTaskSchema,
  decideAgentProposalSchema,
  registerAgentSchema,
  sendAgentMessageSchema,
  updateAgentTaskSchema
} from "@aperio/shared/a2a";
import { requireRole, type TenantRequest } from "../middleware/security";

export const agentsRouter = Router();

function jsonSafe(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

async function getAgentId(organizationId: string, key?: string) {
  if (!key) return null;
  const agent = await prisma.agent.findUnique({
    where: { organizationId_key: { organizationId, key } },
    select: { id: true }
  });
  return agent?.id ?? null;
}

async function taskExists(organizationId: string, taskId?: string | null) {
  if (!taskId) return true;
  const task = await prisma.agentTask.findFirst({
    where: { id: taskId, organizationId },
    select: { id: true }
  });
  return Boolean(task);
}

async function findingExists(organizationId: string, findingId?: string | null) {
  if (!findingId) return true;
  const finding = await prisma.securityFinding.findFirst({
    where: { id: findingId, organizationId },
    select: { id: true }
  });
  return Boolean(finding);
}

function serializeDate(value: Date | null | undefined) {
  return value ? value.toISOString() : null;
}

const listAgents: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const agents = await prisma.agent.findMany({
      where: { organizationId: tenantReq.tenantId },
      orderBy: [{ kind: "asc" }, { name: "asc" }]
    });
    return res.json({
      data: agents.map((agent) => ({
        ...agent,
        createdAt: agent.createdAt.toISOString(),
        updatedAt: agent.updatedAt.toISOString(),
        lastSeenAt: serializeDate(agent.lastSeenAt)
      }))
    });
  } catch (error) {
    return next(error);
  }
};

const registerAgent: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = registerAgentSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid agent payload", details: parsed.error.flatten() });
    }
    const agent = await prisma.agent.upsert({
      where: {
        organizationId_key: {
          organizationId: tenantReq.tenantId,
          key: parsed.data.key
        }
      },
      create: {
        organizationId: tenantReq.tenantId,
        key: parsed.data.key,
        name: parsed.data.name,
        kind: parsed.data.kind,
        capabilities: parsed.data.capabilities,
        endpointUrl: parsed.data.endpointUrl ?? null,
        mcpServerUrl: parsed.data.mcpServerUrl ?? null,
        status: parsed.data.status,
        lastSeenAt: new Date()
      },
      update: {
        name: parsed.data.name,
        kind: parsed.data.kind,
        capabilities: parsed.data.capabilities,
        endpointUrl: parsed.data.endpointUrl ?? null,
        mcpServerUrl: parsed.data.mcpServerUrl ?? null,
        status: parsed.data.status,
        lastSeenAt: new Date()
      }
    });
    await prisma.tenantAuditLog.create({
      data: {
        organizationId: tenantReq.tenantId,
        actorUserId: tenantReq.auth.userId,
        action: "agent.register",
        targetType: "agent",
        targetId: agent.id,
        ipAddress: req.ip,
        metadata: { key: agent.key, kind: agent.kind }
      }
    });
    return res.status(201).json({ data: agent });
  } catch (error) {
    return next(error);
  }
};

const createTask: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = createAgentTaskSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid task payload", details: parsed.error.flatten() });
    }
    const [createdByAgentId, assignedAgentId] = await Promise.all([
      getAgentId(tenantReq.tenantId, parsed.data.createdByAgentKey),
      getAgentId(tenantReq.tenantId, parsed.data.assignedAgentKey)
    ]);
    if (parsed.data.createdByAgentKey && !createdByAgentId) {
      return res.status(400).json({ error: "createdByAgentKey not found" });
    }
    if (parsed.data.assignedAgentKey && !assignedAgentId) {
      return res.status(400).json({ error: "assignedAgentKey not found" });
    }
    if (!(await taskExists(tenantReq.tenantId, parsed.data.parentTaskId))) {
      return res.status(404).json({ error: "parentTaskId not found" });
    }
    const task = await prisma.agentTask.create({
      data: {
        organizationId: tenantReq.tenantId,
        taskType: parsed.data.taskType,
        title: parsed.data.title,
        input: jsonSafe(parsed.data.input),
        createdByAgentId,
        assignedAgentId,
        parentTaskId: parsed.data.parentTaskId ?? null
      }
    });
    return res.status(201).json({ data: task });
  } catch (error) {
    return next(error);
  }
};

const listTasks: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const rawStatus =
      typeof req.query.status === "string" ? req.query.status : undefined;
    const parsedStatus = rawStatus
      ? agentTaskStatusSchema.safeParse(rawStatus)
      : null;
    if (rawStatus && !parsedStatus?.success) {
      return res.status(400).json({ error: "Invalid task status" });
    }
    const assignedAgentKey =
      typeof req.query.assignedAgentKey === "string"
        ? req.query.assignedAgentKey
        : undefined;
    const assignedAgentId = await getAgentId(
      tenantReq.tenantId,
      assignedAgentKey
    );
    if (assignedAgentKey && !assignedAgentId) {
      return res.status(404).json({ error: "assignedAgentKey not found" });
    }
    const tasks = await prisma.agentTask.findMany({
      where: {
        organizationId: tenantReq.tenantId,
        status: parsedStatus?.success ? parsedStatus.data : undefined,
        assignedAgentId: assignedAgentId ?? undefined
      },
      include: {
        assignedAgent: { select: { key: true, name: true, kind: true } },
        createdByAgent: { select: { key: true, name: true, kind: true } }
      },
      orderBy: { createdAt: "desc" },
      take: 100
    });
    return res.json({ data: tasks });
  } catch (error) {
    return next(error);
  }
};

const updateTask: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = updateAgentTaskSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid task update", details: parsed.error.flatten() });
    }
    const assignedAgentId = await getAgentId(
      tenantReq.tenantId,
      parsed.data.assignedAgentKey
    );
    if (parsed.data.assignedAgentKey && !assignedAgentId) {
      return res.status(400).json({ error: "assignedAgentKey not found" });
    }
    const existing = await prisma.agentTask.findFirst({
      where: { id: req.params.id, organizationId: tenantReq.tenantId },
      select: { id: true }
    });
    if (!existing) {
      return res.status(404).json({ error: "Task not found" });
    }
    const task = await prisma.agentTask.update({
      where: { id: existing.id },
      data: {
        status: parsed.data.status,
        output: parsed.data.output ? jsonSafe(parsed.data.output) : undefined,
        error: parsed.data.error,
        assignedAgentId: assignedAgentId ?? undefined,
        startedAt: parsed.data.status === "RUNNING" ? new Date() : undefined,
        completedAt:
          parsed.data.status === "SUCCEEDED" || parsed.data.status === "FAILED"
            ? new Date()
            : undefined
      }
    });
    return res.json({ data: task });
  } catch (error) {
    return next(error);
  }
};

const sendMessage: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = sendAgentMessageSchema.safeParse({
      ...req.body,
      taskId: req.params.id
    });
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid message", details: parsed.error.flatten() });
    }
    const [fromAgentId, toAgentId] = await Promise.all([
      getAgentId(tenantReq.tenantId, parsed.data.fromAgentKey),
      getAgentId(tenantReq.tenantId, parsed.data.toAgentKey)
    ]);
    if (parsed.data.fromAgentKey && !fromAgentId) {
      return res.status(400).json({ error: "fromAgentKey not found" });
    }
    if (parsed.data.toAgentKey && !toAgentId) {
      return res.status(400).json({ error: "toAgentKey not found" });
    }
    if (!(await taskExists(tenantReq.tenantId, parsed.data.taskId))) {
      return res.status(404).json({ error: "Task not found" });
    }
    const message = await prisma.agentMessage.create({
      data: {
        organizationId: tenantReq.tenantId,
        taskId: parsed.data.taskId ?? null,
        fromAgentId,
        toAgentId,
        role: parsed.data.role,
        messageType: parsed.data.messageType,
        correlationId: parsed.data.correlationId ?? null,
        content: jsonSafe(parsed.data.content)
      }
    });
    return res.status(201).json({ data: message });
  } catch (error) {
    return next(error);
  }
};

const listMessages: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    if (!(await taskExists(tenantReq.tenantId, req.params.id))) {
      return res.status(404).json({ error: "Task not found" });
    }
    const messages = await prisma.agentMessage.findMany({
      where: { organizationId: tenantReq.tenantId, taskId: req.params.id },
      include: {
        fromAgent: { select: { key: true, name: true } },
        toAgent: { select: { key: true, name: true } }
      },
      orderBy: { createdAt: "asc" },
      take: 200
    });
    return res.json({ data: messages });
  } catch (error) {
    return next(error);
  }
};

const createProposal: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = createAgentProposalSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid proposal", details: parsed.error.flatten() });
    }
    const proposedByAgentId = await getAgentId(
      tenantReq.tenantId,
      parsed.data.proposedByAgentKey
    );
    if (parsed.data.proposedByAgentKey && !proposedByAgentId) {
      return res.status(400).json({ error: "proposedByAgentKey not found" });
    }
    if (!(await taskExists(tenantReq.tenantId, parsed.data.taskId))) {
      return res.status(404).json({ error: "taskId not found" });
    }
    if (!(await findingExists(tenantReq.tenantId, parsed.data.findingId))) {
      return res.status(404).json({ error: "findingId not found" });
    }
    const proposal = await prisma.agentProposal.create({
      data: {
        organizationId: tenantReq.tenantId,
        taskId: parsed.data.taskId ?? null,
        findingId: parsed.data.findingId ?? null,
        proposedByAgentId,
        action: parsed.data.action,
        rationale: parsed.data.rationale,
        payload: jsonSafe(parsed.data.payload)
      }
    });
    return res.status(201).json({ data: proposal });
  } catch (error) {
    return next(error);
  }
};

const listProposals: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const proposals = await prisma.agentProposal.findMany({
      where: { organizationId: tenantReq.tenantId },
      include: {
        proposedByAgent: { select: { key: true, name: true, kind: true } },
        approvedBy: { select: { email: true, displayName: true } }
      },
      orderBy: { createdAt: "desc" },
      take: 100
    });
    return res.json({ data: proposals });
  } catch (error) {
    return next(error);
  }
};

const decideProposal: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = decideAgentProposalSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid decision", details: parsed.error.flatten() });
    }
    const existing = await prisma.agentProposal.findFirst({
      where: { id: req.params.id, organizationId: tenantReq.tenantId },
      select: { id: true }
    });
    if (!existing) {
      return res.status(404).json({ error: "Proposal not found" });
    }
    const proposal = await prisma.agentProposal.update({
      where: { id: existing.id },
      data: {
        status: parsed.data.decision,
        approvedByUserId:
          parsed.data.decision === "APPROVED" ? tenantReq.auth.userId : null,
        approvedAt: parsed.data.decision === "APPROVED" ? new Date() : null
      }
    });
    await prisma.tenantAuditLog.create({
      data: {
        organizationId: tenantReq.tenantId,
        actorUserId: tenantReq.auth.userId,
        action: `agent.proposal.${parsed.data.decision.toLowerCase()}`,
        targetType: "agent_proposal",
        targetId: proposal.id,
        ipAddress: req.ip,
        metadata: { note: parsed.data.note ?? null, action: proposal.action }
      }
    });
    return res.json({ data: proposal });
  } catch (error) {
    return next(error);
  }
};

agentsRouter.get("/", listAgents);
agentsRouter.post("/", requireRole(["OWNER", "ADMIN"]), registerAgent);
agentsRouter.get("/tasks", listTasks);
agentsRouter.post("/tasks", createTask);
agentsRouter.patch("/tasks/:id", updateTask);
agentsRouter.get("/tasks/:id/messages", listMessages);
agentsRouter.post("/tasks/:id/messages", sendMessage);
agentsRouter.get("/proposals", listProposals);
agentsRouter.post("/proposals", createProposal);
agentsRouter.patch(
  "/proposals/:id/decision",
  requireRole(["OWNER", "ADMIN"]),
  decideProposal
);

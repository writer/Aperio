import {
  Router,
  type NextFunction,
  type RequestHandler,
  type Response
} from "express";
import {
  assertSafeSiemEndpointUrl,
  normalizeSiemFilePath
} from "@aperio/shared/siem-security";
import { prisma } from "@aperio/db";
import { encryptString } from "@aperio/security";
import {
  createSiemDestinationSchema,
  findSiemDefinition,
  siemCatalog,
  validateSiemPayload
} from "@aperio/shared/siem";
import { requireRole, type TenantRequest } from "../middleware/security";
import { dispatchTestPing } from "../../../../workers/siem-dispatcher";

export const siemRouter = Router();

function serializeDestination(destination: {
  id: string;
  kind: string;
  name: string;
  endpointUrl: string | null;
  filePath: string | null;
  index: string | null;
  streams: string[];
  status: string;
  lastDeliveryAt: Date | null;
  lastError: string | null;
  deliveriesOk: number;
  deliveriesFail: number;
  createdAt: Date;
}) {
  return {
    id: destination.id,
    kind: destination.kind,
    name: destination.name,
    endpointUrl: destination.endpointUrl,
    filePath: destination.filePath,
    index: destination.index,
    streams: destination.streams,
    status: destination.status,
    lastDeliveryAt: destination.lastDeliveryAt?.toISOString() ?? null,
    lastError: destination.lastError,
    deliveriesOk: destination.deliveriesOk,
    deliveriesFail: destination.deliveriesFail,
    createdAt: destination.createdAt.toISOString()
  };
}

const listCatalog: RequestHandler = (_req, res: Response) => {
  res.json({ data: siemCatalog });
};

const listDestinations: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const destinations = await prisma.siemDestination.findMany({
      where: { organizationId: tenantReq.tenantId },
      orderBy: [{ createdAt: "desc" }],
      select: {
        id: true,
        kind: true,
        name: true,
        endpointUrl: true,
        filePath: true,
        index: true,
        streams: true,
        status: true,
        lastDeliveryAt: true,
        lastError: true,
        deliveriesOk: true,
        deliveriesFail: true,
        createdAt: true
      }
    });
    return res.json({
      data: destinations.map(serializeDestination)
    });
  } catch (error) {
    return next(error);
  }
};

const createDestination: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = createSiemDestinationSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid SIEM payload", details: parsed.error.flatten() });
    }
    const definition = findSiemDefinition(parsed.data.kind);
    if (!definition) {
      return res.status(404).json({ error: "Unsupported SIEM kind" });
    }
    const validationError = validateSiemPayload(parsed.data);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const endpointUrl = parsed.data.endpointUrl?.trim() ?? null;
    if (endpointUrl) {
      const endpointError = await assertSafeSiemEndpointUrl(endpointUrl);
      if (endpointError) {
        return res.status(400).json({ error: endpointError });
      }
    }

    let filePath = parsed.data.filePath?.trim() ?? null;
    if (filePath) {
      const normalizedFilePath = normalizeSiemFilePath(filePath);
      if ("error" in normalizedFilePath) {
        return res.status(400).json({ error: normalizedFilePath.error });
      }
      filePath = normalizedFilePath.absolutePath;
    }

    const created = await prisma.$transaction(async (tx) => {
      const destination = await tx.siemDestination.create({
        data: {
          organizationId: tenantReq.tenantId,
          kind: parsed.data.kind,
          name: parsed.data.name,
          endpointUrl: endpointUrl ? new URL(endpointUrl).toString() : null,
          filePath,
          index: parsed.data.index ?? null,
          streams: parsed.data.streams,
          encryptedToken: null,
          status: "ACTIVE"
        }
      });

      if (parsed.data.token) {
        const aad = `${tenantReq.tenantId}:siem:${destination.id}:token`;
        const reEncrypted = encryptString(parsed.data.token, aad);
        await tx.siemDestination.update({
          where: { id: destination.id },
          data: { encryptedToken: reEncrypted }
        });
        destination.encryptedToken = reEncrypted;
      }

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "siem.destination.create",
          targetType: "siem_destination",
          targetId: destination.id,
          ipAddress: req.ip,
          metadata: {
            kind: destination.kind,
            name: destination.name,
            streams: destination.streams
          }
        }
      });

      return destination;
    });

    return res.status(201).json({ data: serializeDestination(created) });
  } catch (error) {
    return next(error);
  }
};

const deleteDestination: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const destinationId = req.params.id;
  if (!destinationId) {
    return res.status(400).json({ error: "Destination id is required" });
  }
  try {
    const removed = await prisma.$transaction(async (tx) => {
      const existing = await tx.siemDestination.findFirst({
        where: { id: destinationId, organizationId: tenantReq.tenantId }
      });
      if (!existing) return null;
      await tx.siemDestination.delete({ where: { id: existing.id } });
      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "siem.destination.delete",
          targetType: "siem_destination",
          targetId: existing.id,
          ipAddress: req.ip,
          metadata: {
            kind: existing.kind,
            name: existing.name
          }
        }
      });
      return existing;
    });
    if (!removed) {
      return res.status(404).json({ error: "Destination not found" });
    }
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
};

const testDestination: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const destinationId = req.params.id;
  if (!destinationId) {
    return res.status(400).json({ error: "Destination id is required" });
  }
  try {
    const result = await dispatchTestPing(destinationId, tenantReq.tenantId);
    if (result.message === "destination not found") {
      return res.status(404).json({ error: "Destination not found" });
    }
    await prisma.tenantAuditLog.create({
      data: {
        organizationId: tenantReq.tenantId,
        actorUserId: tenantReq.auth.userId,
        action: result.ok ? "siem.destination.test.ok" : "siem.destination.test.fail",
        targetType: "siem_destination",
        targetId: destinationId,
        ipAddress: req.ip,
        metadata: { message: result.message }
      }
    });
    return res.json({ data: result });
  } catch (error) {
    return next(error);
  }
};

siemRouter.get("/catalog", listCatalog);
siemRouter.get("/", listDestinations);
siemRouter.post("/", requireRole(["OWNER", "ADMIN"]), createDestination);
siemRouter.post(
  "/:id/test",
  requireRole(["OWNER", "ADMIN"]),
  testDestination
);
siemRouter.delete(
  "/:id",
  requireRole(["OWNER", "ADMIN"]),
  deleteDestination
);

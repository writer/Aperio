import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { prisma } from "@aperio/db";
import { ingestionPayloadSchema } from "@aperio/shared";
import type { TenantRequest } from "../middleware/security";
import { enqueueIngestionPayload } from "../../../../workers/ingestion-worker";

export const ingestionRouter = Router();

const enqueueEvent: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = ingestionPayloadSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid ingestion payload" });
    }

    const integration = await prisma.integrationConnection.findFirst({
      where: {
        id: parsed.data.integrationId,
        organizationId: tenantReq.tenantId,
        provider: parsed.data.provider,
        status: "CONNECTED"
      },
      select: { id: true }
    });

    if (!integration) {
      return res.status(404).json({ error: "Integration not found" });
    }

    const job = enqueueIngestionPayload({
      organizationId: tenantReq.tenantId,
      ...parsed.data,
      occurredAt: parsed.data.occurredAt
        ? new Date(parsed.data.occurredAt)
        : new Date()
    });

    return res.status(202).json({
      data: {
        jobId: job.id,
        status: job.status
      }
    });
  } catch (error) {
    return next(error);
  }
};

ingestionRouter.post("/events", enqueueEvent);

import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { z } from "zod";
import { prisma } from "@aperio/db";
import { decryptString } from "@aperio/security";
import {
  findConnector,
  type RemediationActionKey
} from "@aperio/shared/connectors";
import { encodeFindingLifecycleEvent } from "@aperio/shared/protobuf-contracts";
import { publishAperioEvent } from "../../../../workers/event-bus";
import { requireRole, type TenantRequest } from "../middleware/security";
import { executeRemediation } from "../remediation/executor";

export const remediationsRouter = Router();

const remediationSchema = z.object({
  action: z.string().min(1).max(120),
  targetIdentifier: z.string().trim().min(1).max(255).optional(),
  note: z.string().trim().max(2000).optional()
});

const remediate: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const findingId = req.params.id;
  if (!findingId) {
    return res.status(400).json({ error: "Finding id is required" });
  }

  const parsed = remediationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid remediation payload", details: parsed.error.flatten() });
  }

  try {
    const finding = await prisma.securityFinding.findFirst({
      where: { id: findingId, organizationId: tenantReq.tenantId },
      include: {
        integration: true
      }
    });

    if (!finding) {
      return res.status(404).json({ error: "Finding not found" });
    }

    const connector = findConnector(finding.integration.provider);
    if (!connector) {
      return res.status(400).json({ error: "Unsupported connector" });
    }

    const action = connector.remediationActions.find(
      (item) => item.key === parsed.data.action
    );
    if (!action) {
      return res.status(400).json({
        error: `Action ${parsed.data.action} is not defined for ${connector.name}`
      });
    }

    if (finding.integration.mode !== "REMEDIATION") {
      return res.status(403).json({
        error:
          "This connection is read-only. Reconnect with remediation scopes to enable write actions."
      });
    }

    const evidence = (finding.evidence ?? {}) as Record<string, unknown>;
    const targetIdentifier =
      parsed.data.targetIdentifier ??
      (typeof evidence.subject === "string"
        ? evidence.subject
        : typeof evidence.actor === "string"
          ? evidence.actor
          : finding.integration.externalAccountId);

    const aad = `${tenantReq.tenantId}:${finding.integration.provider}:${finding.integration.externalAccountId}:access_token`;
    const accessToken = decryptString(
      finding.integration.encryptedAccessToken,
      aad
    );

    const result = await executeRemediation({
      provider: finding.integration.provider,
      action: parsed.data.action as RemediationActionKey,
      integrationId: finding.integration.id,
      externalAccountId: finding.integration.externalAccountId,
      targetIdentifier,
      decryptedAccessToken: accessToken
    });

    await prisma.$transaction(async (tx) => {
      if (result.success) {
        await tx.securityFinding.update({
          where: { id: finding.id },
          data: {
            status: "RESOLVED",
            resolvedAt: new Date(),
            resolvedById: tenantReq.auth.userId
          }
        });
      }
      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: result.success
            ? "finding.remediate.success"
            : "finding.remediate.failure",
          targetType: "security_finding",
          targetId: finding.id,
          ipAddress: req.ip,
          metadata: {
            provider: finding.integration.provider,
            integrationId: finding.integration.id,
            actionKey: parsed.data.action,
            targetIdentifier,
            providerRequestId: result.providerRequestId,
            note: parsed.data.note ?? null,
            effects: result.effects
          }
        }
      });
    });

    if (result.success) {
      await publishAperioEvent(
        await encodeFindingLifecycleEvent({
          findingId: finding.id,
          organizationId: tenantReq.tenantId,
          integrationId: finding.integration.id,
          previousStatus: finding.status,
          nextStatus: "RESOLVED",
          actorUserId: tenantReq.auth.userId,
          statusSource: "user",
          occurredAt: new Date(),
          resolutionNote: parsed.data.note ?? null
        })
      );
    }

    return res.json({
      data: {
        findingId: finding.id,
        action: parsed.data.action,
        success: result.success,
        message: result.message,
        providerRequestId: result.providerRequestId,
        effects: result.effects
      }
    });
  } catch (error) {
    return next(error);
  }
};

remediationsRouter.post(
  "/:id/remediate",
  requireRole(["OWNER", "ADMIN"]),
  remediate
);

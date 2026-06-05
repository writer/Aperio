import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import type { Prisma } from "@prisma/client";
import { prisma } from "@aperio/db";
import {
  findingsQuerySchema,
  resolveFindingSchema
} from "@aperio/shared";
import { encodeFindingLifecycleEvent } from "@aperio/shared/protobuf-contracts";
import { calculateFindingRiskScore } from "@aperio/shared/risk-scoring";
import { publishAperioEvent } from "../../../../workers/event-bus";
import { requireRole, type TenantRequest } from "../middleware/security";

export const findingsRouter = Router();

function serializeFinding(
  finding: Prisma.SecurityFindingGetPayload<{
    include: {
      integration: {
        select: {
          id: true;
          provider: true;
          displayName: true;
        };
      };
    };
  }>
) {
  const evidence =
    finding.evidence && typeof finding.evidence === "object"
      ? (finding.evidence as Record<string, unknown>)
      : null;

  return {
    id: finding.id,
    assetId: finding.assetId,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    status: finding.status,
    riskScore: calculateFindingRiskScore({
      baseRiskScore: finding.riskScore,
      severity: finding.severity,
      evidence,
      detectedAt: finding.detectedAt
    }),
    remediationSteps: finding.remediationSteps,
    evidence: finding.evidence,
    detectedAt: finding.detectedAt.toISOString(),
    resolvedAt: finding.resolvedAt?.toISOString() ?? null,
    integration: finding.integration
  };
}

const listFindings: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
    const tenantReq = req as TenantRequest;

    try {
      const parsed = findingsQuerySchema.safeParse(req.query);

      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid query filters" });
      }

      const where: Prisma.SecurityFindingWhereInput = {
        organizationId: tenantReq.tenantId,
        ...(parsed.data.severity ? { severity: parsed.data.severity } : {}),
        ...(parsed.data.status ? { status: parsed.data.status } : {}),
        ...(parsed.data.integrationId
          ? { integrationId: parsed.data.integrationId }
          : {}),
        ...(parsed.data.provider
          ? { integration: { provider: parsed.data.provider } }
          : {})
      };

      const findings = await prisma.securityFinding.findMany({
        where,
        orderBy: [{ detectedAt: "desc" }, { id: "desc" }],
        take: parsed.data.limit,
        ...(parsed.data.cursor
          ? { cursor: { id: parsed.data.cursor }, skip: 1 }
          : {}),
        include: {
          integration: {
            select: {
              id: true,
              provider: true,
              displayName: true
            }
          }
        }
      });
      const total = await prisma.securityFinding.count({ where });

      return res.json({
        data: findings.map(serializeFinding),
        pageInfo: {
          total,
          nextCursor:
            findings.length === parsed.data.limit
              ? findings[findings.length - 1]?.id ?? null
              : null
        }
      });
    } catch (error) {
      return next(error);
    }
};

const getFinding: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const findingId = req.params.id;

  if (!findingId) {
    return res.status(400).json({ error: "Finding id is required" });
  }

  try {
    const finding = await prisma.securityFinding.findFirst({
      where: {
        id: findingId,
        organizationId: tenantReq.tenantId
      },
      include: {
        integration: {
          select: {
            id: true,
            provider: true,
            displayName: true
          }
        }
      }
    });

    if (!finding) {
      return res.status(404).json({ error: "Finding not found" });
    }

    return res.json({ data: serializeFinding(finding) });
  } catch (error) {
    return next(error);
  }
};

const resolveFindingHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
    const tenantReq = req as TenantRequest;

    try {
      const parsed = resolveFindingSchema.safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid remediation request" });
      }

      const findingId = req.params.id;
      if (!findingId) {
        return res.status(400).json({ error: "Finding id is required" });
      }

      const result = await prisma.$transaction(async (tx) => {
        const existing = await tx.securityFinding.findFirst({
          where: {
            id: findingId,
            organizationId: tenantReq.tenantId
          }
        });

        if (!existing) {
          return null;
        }

        const resolver = await tx.user.findFirst({
          where: {
            id: tenantReq.auth.userId,
            organizationId: tenantReq.tenantId,
            isActive: true
          },
          select: { id: true }
        });

        const updatedFinding = await tx.securityFinding.update({
          where: { id: existing.id },
          data: {
            status: parsed.data.status,
            resolvedAt: new Date(),
            resolvedById: resolver?.id ?? null
          },
          include: {
            integration: {
              select: {
                id: true,
                provider: true,
                displayName: true
              }
            }
          }
        });

        await tx.tenantAuditLog.create({
          data: {
            organizationId: tenantReq.tenantId,
            actorUserId: resolver?.id ?? null,
            action:
              parsed.data.status === "MUTED"
                ? "finding.accept_risk"
                : "finding.resolve",
            targetType: "security_finding",
            targetId: existing.id,
            ipAddress: req.ip,
            metadata: {
              nextStatus: parsed.data.status,
              resolutionNote: parsed.data.resolutionNote ?? null,
              previousStatus: existing.status
            }
          }
        });

        return {
          previousStatus: existing.status,
          resolverId: resolver?.id ?? null,
          updatedFinding
        };
      });

      if (!result) {
        return res.status(404).json({ error: "Finding not found" });
      }

      const updated = result.updatedFinding;
      await publishAperioEvent(
        await encodeFindingLifecycleEvent({
          findingId: updated.id,
          organizationId: tenantReq.tenantId,
          integrationId: updated.integration.id,
          previousStatus: result.previousStatus,
          nextStatus: updated.status,
          actorUserId: result.resolverId,
          statusSource: "user",
          occurredAt: updated.resolvedAt ?? new Date(),
          resolutionNote: parsed.data.resolutionNote ?? null
        })
      );

      return res.json({
        data: {
          id: updated.id,
          assetId: updated.assetId,
          title: updated.title,
          status: updated.status,
          resolvedAt: updated.resolvedAt?.toISOString() ?? null,
          integration: updated.integration
        }
      });
    } catch (error) {
      return next(error);
    }
};

findingsRouter.get("/", listFindings);
findingsRouter.get("/:id", getFinding);

findingsRouter.patch(
  "/:id",
  requireRole(["OWNER", "ADMIN", "SECURITY_ANALYST"]),
  resolveFindingHandler
);

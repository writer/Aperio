import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { prisma } from "@aperio/db";
import {
  aggregateRiskScore,
  calculateFindingRiskScore
} from "@aperio/shared/risk-scoring";
import type { TenantRequest } from "../middleware/security";

export const dashboardRouter = Router();

const getMetrics: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const oneMinuteAgo = new Date(Date.now() - 60_000);
    const [
      openFindings,
      openCriticalFindings,
      connectedApps,
      eventsLastMinute
    ] = await Promise.all([
      prisma.securityFinding.findMany({
        where: {
          organizationId: tenantReq.tenantId,
          status: "OPEN"
        },
        select: {
          riskScore: true,
          severity: true,
          detectedAt: true,
          evidence: true,
          integration: {
            select: {
              provider: true
            }
          }
        }
      }),
      prisma.securityFinding.count({
        where: {
          organizationId: tenantReq.tenantId,
          status: "OPEN",
          severity: "CRITICAL"
        }
      }),
      prisma.integrationConnection.count({
        where: {
          organizationId: tenantReq.tenantId,
          status: "CONNECTED"
        }
      }),
      prisma.ingestedEvent.count({
        where: {
          organizationId: tenantReq.tenantId,
          createdAt: { gte: oneMinuteAgo }
        }
      })
    ]);

    return res.json({
      data: {
        totalRiskScore: aggregateRiskScore(
          openFindings.map((finding) => ({
            riskScore: calculateFindingRiskScore({
              baseRiskScore: finding.riskScore,
              severity: finding.severity,
              evidence:
                finding.evidence && typeof finding.evidence === "object"
                  ? (finding.evidence as Record<string, unknown>)
                  : null,
              detectedAt: finding.detectedAt
            }),
            severity: finding.severity,
            detectedAt: finding.detectedAt,
            integration: finding.integration
          }))
        ),
        openCriticalFindings,
        connectedApps,
        eventIngestionRate: eventsLastMinute
      }
    });
  } catch (error) {
    return next(error);
  }
};

dashboardRouter.get("/metrics", getMetrics);

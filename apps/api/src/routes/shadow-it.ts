import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { prisma } from "@aperio/db";
import type { TenantRequest } from "../middleware/security";

export const shadowItRouter = Router();

const listOauthApps: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const assets = await prisma.securityAsset.findMany({
      where: {
        organizationId: tenantReq.tenantId,
        type: "OAUTH_APP",
        labels: { has: "shadow-it" }
      },
      orderBy: [{ riskScore: "desc" }, { name: "asc" }],
      select: {
        id: true,
        provider: true,
        name: true,
        summary: true,
        externalId: true,
        labels: true,
        criticality: true,
        containsSensitiveData: true,
        riskScore: true,
        lastObservedAt: true,
        integration: {
          select: {
            id: true,
            provider: true,
            displayName: true
          }
        }
      }
    });

    const assetIds = assets.map((asset) => asset.id);
    const grants = assetIds.length
      ? await prisma.oauthAppGrant.groupBy({
          by: ["assetId"],
          where: {
            organizationId: tenantReq.tenantId,
            assetId: { in: assetIds }
          },
          _count: { _all: true },
          _max: { lastObservedAt: true }
        })
      : [];
    const grantsByAsset = new Map(
      grants.map((entry) => [
        entry.assetId,
        {
          userCount: entry._count._all,
          lastObservedAt: entry._max.lastObservedAt
        }
      ])
    );

    const scopesByAsset = assetIds.length
      ? await prisma.oauthAppGrant.findMany({
          where: {
            organizationId: tenantReq.tenantId,
            assetId: { in: assetIds }
          },
          select: { assetId: true, scopes: true }
        })
      : [];
    const aggregatedScopes = new Map<string, Set<string>>();
    for (const row of scopesByAsset) {
      if (!row.assetId) continue;
      let bucket = aggregatedScopes.get(row.assetId);
      if (!bucket) {
        bucket = new Set<string>();
        aggregatedScopes.set(row.assetId, bucket);
      }
      for (const scope of row.scopes) {
        bucket.add(scope);
      }
    }

    return res.json({
      data: assets.map((asset) => {
        const grantInfo = asset.id ? grantsByAsset.get(asset.id) : undefined;
        const scopes = Array.from(aggregatedScopes.get(asset.id) ?? []);
        return {
          id: asset.id,
          provider: asset.provider,
          name: asset.name,
          summary: asset.summary,
          externalId: asset.externalId,
          labels: asset.labels,
          criticality: asset.criticality,
          containsSensitiveData: asset.containsSensitiveData,
          riskScore: asset.riskScore,
          lastObservedAt:
            grantInfo?.lastObservedAt?.toISOString() ??
            asset.lastObservedAt?.toISOString() ??
            null,
          userCount: grantInfo?.userCount ?? 0,
          scopes,
          integration: asset.integration
            ? {
                id: asset.integration.id,
                provider: asset.integration.provider,
                displayName: asset.integration.displayName
              }
            : null
        };
      })
    });
  } catch (error) {
    return next(error);
  }
};

const listOauthAppGrants: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const { assetId } = tenantReq.params as { assetId?: string };
  if (!assetId) {
    return res.status(400).json({ error: "Missing assetId" });
  }

  try {
    const asset = await prisma.securityAsset.findFirst({
      where: {
        id: assetId,
        organizationId: tenantReq.tenantId,
        type: "OAUTH_APP"
      },
      select: {
        id: true,
        name: true,
        externalId: true,
        provider: true
      }
    });

    if (!asset) {
      return res.status(404).json({ error: "OAuth app not found" });
    }

    const grants = await prisma.oauthAppGrant.findMany({
      where: {
        organizationId: tenantReq.tenantId,
        assetId
      },
      orderBy: [{ userEmail: "asc" }],
      select: {
        id: true,
        userEmail: true,
        userExternalId: true,
        userDisplayName: true,
        scopes: true,
        anonymous: true,
        nativeApp: true,
        lastObservedAt: true
      }
    });

    return res.json({
      data: {
        app: asset,
        grants: grants.map((grant) => ({
          id: grant.id,
          userEmail: grant.userEmail,
          userExternalId: grant.userExternalId,
          userDisplayName: grant.userDisplayName,
          scopes: grant.scopes,
          anonymous: grant.anonymous,
          nativeApp: grant.nativeApp,
          lastObservedAt: grant.lastObservedAt.toISOString()
        }))
      }
    });
  } catch (error) {
    return next(error);
  }
};

shadowItRouter.get("/oauth-apps", listOauthApps);
shadowItRouter.get("/oauth-apps/:assetId/grants", listOauthAppGrants);

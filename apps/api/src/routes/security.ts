import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "@aperio/db";
import {
  createRiskExceptionSchema,
  createSecurityAssetSchema,
  securityAssetsQuerySchema,
  updateRiskExceptionSchema,
  updateSecurityAssetSchema
} from "@aperio/shared/security";
import { requireRole, type TenantRequest } from "../middleware/security";

export const securityRouter = Router();

const assetInclude = Prisma.validator<Prisma.SecurityAssetInclude>()({
  integration: {
    select: {
      id: true,
      provider: true,
      displayName: true
    }
  },
  owner: {
    select: {
      id: true,
      email: true,
      displayName: true
    }
  },
  businessOwner: {
    select: {
      id: true,
      email: true,
      displayName: true
    }
  },
  findings: {
    where: { status: "OPEN" },
    select: { id: true }
  },
  riskExceptions: {
    select: {
      id: true,
      status: true,
      expiresAt: true
    }
  }
});

const exceptionInclude = Prisma.validator<Prisma.RiskExceptionInclude>()({
  asset: {
    select: {
      id: true,
      name: true,
      type: true
    }
  },
  finding: {
    select: {
      id: true,
      title: true,
      severity: true,
      status: true
    }
  },
  createdBy: {
    select: {
      id: true,
      email: true,
      displayName: true
    }
  },
  approvedBy: {
    select: {
      id: true,
      email: true,
      displayName: true
    }
  }
});

const identityInclude = Prisma.validator<Prisma.SaasIdentityInclude>()({
  integration: {
    select: {
      id: true,
      provider: true,
      displayName: true
    }
  }
});

type AssetRecord = Prisma.SecurityAssetGetPayload<{ include: typeof assetInclude }>;
type ExceptionRecord = Prisma.RiskExceptionGetPayload<{
  include: typeof exceptionInclude;
}>;
type IdentityRecord = Prisma.SaasIdentityGetPayload<{
  include: typeof identityInclude;
}>;

function hasOwnProperty<T extends object>(
  value: T,
  key: keyof T
): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function deriveOwnershipStatus(input: {
  ownershipStatus?: "ASSIGNED" | "UNASSIGNED" | "REVIEW_REQUIRED" | null;
  ownerUserId?: string | null;
  businessOwnerUserId?: string | null;
}) {
  if (input.ownershipStatus === "REVIEW_REQUIRED") {
    return "REVIEW_REQUIRED" as const;
  }
  return input.ownerUserId || input.businessOwnerUserId
    ? ("ASSIGNED" as const)
    : ("UNASSIGNED" as const);
}

function effectiveExceptionStatus(exception: {
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  expiresAt: Date | null;
}) {
  if (
    exception.status === "ACTIVE" &&
    exception.expiresAt &&
    exception.expiresAt.getTime() <= Date.now()
  ) {
    return "EXPIRED" as const;
  }
  return exception.status;
}

function serializeAsset(asset: AssetRecord) {
  const activeExceptionCount = asset.riskExceptions.filter(
    (exception) => effectiveExceptionStatus(exception) === "ACTIVE"
  ).length;

  return {
    id: asset.id,
    type: asset.type,
    provider: asset.provider,
    name: asset.name,
    summary: asset.summary,
    externalId: asset.externalId,
    labels: asset.labels,
    criticality: asset.criticality,
    exposureLevel: asset.exposureLevel,
    ownershipStatus: asset.ownershipStatus,
    containsSensitiveData: asset.containsSensitiveData,
    isPrivileged: asset.isPrivileged,
    riskScore: asset.riskScore,
    lastObservedAt: asset.lastObservedAt?.toISOString() ?? null,
    createdAt: asset.createdAt.toISOString(),
    updatedAt: asset.updatedAt.toISOString(),
    integration: asset.integration
      ? {
          id: asset.integration.id,
          provider: asset.integration.provider,
          displayName: asset.integration.displayName
        }
      : null,
    owner: asset.owner
      ? {
          id: asset.owner.id,
          email: asset.owner.email,
          displayName: asset.owner.displayName
        }
      : null,
    businessOwner: asset.businessOwner
      ? {
          id: asset.businessOwner.id,
          email: asset.businessOwner.email,
          displayName: asset.businessOwner.displayName
        }
      : null,
    openFindingCount: asset.findings.length,
    activeExceptionCount
  };
}

function serializeException(exception: ExceptionRecord) {
  const status = effectiveExceptionStatus(exception);

  return {
    id: exception.id,
    title: exception.title,
    rationale: exception.rationale,
    compensatingControls: exception.compensatingControls,
    status,
    expiresAt: exception.expiresAt?.toISOString() ?? null,
    approvedAt: exception.approvedAt?.toISOString() ?? null,
    createdAt: exception.createdAt.toISOString(),
    updatedAt: exception.updatedAt.toISOString(),
    asset: exception.asset,
    finding: exception.finding,
    createdBy: exception.createdBy
      ? {
          id: exception.createdBy.id,
          email: exception.createdBy.email,
          displayName: exception.createdBy.displayName
        }
      : null,
    approvedBy: exception.approvedBy
      ? {
          id: exception.approvedBy.id,
          email: exception.approvedBy.email,
          displayName: exception.approvedBy.displayName
        }
      : null
  };
}

function serializeIdentity(
  identity: IdentityRecord,
  assetsById: Map<string, AssetRecord>,
  applicationByIntegrationId: Map<string, AssetRecord>
) {
  const linkedAssets = identity.linkedAssetIds
    .map((assetId) => assetsById.get(assetId))
    .filter((asset): asset is AssetRecord => !!asset);
  const applicationAsset = identity.integrationId
    ? applicationByIntegrationId.get(identity.integrationId) ?? null
    : null;
  const allLinkedAssets = applicationAsset
    ? [
        applicationAsset,
        ...linkedAssets.filter((asset) => asset.id !== applicationAsset.id)
      ]
    : linkedAssets;
  const dormant =
    identity.status === "DORMANT" ||
    (!!identity.lastObservedAt &&
      Date.now() - identity.lastObservedAt.getTime() > 30 * 24 * 60 * 60 * 1000);
  const baseRisk =
    identity.riskScore > 0
      ? identity.riskScore
      : Math.min(
          100,
          (identity.isPrivileged ? 55 : 20) +
            (identity.mfaEnabled === false ? 20 : 0) +
            (identity.isExternal ? 10 : 0) +
            (dormant ? 10 : 0) +
            Math.min(10, allLinkedAssets.length * 3)
        );

  return {
    id: `identity:${identity.id}`,
    entityId: identity.id,
    kind: identity.kind,
    name: identity.displayName ?? identity.email ?? identity.externalId,
    email: identity.email,
    provider: identity.provider,
    integration: identity.integration
      ? {
          id: identity.integration.id,
          provider: identity.integration.provider,
          displayName: identity.integration.displayName
        }
      : null,
    role: identity.role ?? "Unknown",
    privileged: identity.isPrivileged,
    mfaEnabled: identity.mfaEnabled,
    status: dormant ? "DORMANT" : identity.status,
    isExternal: identity.isExternal,
    lastObservedAt: identity.lastObservedAt?.toISOString() ?? null,
    linkedAssetCount: allLinkedAssets.length,
    riskScore: baseRisk
  };
}

async function assertTenantUser(
  tx: Prisma.TransactionClient,
  organizationId: string,
  userId: string | null | undefined
) {
  if (!userId) {
    return null;
  }

  return tx.user.findFirst({
    where: { id: userId, organizationId },
    select: { id: true }
  });
}

async function assertTenantIntegration(
  tx: Prisma.TransactionClient,
  organizationId: string,
  integrationId: string | null | undefined
) {
  if (!integrationId) {
    return null;
  }

  return tx.integrationConnection.findFirst({
    where: { id: integrationId, organizationId },
    select: { id: true, provider: true, displayName: true }
  });
}

const getOverview: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const [
      saasIdentities,
      assets,
      exceptions,
      openFindings,
      googleWorkspaceIntegrations
    ] = await Promise.all([
      prisma.saasIdentity.findMany({
        where: { organizationId: tenantReq.tenantId },
        include: identityInclude,
        orderBy: [{ riskScore: "desc" }, { lastObservedAt: "desc" }]
      }),
      prisma.securityAsset.findMany({
        where: { organizationId: tenantReq.tenantId },
        include: assetInclude,
        orderBy: [{ riskScore: "desc" }, { name: "asc" }]
      }),
      prisma.riskException.findMany({
        where: { organizationId: tenantReq.tenantId },
        include: exceptionInclude,
        orderBy: [{ createdAt: "desc" }]
      }),
      prisma.securityFinding.findMany({
        where: {
          organizationId: tenantReq.tenantId,
          status: "OPEN"
        },
        include: {
          integration: {
            select: {
              id: true,
              provider: true,
              displayName: true
            }
          },
          asset: {
            select: {
              id: true,
              name: true,
              type: true,
              integrationId: true,
              ownerUserId: true,
              businessOwnerUserId: true,
              riskScore: true,
              exposureLevel: true,
              containsSensitiveData: true,
              isPrivileged: true
            }
          }
        },
        orderBy: [{ riskScore: "desc" }, { detectedAt: "desc" }]
      }),
      prisma.integrationConnection.findMany({
        where: {
          organizationId: tenantReq.tenantId,
          provider: "GOOGLE_WORKSPACE"
        },
        select: {
          id: true,
          provider: true,
          displayName: true,
          externalAccountId: true,
          status: true,
          mode: true,
          lastSyncAt: true,
          createdAt: true,
          googleMailboxScanClientEmail: true,
          encryptedGoogleMailboxScanPrivateKey: true
        }
      })
    ]);

    const assetMap = new Map(assets.map((asset) => [asset.id, asset]));
    const applicationByIntegrationId = new Map(
      assets
        .filter((asset) => asset.type === "APPLICATION" && asset.integration?.id)
        .map((asset) => [asset.integration!.id, asset])
    );

    const identities = saasIdentities
      .map((identity) =>
        serializeIdentity(identity, assetMap, applicationByIntegrationId)
      )
      .sort((left, right) => right.riskScore - left.riskScore);

    const graphNodes = [
      ...identities.map((identity) => ({
        id: identity.id,
        label: identity.name,
        kind: identity.kind,
        riskScore: identity.riskScore,
        privileged: identity.privileged,
        exposureLevel: identity.isExternal ? "TRUSTED_EXTERNAL" : "INTERNAL",
        criticality: identity.privileged ? "HIGH" : "MEDIUM"
      })),
      ...assets.map((asset) => ({
        id: `asset:${asset.id}`,
        label: asset.name,
        kind: asset.type,
        riskScore: asset.riskScore,
        privileged: asset.isPrivileged,
        exposureLevel: asset.exposureLevel,
        criticality: asset.criticality
      }))
    ];

    const graphEdges = [
      ...identities.flatMap((identity) => {
        const identityAssetIds = new Set(
          saasIdentities
            .find((record) => `identity:${record.id}` === identity.id)
            ?.linkedAssetIds ?? []
        );
        const applicationAsset = identity.integration?.id
          ? applicationByIntegrationId.get(identity.integration.id)
          : null;
        if (applicationAsset) {
          identityAssetIds.add(applicationAsset.id);
        }

        return Array.from(identityAssetIds)
          .map((assetId) => assetMap.get(assetId))
          .filter((asset): asset is AssetRecord => !!asset)
          .map((asset) => ({
            id: `identity-access:${identity.entityId}:${asset.id}`,
            sourceId: identity.id,
            targetId: `asset:${asset.id}`,
            relationshipType: identity.privileged ? "privileged_access" : "access"
          }));
      }),
      ...assets.flatMap((asset) => {
      const edges: Array<{
        id: string;
        sourceId: string;
        targetId: string;
        relationshipType: string;
      }> = [];

      const applicationAsset =
        asset.integration?.id
          ? applicationByIntegrationId.get(asset.integration.id)
          : null;

      if (
        applicationAsset &&
        applicationAsset.id !== asset.id &&
        (asset.type === "OAUTH_APP" || asset.type === "SERVICE_ACCOUNT")
      ) {
        edges.push({
          id: `entry:${asset.id}:${applicationAsset.id}`,
          sourceId: `asset:${asset.id}`,
          targetId: `asset:${applicationAsset.id}`,
          relationshipType:
            asset.type === "OAUTH_APP" ? "admin_scopes" : "automation_access"
        });
      }

      if (
        applicationAsset &&
        applicationAsset.id !== asset.id &&
        ["DATA_RESOURCE", "WORKSPACE", "VAULT", "REPOSITORY"].includes(asset.type)
      ) {
        edges.push({
          id: `contains:${applicationAsset.id}:${asset.id}`,
          sourceId: `asset:${applicationAsset.id}`,
          targetId: `asset:${asset.id}`,
          relationshipType: "contains_data"
        });
      }

        return edges;
      })
    ];

    const oauthApps = assets
      .filter((asset) => asset.type === "OAUTH_APP")
      .map(serializeAsset)
      .sort((left, right) => right.riskScore - left.riskScore);

    const dataAssets = assets
      .filter(
        (asset) =>
          asset.containsSensitiveData ||
          ["DATA_RESOURCE", "WORKSPACE", "VAULT", "REPOSITORY"].includes(
            asset.type
          ) ||
          asset.exposureLevel !== "INTERNAL"
      )
      .map(serializeAsset)
      .sort((left, right) => right.riskScore - left.riskScore);

    const activeExceptions = exceptions
      .filter((exception) => effectiveExceptionStatus(exception) === "ACTIVE")
      .map(serializeException);

    const ownershipGaps = assets
      .filter(
        (asset) =>
          asset.ownershipStatus !== "ASSIGNED" ||
          (!asset.owner && !asset.businessOwner)
      )
      .map(serializeAsset)
      .sort((left, right) => right.riskScore - left.riskScore);

    const googleMailboxStateRuleIds = new Set([
      "google_workspace.email_forwarding_enabled",
      "google_workspace.mailbox_delegation_granted",
      "google_workspace.forwarding_delegate_send_as_combo"
    ]);
    const googleDwdScopes = [
      "https://www.googleapis.com/auth/gmail.settings.basic",
      "https://www.googleapis.com/auth/gmail.settings.sharing"
    ];

    const openMailboxFindingsByIntegration = new Map<string, number>();
    for (const finding of openFindings) {
      const evidence =
        finding.evidence && typeof finding.evidence === "object"
          ? (finding.evidence as Record<string, unknown>)
          : {};
      const ruleId =
        typeof evidence.ruleId === "string" ? evidence.ruleId : null;
      if (ruleId && googleMailboxStateRuleIds.has(ruleId)) {
        const previous =
          openMailboxFindingsByIntegration.get(finding.integration.id) ?? 0;
        openMailboxFindingsByIntegration.set(
          finding.integration.id,
          previous + 1
        );
      }
    }

    const domainWideDelegations = googleWorkspaceIntegrations
      .map((integration) => {
        const enabled = Boolean(
          integration.googleMailboxScanClientEmail &&
            integration.encryptedGoogleMailboxScanPrivateKey
        );
        const openMailboxFindings =
          openMailboxFindingsByIntegration.get(integration.id) ?? 0;

        return {
          integrationId: integration.id,
          provider: integration.provider,
          displayName: integration.displayName,
          workspaceDomain: integration.externalAccountId,
          serviceAccountClientEmail:
            integration.googleMailboxScanClientEmail ?? null,
          scopes: enabled ? googleDwdScopes : [],
          status: enabled
            ? ("ENABLED" as const)
            : ("NOT_CONFIGURED" as const),
          integrationStatus: integration.status,
          mode: integration.mode,
          openMailboxFindings,
          lastSyncAt: integration.lastSyncAt?.toISOString() ?? null,
          configuredAt: integration.createdAt.toISOString()
        };
      })
      .filter(
        (entry) => entry.status === "ENABLED" || entry.openMailboxFindings > 0
      )
      .sort(
        (left, right) =>
          right.openMailboxFindings - left.openMailboxFindings ||
          left.workspaceDomain.localeCompare(right.workspaceDomain)
      );

    const attackPaths = openFindings
      .flatMap((finding) => {
        const findingAsset = finding.assetId
          ? assetMap.get(finding.assetId) ?? null
          : null;
        const applicationAsset = applicationByIntegrationId.get(
          finding.integration.id
        );
        const candidateTargets = findingAsset
          ? [findingAsset]
          : assets.filter(
              (asset) =>
                asset.integration?.id === finding.integration.id &&
                asset.type !== "APPLICATION"
            );
        const targets =
          candidateTargets.length > 0
            ? candidateTargets
            : applicationAsset
              ? [applicationAsset]
              : [];

        return targets.map((target) => {
          const entryAsset =
            assets
              .filter(
                (asset) =>
                  asset.integration?.id === target.integration?.id &&
                  ["OAUTH_APP", "SERVICE_ACCOUNT"].includes(asset.type)
              )
              .sort((left, right) => right.riskScore - left.riskScore)[0] ?? null;
          const entryIdentity =
            identities
              .filter(
                (identity) =>
                  identity.integration?.id === target.integration?.id &&
                  (identity.privileged ||
                    !!saasIdentities
                      .find((record) => record.id === identity.entityId)
                      ?.linkedAssetIds.find(
                        (assetId) =>
                          assetId === target.id ||
                          assetId === entryAsset?.id ||
                          assetId === applicationAsset?.id
                      ))
              )
              .sort((left, right) => right.riskScore - left.riskScore)[0] ?? null;
          const owner =
            target.owner ??
            target.businessOwner ??
            entryAsset?.owner ??
            entryAsset?.businessOwner ??
            null;
          const exceptionPenalty = exceptions.some(
            (exception) =>
              effectiveExceptionStatus(exception) === "ACTIVE" &&
              (exception.findingId === finding.id || exception.assetId === target.id)
          )
            ? -5
            : 0;

          const score = Math.min(
            100,
            finding.riskScore +
              Math.round(target.riskScore * 0.5) +
              (entryAsset?.isPrivileged ? 10 : 0) +
              (entryIdentity?.privileged ? 10 : 0) +
              (target.containsSensitiveData ? 10 : 0) +
              (target.exposureLevel === "PUBLIC"
                ? 15
                : target.exposureLevel === "TRUSTED_EXTERNAL"
                  ? 8
                  : 0) +
              (target.isPrivileged ? 10 : 0) +
              (!target.owner && !target.businessOwner ? 10 : 0) +
              exceptionPenalty
          );

          const path = [
            entryIdentity?.name,
            entryAsset?.name,
            applicationAsset?.name,
            target.name
          ].filter((value, index, values): value is string =>
            !!value && values.indexOf(value) === index
          );

          return {
            id: `${finding.id}:${target.id}`,
            title: path.join(" → "),
            score,
            findingTitle: finding.title,
            entryPoint:
              entryIdentity?.name ??
              entryAsset?.name ??
              applicationAsset?.name ??
              "Unknown entry point",
            target: target.name,
            owner: owner?.email ?? "Unassigned",
            exposureLevel: target.exposureLevel,
            criticality: target.criticality,
            reason: `${finding.title} can propagate through ${entryIdentity?.name ?? finding.integration.displayName} into ${target.name}.`,
            path
          };
        });
      })
      .sort((left, right) => right.score - left.score)
      .slice(0, 8);

    return res.json({
      data: {
        summary: {
          privilegedIdentities: identities.filter((identity) => identity.privileged)
            .length,
          adminIdentitiesWithoutMfa: identities.filter(
            (identity) => identity.privileged && identity.mfaEnabled === false
          ).length,
          riskyOauthApps: oauthApps.filter((asset) => asset.riskScore >= 70).length,
          exposedDataAssets: dataAssets.filter(
            (asset) => asset.exposureLevel !== "INTERNAL"
          ).length,
          unownedAssets: ownershipGaps.length,
          activeExceptions: activeExceptions.length,
          topBlastRadiusScore: attackPaths[0]?.score ?? 0
        },
        identities,
        graph: {
          nodes: graphNodes,
          edges: graphEdges
        },
        oauthApps,
        dataAssets,
        attackPaths,
        ownershipGaps,
        exceptions: activeExceptions,
        domainWideDelegations
      }
    });
  } catch (error) {
    return next(error);
  }
};

const listAssets: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = securityAssetsQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid asset filters" });
    }

    const assets = await prisma.securityAsset.findMany({
      where: {
        organizationId: tenantReq.tenantId,
        ...(parsed.data.type ? { type: parsed.data.type } : {}),
        ...(parsed.data.ownershipStatus
          ? { ownershipStatus: parsed.data.ownershipStatus }
          : {}),
        ...(parsed.data.integrationId
          ? { integrationId: parsed.data.integrationId }
          : {})
      },
      include: assetInclude,
      orderBy: [{ riskScore: "desc" }, { name: "asc" }]
    });

    return res.json({
      data: assets.map(serializeAsset)
    });
  } catch (error) {
    return next(error);
  }
};

const createAsset: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = createSecurityAssetSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid asset payload",
        details: parsed.error.flatten()
      });
    }

    const created = await prisma.$transaction(async (tx) => {
      const [owner, businessOwner, integration] = await Promise.all([
        assertTenantUser(tx, tenantReq.tenantId, parsed.data.ownerUserId),
        assertTenantUser(tx, tenantReq.tenantId, parsed.data.businessOwnerUserId),
        assertTenantIntegration(tx, tenantReq.tenantId, parsed.data.integrationId)
      ]);

      if (parsed.data.ownerUserId && !owner) {
        throw new Error("Owner does not belong to this tenant");
      }
      if (parsed.data.businessOwnerUserId && !businessOwner) {
        throw new Error("Business owner does not belong to this tenant");
      }
      if (parsed.data.integrationId && !integration) {
        throw new Error("Integration not found");
      }

      const asset = await tx.securityAsset.create({
        data: {
          organizationId: tenantReq.tenantId,
          integrationId: integration?.id ?? null,
          ownerUserId: owner?.id ?? null,
          businessOwnerUserId: businessOwner?.id ?? null,
          type: parsed.data.type,
          provider: integration?.provider ?? parsed.data.provider ?? null,
          name: parsed.data.name,
          summary: parsed.data.summary ?? null,
          externalId: parsed.data.externalId ?? null,
          labels: parsed.data.labels,
          criticality: parsed.data.criticality,
          exposureLevel: parsed.data.exposureLevel,
          ownershipStatus: deriveOwnershipStatus({
            ownershipStatus: parsed.data.ownershipStatus,
            ownerUserId: owner?.id ?? null,
            businessOwnerUserId: businessOwner?.id ?? null
          }),
          containsSensitiveData: parsed.data.containsSensitiveData,
          isPrivileged: parsed.data.isPrivileged,
          riskScore: parsed.data.riskScore,
          lastObservedAt: parsed.data.lastObservedAt
            ? new Date(parsed.data.lastObservedAt)
            : null
        },
        include: assetInclude
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "security.asset.create",
          targetType: "security_asset",
          targetId: asset.id,
          ipAddress: req.ip,
          metadata: {
            type: asset.type,
            name: asset.name,
            integrationId: asset.integration?.id ?? null
          }
        }
      });

      return asset;
    });

    return res.status(201).json({ data: serializeAsset(created) });
  } catch (error) {
    return next(error);
  }
};

const updateAsset: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const assetId = req.params.id;

  if (!assetId) {
    return res.status(400).json({ error: "Asset id is required" });
  }

  try {
    const parsed = updateSecurityAssetSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid asset payload",
        details: parsed.error.flatten()
      });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const existing = await tx.securityAsset.findFirst({
        where: { id: assetId, organizationId: tenantReq.tenantId },
        select: {
          id: true,
          ownerUserId: true,
          businessOwnerUserId: true,
          integrationId: true
        }
      });

      if (!existing) {
        return null;
      }

      const nextOwnerId = hasOwnProperty(parsed.data, "ownerUserId")
        ? parsed.data.ownerUserId ?? null
        : existing.ownerUserId;
      const nextBusinessOwnerId = hasOwnProperty(parsed.data, "businessOwnerUserId")
        ? parsed.data.businessOwnerUserId ?? null
        : existing.businessOwnerUserId;
      const nextIntegrationId = hasOwnProperty(parsed.data, "integrationId")
        ? parsed.data.integrationId ?? null
        : existing.integrationId;

      const [owner, businessOwner, integration] = await Promise.all([
        assertTenantUser(tx, tenantReq.tenantId, nextOwnerId),
        assertTenantUser(tx, tenantReq.tenantId, nextBusinessOwnerId),
        assertTenantIntegration(tx, tenantReq.tenantId, nextIntegrationId)
      ]);

      if (nextOwnerId && !owner) {
        throw new Error("Owner does not belong to this tenant");
      }
      if (nextBusinessOwnerId && !businessOwner) {
        throw new Error("Business owner does not belong to this tenant");
      }
      if (nextIntegrationId && !integration) {
        throw new Error("Integration not found");
      }

      const data: Prisma.SecurityAssetUncheckedUpdateInput = {};

      if (hasOwnProperty(parsed.data, "type")) {
        data.type = parsed.data.type;
      }
      if (hasOwnProperty(parsed.data, "name")) {
        data.name = parsed.data.name;
      }
      if (hasOwnProperty(parsed.data, "summary")) {
        data.summary = parsed.data.summary ?? null;
      }
      if (hasOwnProperty(parsed.data, "externalId")) {
        data.externalId = parsed.data.externalId ?? null;
      }
      if (hasOwnProperty(parsed.data, "labels")) {
        data.labels = parsed.data.labels ?? [];
      }
      if (hasOwnProperty(parsed.data, "criticality")) {
        data.criticality = parsed.data.criticality;
      }
      if (hasOwnProperty(parsed.data, "exposureLevel")) {
        data.exposureLevel = parsed.data.exposureLevel;
      }
      if (hasOwnProperty(parsed.data, "containsSensitiveData")) {
        data.containsSensitiveData = parsed.data.containsSensitiveData;
      }
      if (hasOwnProperty(parsed.data, "isPrivileged")) {
        data.isPrivileged = parsed.data.isPrivileged;
      }
      if (hasOwnProperty(parsed.data, "riskScore")) {
        data.riskScore = parsed.data.riskScore;
      }
      if (hasOwnProperty(parsed.data, "lastObservedAt")) {
        data.lastObservedAt = parsed.data.lastObservedAt
          ? new Date(parsed.data.lastObservedAt)
          : null;
      }
      if (
        hasOwnProperty(parsed.data, "integrationId") ||
        hasOwnProperty(parsed.data, "provider")
      ) {
        data.integrationId = integration?.id ?? null;
        data.provider =
          integration?.provider ??
          (hasOwnProperty(parsed.data, "provider")
            ? parsed.data.provider ?? null
            : undefined);
      }
      if (hasOwnProperty(parsed.data, "ownerUserId")) {
        data.ownerUserId = owner?.id ?? null;
      }
      if (hasOwnProperty(parsed.data, "businessOwnerUserId")) {
        data.businessOwnerUserId = businessOwner?.id ?? null;
      }

      data.ownershipStatus = deriveOwnershipStatus({
        ownershipStatus: hasOwnProperty(parsed.data, "ownershipStatus")
          ? parsed.data.ownershipStatus ?? null
          : undefined,
        ownerUserId: nextOwnerId,
        businessOwnerUserId: nextBusinessOwnerId
      });

      const asset = await tx.securityAsset.update({
        where: { id: existing.id },
        data,
        include: assetInclude
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "security.asset.update",
          targetType: "security_asset",
          targetId: asset.id,
          ipAddress: req.ip,
          metadata: {
            changed: Object.keys(parsed.data)
          }
        }
      });

      return asset;
    });

    if (!updated) {
      return res.status(404).json({ error: "Asset not found" });
    }

    return res.json({ data: serializeAsset(updated) });
  } catch (error) {
    return next(error);
  }
};

const listExceptions: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const exceptions = await prisma.riskException.findMany({
      where: { organizationId: tenantReq.tenantId },
      include: exceptionInclude,
      orderBy: [{ createdAt: "desc" }]
    });

    return res.json({
      data: exceptions.map(serializeException)
    });
  } catch (error) {
    return next(error);
  }
};

const createException: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = createRiskExceptionSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid exception payload",
        details: parsed.error.flatten()
      });
    }

    const created = await prisma.$transaction(async (tx) => {
      const [asset, finding] = await Promise.all([
        parsed.data.assetId
          ? tx.securityAsset.findFirst({
              where: {
                id: parsed.data.assetId,
                organizationId: tenantReq.tenantId
              },
              select: { id: true }
            })
          : null,
        parsed.data.findingId
          ? tx.securityFinding.findFirst({
              where: {
                id: parsed.data.findingId,
                organizationId: tenantReq.tenantId
              },
              select: { id: true }
            })
          : null
      ]);

      if (parsed.data.assetId && !asset) {
        throw new Error("Asset not found");
      }
      if (parsed.data.findingId && !finding) {
        throw new Error("Finding not found");
      }

      const autoApprove =
        tenantReq.auth.role === "OWNER" || tenantReq.auth.role === "ADMIN";

      const exception = await tx.riskException.create({
        data: {
          organizationId: tenantReq.tenantId,
          assetId: asset?.id ?? null,
          findingId: finding?.id ?? null,
          title: parsed.data.title,
          rationale: parsed.data.rationale,
          compensatingControls: parsed.data.compensatingControls,
          status: "ACTIVE",
          expiresAt: parsed.data.expiresAt
            ? new Date(parsed.data.expiresAt)
            : null,
          createdByUserId: tenantReq.auth.userId,
          approvedByUserId: autoApprove ? tenantReq.auth.userId : null,
          approvedAt: autoApprove ? new Date() : null
        },
        include: exceptionInclude
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "security.exception.create",
          targetType: "risk_exception",
          targetId: exception.id,
          ipAddress: req.ip,
          metadata: {
            assetId: exception.asset?.id ?? null,
            findingId: exception.finding?.id ?? null,
            expiresAt: exception.expiresAt?.toISOString() ?? null
          }
        }
      });

      return exception;
    });

    return res.status(201).json({ data: serializeException(created) });
  } catch (error) {
    return next(error);
  }
};

const updateException: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const exceptionId = req.params.id;

  if (!exceptionId) {
    return res.status(400).json({ error: "Exception id is required" });
  }

  try {
    const parsed = updateRiskExceptionSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid exception payload",
        details: parsed.error.flatten()
      });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const existing = await tx.riskException.findFirst({
        where: { id: exceptionId, organizationId: tenantReq.tenantId },
        select: { id: true }
      });

      if (!existing) {
        return null;
      }

      const data: Prisma.RiskExceptionUncheckedUpdateInput = {};

      if (hasOwnProperty(parsed.data, "title")) {
        data.title = parsed.data.title;
      }
      if (hasOwnProperty(parsed.data, "rationale")) {
        data.rationale = parsed.data.rationale;
      }
      if (hasOwnProperty(parsed.data, "compensatingControls")) {
        data.compensatingControls = parsed.data.compensatingControls ?? [];
      }
      if (hasOwnProperty(parsed.data, "expiresAt")) {
        data.expiresAt = parsed.data.expiresAt
          ? new Date(parsed.data.expiresAt)
          : null;
      }
      if (hasOwnProperty(parsed.data, "status")) {
        data.status = parsed.data.status;
        if (
          parsed.data.status === "ACTIVE" &&
          (tenantReq.auth.role === "OWNER" || tenantReq.auth.role === "ADMIN")
        ) {
          data.approvedByUserId = tenantReq.auth.userId;
          data.approvedAt = new Date();
        }
      }

      const exception = await tx.riskException.update({
        where: { id: existing.id },
        data,
        include: exceptionInclude
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "security.exception.update",
          targetType: "risk_exception",
          targetId: exception.id,
          ipAddress: req.ip,
          metadata: {
            changed: Object.keys(parsed.data)
          }
        }
      });

      return exception;
    });

    if (!updated) {
      return res.status(404).json({ error: "Exception not found" });
    }

    return res.json({ data: serializeException(updated) });
  } catch (error) {
    return next(error);
  }
};

securityRouter.get("/overview", getOverview);
securityRouter.get("/assets", listAssets);
securityRouter.post(
  "/assets",
  requireRole(["OWNER", "ADMIN", "SECURITY_ANALYST"]),
  createAsset
);
securityRouter.patch(
  "/assets/:id",
  requireRole(["OWNER", "ADMIN", "SECURITY_ANALYST"]),
  updateAsset
);
securityRouter.get("/exceptions", listExceptions);
securityRouter.post(
  "/exceptions",
  requireRole(["OWNER", "ADMIN", "SECURITY_ANALYST"]),
  createException
);
securityRouter.patch(
  "/exceptions/:id",
  requireRole(["OWNER", "ADMIN"]),
  updateException
);

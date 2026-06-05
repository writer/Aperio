import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { z } from "zod";
import { prisma } from "@aperio/db";
import { createOneTimeToken } from "@aperio/security";
import { inviteMemberSchema } from "@aperio/shared/auth";
import { sendTenantOperationalAlert } from "../lib/alerts";
import { deliverAuthLinkEmail } from "../lib/email";
import { requireRole, type TenantRequest } from "../middleware/security";

export const adminRouter = Router();

const settingsSchema = z
  .object({
    name: z.string().trim().min(1).max(160).optional(),
    notificationEmail: z
      .union([z.string().trim().email().max(255), z.literal("")])
      .optional(),
    dataRetentionDays: z.coerce.number().int().min(7).max(3650).optional(),
    criticalRiskThreshold: z.coerce.number().int().min(0).max(100).optional(),
    defaultSlaHours: z.coerce.number().int().min(1).max(720).optional(),
    autoResolveLowSeverity: z.boolean().optional(),
    enforceSsoOnly: z.boolean().optional(),
    webhookAlertUrl: z
      .union([z.string().trim().url().max(500), z.literal("")])
      .optional()
  })
  .strict();

const memberRoleSchema = z.object({
  roleName: z.enum(["OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"])
});

const createMemberSchema = inviteMemberSchema;

function buildAuthLink(path: string, token: string) {
  const baseUrl = (
    process.env.APERIO_WEB_ORIGIN ?? process.env.NEXT_PUBLIC_APP_BASE_URL ?? "http://localhost:3000"
  ).replace(/\/$/, "");
  return `${baseUrl}${path}?token=${encodeURIComponent(token)}`;
}

async function deliverAuthLink(input: {
  kind: "invite" | "password_reset";
  organizationId: string;
  organizationName: string;
  recipientEmail: string;
  recipientName?: string | null;
  path: "/accept-invite" | "/reset-password";
  token: string;
  expiresAt: Date;
}) {
  const url = buildAuthLink(input.path, input.token);

  try {
    const delivery = await deliverAuthLinkEmail({
      kind: input.kind,
      organizationName: input.organizationName,
      recipientEmail: input.recipientEmail,
      recipientName: input.recipientName,
      link: url,
      expiresAt: input.expiresAt
    });

    return {
      ...delivery,
      expiresAt: input.expiresAt.toISOString()
    };
  } catch (error) {
    await sendTenantOperationalAlert({
      organizationId: input.organizationId,
      title: "Auth delivery failure",
      details: `Unable to deliver ${input.kind.replace("_", " ")} email to ${input.recipientEmail}.`,
      metadata: {
        path: input.path,
        error: error instanceof Error ? error.message : String(error)
      }
    });
    throw error;
  }
}

function isEmailDeliveryError(error: unknown) {
  return (
    error instanceof Error &&
    error.message.toLowerCase().startsWith("email delivery")
  );
}

function serializeMember(user: {
  id: string;
  email: string;
  displayName: string | null;
  isActive: boolean;
  passwordHash: string | null;
  mfaEnabled: boolean;
  lastLoginAt: Date | null;
  isBreakGlass: boolean;
  createdAt: Date;
  role: { name: "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER" };
  authTokens?: Array<{
    purpose: "INVITE" | "PASSWORD_RESET";
    expiresAt: Date;
    consumedAt: Date | null;
  }>;
}) {
  const pendingToken = user.authTokens?.find(
    (token) => !token.consumedAt && token.expiresAt.getTime() > Date.now()
  );
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    isActive: user.isActive,
    mfaEnabled: user.mfaEnabled,
    lastLoginAt: user.lastLoginAt?.toISOString() ?? null,
    isBreakGlass: user.isBreakGlass,
    role: user.role.name,
    authState: pendingToken
      ? pendingToken.purpose === "PASSWORD_RESET"
        ? "PASSWORD_RESET_PENDING"
        : "INVITED"
      : user.passwordHash
        ? "ACTIVE"
        : "INVITED",
    pendingActionExpiresAt: pendingToken?.expiresAt.toISOString() ?? null,
    createdAt: user.createdAt.toISOString()
  };
}

function serializeOrg(org: {
  id: string;
  name: string;
  slug: string;
  notificationEmail: string | null;
  dataRetentionDays: number;
  criticalRiskThreshold: number;
  defaultSlaHours: number;
  autoResolveLowSeverity: boolean;
  enforceSsoOnly: boolean;
  webhookAlertUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: org.id,
    name: org.name,
    slug: org.slug,
    notificationEmail: org.notificationEmail,
    dataRetentionDays: org.dataRetentionDays,
    criticalRiskThreshold: org.criticalRiskThreshold,
    defaultSlaHours: org.defaultSlaHours,
    autoResolveLowSeverity: org.autoResolveLowSeverity,
    enforceSsoOnly: org.enforceSsoOnly,
    webhookAlertUrl: org.webhookAlertUrl,
    createdAt: org.createdAt.toISOString(),
    updatedAt: org.updatedAt.toISOString()
  };
}

const getSettings: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const org = await prisma.organization.findUnique({
      where: { id: tenantReq.tenantId }
    });
    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }
    return res.json({ data: serializeOrg(org) });
  } catch (error) {
    if (isEmailDeliveryError(error)) {
      return res.status(503).json({
        error: "Invitation delivery is unavailable"
      });
    }
    return next(error);
  }
};

const updateSettings: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = settingsSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid settings payload", details: parsed.error.flatten() });
    }

    const data = {
      ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
      ...(parsed.data.notificationEmail !== undefined
        ? { notificationEmail: parsed.data.notificationEmail || null }
        : {}),
      ...(parsed.data.dataRetentionDays !== undefined
        ? { dataRetentionDays: parsed.data.dataRetentionDays }
        : {}),
      ...(parsed.data.criticalRiskThreshold !== undefined
        ? { criticalRiskThreshold: parsed.data.criticalRiskThreshold }
        : {}),
      ...(parsed.data.defaultSlaHours !== undefined
        ? { defaultSlaHours: parsed.data.defaultSlaHours }
        : {}),
      ...(parsed.data.autoResolveLowSeverity !== undefined
        ? { autoResolveLowSeverity: parsed.data.autoResolveLowSeverity }
        : {}),
      ...(parsed.data.enforceSsoOnly !== undefined
        ? { enforceSsoOnly: parsed.data.enforceSsoOnly }
        : {}),
      ...(parsed.data.webhookAlertUrl !== undefined
        ? { webhookAlertUrl: parsed.data.webhookAlertUrl || null }
        : {})
    };

    const updated = await prisma.$transaction(async (tx) => {
      const org = await tx.organization.update({
        where: { id: tenantReq.tenantId },
        data
      });
      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "tenant.settings.update",
          targetType: "organization",
          targetId: tenantReq.tenantId,
          ipAddress: req.ip,
          metadata: { changed: Object.keys(data) }
        }
      });
      return org;
    });

    return res.json({ data: serializeOrg(updated) });
  } catch (error) {
    if (isEmailDeliveryError(error)) {
      return res.status(503).json({
        error: "Password reset delivery is unavailable"
      });
    }
    return next(error);
  }
};

const listMembers: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const users = await prisma.user.findMany({
      where: { organizationId: tenantReq.tenantId },
      orderBy: [{ createdAt: "asc" }],
      include: {
        role: { select: { name: true } },
        authTokens: {
          where: { consumedAt: null },
          select: { purpose: true, expiresAt: true, consumedAt: true },
          orderBy: [{ createdAt: "desc" }],
          take: 3
        }
      }
    });
    return res.json({
      data: users.map(serializeMember)
    });
  } catch (error) {
    return next(error);
  }
};

const createMember: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const parsed = createMemberSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Invalid member payload", details: parsed.error.flatten() });
    }

    const existing = await prisma.user.findUnique({
      where: {
        organizationId_email: {
          organizationId: tenantReq.tenantId,
          email: parsed.data.email
        }
      },
      include: { role: { select: { name: true } } }
    });

    if (existing?.passwordHash) {
      return res.status(409).json({
        error: "A member with this email already exists. Generate a reset link instead."
      });
    }

    const created = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.findUniqueOrThrow({
        where: { id: tenantReq.tenantId },
        select: { name: true }
      });
      const role = await tx.role.upsert({
        where: {
          organizationId_name: {
            organizationId: tenantReq.tenantId,
            name: parsed.data.roleName
          }
        },
        update: {},
        create: {
          organizationId: tenantReq.tenantId,
          name: parsed.data.roleName,
          permissions:
            parsed.data.roleName === "OWNER" || parsed.data.roleName === "ADMIN"
              ? ["*"]
              : ["read"]
        }
      });
      const user = existing
        ? await tx.user.update({
            where: { id: existing.id },
            data: {
              roleId: role.id,
              displayName: parsed.data.displayName ?? existing.displayName,
              isActive: true,
              passwordHash: null,
              mfaEnabled: false,
              mfaSecretEncrypted: null
            },
            include: {
              role: { select: { name: true } },
              authTokens: {
                where: { consumedAt: null },
                select: { purpose: true, expiresAt: true, consumedAt: true },
                orderBy: [{ createdAt: "desc" }],
                take: 3
              }
            }
          })
        : await tx.user.create({
            data: {
              organizationId: tenantReq.tenantId,
              roleId: role.id,
              email: parsed.data.email,
              displayName: parsed.data.displayName ?? null,
              passwordHash: null
            },
            include: {
              role: { select: { name: true } },
              authTokens: {
                where: { consumedAt: null },
                select: { purpose: true, expiresAt: true, consumedAt: true },
                orderBy: [{ createdAt: "desc" }],
                take: 3
              }
            }
          });

      await tx.authToken.updateMany({
        where: {
          organizationId: tenantReq.tenantId,
          userId: user.id,
          purpose: "INVITE",
          consumedAt: null
        },
        data: { consumedAt: new Date() }
      });

      const { token, tokenHash } = createOneTimeToken();
      const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);

      await tx.authToken.create({
        data: {
          organizationId: tenantReq.tenantId,
          userId: user.id,
          createdByUserId: tenantReq.auth.userId,
          purpose: "INVITE",
          tokenHash,
          expiresAt
        }
      });
      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "tenant.member.invite",
          targetType: "user",
          targetId: user.id,
          ipAddress: req.ip,
          metadata: {
            email: user.email,
            role: parsed.data.roleName
          }
        }
      });
      return {
        organizationName: organization.name,
        user,
        invitation: {
          token,
          expiresAt
        }
      };
    });

    const delivery = await deliverAuthLink({
      kind: "invite",
      organizationId: tenantReq.tenantId,
      organizationName: created.organizationName,
      recipientEmail: created.user.email,
      recipientName: created.user.displayName,
      path: "/accept-invite",
      token: created.invitation.token,
      expiresAt: created.invitation.expiresAt
    });

    return res.status(201).json({
      data: serializeMember({
        ...created.user,
        authTokens: [
          {
            purpose: "INVITE",
            expiresAt: created.invitation.expiresAt,
            consumedAt: null
          }
        ]
      }),
      invitation: {
        delivery: delivery.delivery,
        ...(delivery.url ? { url: delivery.url } : {}),
        expiresAt: delivery.expiresAt
      }
    });
  } catch (error) {
    return next(error);
  }
};

const createResetLink: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const userId = req.params.id;

  if (!userId) {
    return res.status(400).json({ error: "User id is required" });
  }

  try {
    const issued = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.findUniqueOrThrow({
        where: { id: tenantReq.tenantId },
        select: { name: true }
      });
      const user = await tx.user.findFirst({
        where: { id: userId, organizationId: tenantReq.tenantId, isActive: true },
        include: { role: { select: { name: true } } }
      });

      if (!user) {
        return null;
      }

      await tx.authToken.updateMany({
        where: {
          organizationId: tenantReq.tenantId,
          userId: user.id,
          purpose: "PASSWORD_RESET",
          consumedAt: null
        },
        data: { consumedAt: new Date() }
      });

      const { token, tokenHash } = createOneTimeToken();
      const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);

      await tx.authToken.create({
        data: {
          organizationId: tenantReq.tenantId,
          userId: user.id,
          createdByUserId: tenantReq.auth.userId,
          purpose: "PASSWORD_RESET",
          tokenHash,
          expiresAt
        }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "tenant.member.password_reset_link",
          targetType: "user",
          targetId: user.id,
          ipAddress: req.ip,
          metadata: {
            email: user.email,
            expiresAt: expiresAt.toISOString()
          }
        }
      });

      return {
        organizationName: organization.name,
        user,
        reset: {
          token,
          expiresAt
        }
      };
    });

    if (!issued) {
      return res.status(404).json({ error: "User not found" });
    }

    const delivery = await deliverAuthLink({
      kind: "password_reset",
      organizationId: tenantReq.tenantId,
      organizationName: issued.organizationName,
      recipientEmail: issued.user.email,
      recipientName: issued.user.displayName,
      path: "/reset-password",
      token: issued.reset.token,
      expiresAt: issued.reset.expiresAt
    });

    return res.json({
      data: serializeMember({
        ...issued.user,
        authTokens: [
          {
            purpose: "PASSWORD_RESET",
            expiresAt: issued.reset.expiresAt,
            consumedAt: null
          }
        ]
      }),
      reset: {
        delivery: delivery.delivery,
        ...(delivery.url ? { url: delivery.url } : {}),
        expiresAt: delivery.expiresAt
      }
    });
  } catch (error) {
    return next(error);
  }
};

const updateMemberRole: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  const userId = req.params.id;
  if (!userId) {
    return res.status(400).json({ error: "User id is required" });
  }
  try {
    const parsed = memberRoleSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const target = await tx.user.findFirst({
        where: { id: userId, organizationId: tenantReq.tenantId }
      });
      if (!target) {
        return null;
      }
      const role = await tx.role.upsert({
        where: {
          organizationId_name: {
            organizationId: tenantReq.tenantId,
            name: parsed.data.roleName
          }
        },
        update: {},
        create: {
          organizationId: tenantReq.tenantId,
          name: parsed.data.roleName,
          permissions:
            parsed.data.roleName === "OWNER" || parsed.data.roleName === "ADMIN"
              ? ["*"]
              : ["read"]
        }
      });
      const user = await tx.user.update({
        where: { id: target.id },
        data: { roleId: role.id },
        include: { role: { select: { name: true } } }
      });
      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "tenant.member.role_update",
          targetType: "user",
          targetId: user.id,
          ipAddress: req.ip,
          metadata: { newRole: parsed.data.roleName }
        }
      });
      return user;
    });

    if (!updated) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.json({
      data: serializeMember(updated)
    });
  } catch (error) {
    return next(error);
  }
};

const listAuditLogs: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;
  try {
    const logs = await prisma.tenantAuditLog.findMany({
      where: { organizationId: tenantReq.tenantId },
      orderBy: [{ createdAt: "desc" }],
      take: 50,
      include: {
        actor: { select: { email: true, displayName: true } }
      }
    });
    return res.json({
      data: logs.map((log) => ({
        id: log.id,
        action: log.action,
        targetType: log.targetType,
        targetId: log.targetId,
        actor: log.actor?.email ?? "system",
        createdAt: log.createdAt.toISOString(),
        metadata: log.metadata
      }))
    });
  } catch (error) {
    return next(error);
  }
};

adminRouter.get("/settings", requireRole(["OWNER", "ADMIN"]), getSettings);
adminRouter.patch(
  "/settings",
  requireRole(["OWNER", "ADMIN"]),
  updateSettings
);
adminRouter.get("/members", requireRole(["OWNER", "ADMIN"]), listMembers);
adminRouter.post("/members", requireRole(["OWNER", "ADMIN"]), createMember);
adminRouter.post(
  "/members/:id/reset-link",
  requireRole(["OWNER", "ADMIN"]),
  createResetLink
);
adminRouter.patch(
  "/members/:id/role",
  requireRole(["OWNER", "ADMIN"]),
  updateMemberRole
);
adminRouter.get("/audit-logs", requireRole(["OWNER", "ADMIN"]), listAuditLogs);

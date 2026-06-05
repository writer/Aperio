import type { NextFunction, RequestHandler, Response } from "express";
import { Router } from "express";
import { prisma } from "@aperio/db";
import {
  buildTotpOtpAuthUrl,
  createTotpSecret,
  createOneTimeToken,
  decryptString,
  encryptString,
  hashOpaqueToken,
  hashPassword,
  verifyTotpCode,
  verifyPassword
} from "@aperio/security";
import {
  acceptInviteSchema,
  completePasswordResetSchema,
  disableMfaSchema,
  loginSchema,
  requestPasswordResetSchema,
  signupSchema,
  verifyMfaEnrollmentSchema
} from "@aperio/shared/auth";
import { sendTenantOperationalAlert } from "../lib/alerts";
import { deliverAuthLinkEmail } from "../lib/email";
import { createMemoryRateLimit } from "../middleware/rate-limit";
import {
  issueSessionToken,
  requireAuth,
  requireTenant,
  revokeSession,
  type TenantRequest
} from "../middleware/security";

export const authRouter = Router();

type RoleName = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

const signupRateLimit = createMemoryRateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many workspace signup attempts. Please try again later."
});

const loginRateLimit = createMemoryRateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  message: "Too many login attempts. Please wait before trying again."
});

const passwordResetRateLimit = createMemoryRateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many password reset attempts. Please wait before trying again."
});

function rolePermissions(name: RoleName): string[] {
  switch (name) {
    case "OWNER":
    case "ADMIN":
      return ["*"];
    case "SECURITY_ANALYST":
      return ["read", "triage", "remediate"];
    default:
      return ["read"];
  }
}

async function ensureTenantRoles(organizationId: string) {
  await Promise.all(
    (["OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"] as const).map((name) =>
      prisma.role.upsert({
        where: {
          organizationId_name: {
            organizationId,
            name
          }
        },
        update: {
          permissions: rolePermissions(name)
        },
        create: {
          organizationId,
          name,
          permissions: rolePermissions(name)
        }
      })
    )
  );
}

function serializeSession(input: {
  token: string;
  user: {
    id: string;
    email: string;
    displayName: string | null;
    mfaEnabled: boolean;
    role: { name: RoleName };
    organization: {
      id: string;
      name: string;
      slug: string;
    };
  };
}) {
  return {
    token: input.token,
    user: {
      id: input.user.id,
      email: input.user.email,
      displayName: input.user.displayName,
      mfaEnabled: input.user.mfaEnabled,
      role: input.user.role.name
    },
    organization: {
      id: input.user.organization.id,
      name: input.user.organization.name,
      slug: input.user.organization.slug
    }
  };
}

function buildAuthLink(path: string, token: string) {
  const baseUrl = (
    process.env.APERIO_WEB_ORIGIN ?? process.env.NEXT_PUBLIC_APP_BASE_URL ?? "http://localhost:3000"
  ).replace(/\/$/, "");
  return `${baseUrl}${path}?token=${encodeURIComponent(token)}`;
}

async function issueAuthToken(input: {
  organizationId: string;
  userId: string;
  createdByUserId?: string | null;
  purpose: "INVITE" | "PASSWORD_RESET";
  expiresInHours: number;
}) {
  const { token, tokenHash } = createOneTimeToken();
  const expiresAt = new Date(Date.now() + input.expiresInHours * 60 * 60 * 1000);
  const invalidatedAt = new Date();

  await prisma.$transaction(async (tx) => {
    if (input.purpose === "PASSWORD_RESET") {
      await tx.authToken.updateMany({
        where: {
          organizationId: input.organizationId,
          userId: input.userId,
          purpose: input.purpose,
          consumedAt: null
        },
        data: {
          consumedAt: invalidatedAt
        }
      });
    }

    await tx.authToken.create({
      data: {
        organizationId: input.organizationId,
        userId: input.userId,
        createdByUserId: input.createdByUserId ?? null,
        purpose: input.purpose,
        tokenHash,
        expiresAt
      }
    });
  });

  return {
    token,
    expiresAt
  };
}

function mfaIssuer() {
  return process.env.APERIO_MFA_ISSUER?.trim() || "Aperio";
}

function decryptedMfaSecret(
  encryptedSecret: string | null | undefined,
  userId: string
) {
  if (!encryptedSecret) {
    return null;
  }

  return decryptString(encryptedSecret, `mfa:${userId}`);
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
  const link = buildAuthLink(input.path, input.token);

  try {
    const delivery = await deliverAuthLinkEmail({
      kind: input.kind,
      organizationName: input.organizationName,
      recipientEmail: input.recipientEmail,
      recipientName: input.recipientName,
      link,
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

const signupHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  try {
    const parsed = signupSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid signup payload",
        details: parsed.error.flatten()
      });
    }

    const existingOrganization = await prisma.organization.findUnique({
      where: { slug: parsed.data.organizationSlug },
      select: { id: true }
    });

    if (existingOrganization) {
      return res.status(409).json({
        error: "Workspace slug is already in use"
      });
    }

    const created = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: {
          name: parsed.data.organizationName,
          slug: parsed.data.organizationSlug,
          notificationEmail: parsed.data.notificationEmail || null
        }
      });

      await Promise.all(
        (["OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"] as const).map((name) =>
          tx.role.upsert({
            where: {
              organizationId_name: {
                organizationId: organization.id,
                name
              }
            },
            update: {
              permissions: rolePermissions(name)
            },
            create: {
              organizationId: organization.id,
              name,
              permissions: rolePermissions(name)
            }
          })
        )
      );

      const ownerRole = await tx.role.findUniqueOrThrow({
        where: {
          organizationId_name: {
            organizationId: organization.id,
            name: "OWNER"
          }
        }
      });

      const user = await tx.user.create({
        data: {
          organizationId: organization.id,
          roleId: ownerRole.id,
          email: parsed.data.ownerEmail,
          displayName: parsed.data.ownerDisplayName ?? null,
          passwordHash: hashPassword(parsed.data.password),
          isActive: true,
          mfaEnabled: false
        },
        include: {
          role: { select: { name: true } },
          organization: { select: { id: true, name: true, slug: true } }
        }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: organization.id,
          actorUserId: user.id,
          action: "tenant.workspace.create",
          targetType: "organization",
          targetId: organization.id,
          ipAddress: req.ip,
          metadata: {
            ownerEmail: user.email
          }
        }
      });

      return user;
    });

    const token = await issueSessionToken({
      userId: created.id,
      organizationId: created.organization.id,
      role: created.role.name,
      mfaVerified: false,
      req
    });

    return res.status(201).json({
      data: serializeSession({
        token,
        user: created
      })
    });
  } catch (error) {
    return next(error);
  }
};

const loginHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  try {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid login payload",
        details: parsed.error.flatten()
      });
    }

    const organization = await prisma.organization.findUnique({
      where: { slug: parsed.data.organizationSlug },
      select: { id: true, enforceSsoOnly: true }
    });

    if (!organization) {
      return res.status(401).json({ error: "Invalid workspace or credentials" });
    }

    if (organization.enforceSsoOnly) {
      return res.status(403).json({
        error: "Password login is disabled for this workspace"
      });
    }

    await ensureTenantRoles(organization.id);

    const user = await prisma.user.findUnique({
      where: {
        organizationId_email: {
          organizationId: organization.id,
          email: parsed.data.email
        }
      },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    if (
      !user ||
      !user.isActive ||
      !user.passwordHash ||
      !verifyPassword(parsed.data.password, user.passwordHash)
    ) {
      return res.status(401).json({ error: "Invalid workspace or credentials" });
    }

    const decryptedSecret = decryptedMfaSecret(user.mfaSecretEncrypted, user.id);
    const requiresMfa = user.mfaEnabled && !!decryptedSecret;

    if (requiresMfa && !parsed.data.totpCode) {
      return res.status(401).json({
        error: "Authentication code required",
        details: {
          formErrors: ["Authentication code required"],
          fieldErrors: {
            totpCode: ["Authentication code required"]
          }
        }
      });
    }

    if (
      requiresMfa &&
      (!parsed.data.totpCode ||
        !verifyTotpCode(decryptedSecret, parsed.data.totpCode))
    ) {
      return res.status(401).json({
        error: "Invalid authentication code",
        details: {
          formErrors: ["Invalid authentication code"],
          fieldErrors: {
            totpCode: ["Invalid authentication code"]
          }
        }
      });
    }

    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    const token = await issueSessionToken({
      userId: updatedUser.id,
      organizationId: updatedUser.organization.id,
      role: updatedUser.role.name,
      mfaVerified: requiresMfa,
      req
    });

    return res.json({
      data: serializeSession({
        token,
        user: updatedUser
      })
    });
  } catch (error) {
    return next(error);
  }
};

const meHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const user = await prisma.user.findFirst({
      where: {
        id: tenantReq.auth.userId,
        organizationId: tenantReq.tenantId,
        isActive: true
      },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    return res.json({
      data: serializeSession({
        token: tenantReq.auth.sessionToken,
        user
      })
    });
  } catch (error) {
    return next(error);
  }
};

const forgotPasswordHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  try {
    const parsed = requestPasswordResetSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid password reset payload",
        details: parsed.error.flatten()
      });
    }

    const organization = await prisma.organization.findUnique({
      where: { slug: parsed.data.organizationSlug },
      select: { id: true, slug: true, name: true }
    });

    if (!organization) {
      return res.status(202).json({ data: { accepted: true } });
    }

    const user = await prisma.user.findUnique({
      where: {
        organizationId_email: {
          organizationId: organization.id,
          email: parsed.data.email
        }
      },
      select: { id: true, isActive: true, email: true, displayName: true }
    });

    if (!user?.isActive) {
      return res.status(202).json({ data: { accepted: true } });
    }

    const issued = await issueAuthToken({
      organizationId: organization.id,
      userId: user.id,
      purpose: "PASSWORD_RESET",
      expiresInHours: 2
    });

    await prisma.tenantAuditLog.create({
      data: {
        organizationId: organization.id,
        actorUserId: null,
        action: "auth.password_reset.requested",
        targetType: "user",
        targetId: user.id,
        ipAddress: req.ip,
        metadata: {
          expiresAt: issued.expiresAt.toISOString()
        }
      }
    });

    const delivery = await deliverAuthLink({
      kind: "password_reset",
      organizationId: organization.id,
      organizationName: organization.name,
      recipientEmail: user.email,
      recipientName: user.displayName,
      path: "/reset-password",
      token: issued.token,
      expiresAt: issued.expiresAt
    });

    return res.status(202).json({
      data: {
        accepted: true,
        delivery: delivery.delivery,
        ...(delivery.url ? { resetUrl: delivery.url } : {}),
        expiresAt: delivery.expiresAt
      }
    });
  } catch (error) {
    return next(error);
  }
};

const resetPasswordHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  try {
    const parsed = completePasswordResetSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid password reset payload",
        details: parsed.error.flatten()
      });
    }

    const tokenHash = hashOpaqueToken(parsed.data.token);

    const tokenRecord = await prisma.authToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          include: {
            role: { select: { name: true } },
            organization: { select: { id: true, name: true, slug: true } }
          }
        }
      }
    });

    if (
      !tokenRecord ||
      tokenRecord.purpose !== "PASSWORD_RESET" ||
      tokenRecord.consumedAt ||
      tokenRecord.expiresAt.getTime() <= Date.now() ||
      !tokenRecord.user.isActive
    ) {
      return res.status(400).json({ error: "Password reset link is invalid or expired" });
    }

    const updatedUser = await prisma.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id: tokenRecord.userId },
        data: {
          passwordHash: hashPassword(parsed.data.password),
          lastLoginAt: new Date()
        },
        include: {
          role: { select: { name: true } },
          organization: { select: { id: true, name: true, slug: true } }
        }
      });

      await tx.authToken.update({
        where: { id: tokenRecord.id },
        data: { consumedAt: new Date() }
      });

      await tx.userSession.updateMany({
        where: {
          userId: tokenRecord.userId,
          revokedAt: null
        },
        data: {
          revokedAt: new Date()
        }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tokenRecord.organizationId,
          actorUserId: user.id,
          action: "auth.password_reset.completed",
          targetType: "user",
          targetId: user.id,
          ipAddress: req.ip
        }
      });

      return user;
    });

    const token = await issueSessionToken({
      userId: updatedUser.id,
      organizationId: updatedUser.organization.id,
      role: updatedUser.role.name,
      mfaVerified: updatedUser.mfaEnabled,
      req
    });

    return res.json({
      data: serializeSession({
        token,
        user: updatedUser
      })
    });
  } catch (error) {
    return next(error);
  }
};

const acceptInviteHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  try {
    const parsed = acceptInviteSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid invitation payload",
        details: parsed.error.flatten()
      });
    }

    const tokenHash = hashOpaqueToken(parsed.data.token);

    const tokenRecord = await prisma.authToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          include: {
            role: { select: { name: true } },
            organization: { select: { id: true, name: true, slug: true } }
          }
        }
      }
    });

    if (
      !tokenRecord ||
      tokenRecord.purpose !== "INVITE" ||
      tokenRecord.consumedAt ||
      tokenRecord.expiresAt.getTime() <= Date.now()
    ) {
      return res.status(400).json({ error: "Invitation link is invalid or expired" });
    }

    const updatedUser = await prisma.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id: tokenRecord.userId },
        data: {
          displayName: parsed.data.displayName ?? tokenRecord.user.displayName,
          passwordHash: hashPassword(parsed.data.password),
          isActive: true,
          mfaEnabled: false,
          mfaSecretEncrypted: null,
          lastLoginAt: new Date()
        },
        include: {
          role: { select: { name: true } },
          organization: { select: { id: true, name: true, slug: true } }
        }
      });

      await tx.authToken.update({
        where: { id: tokenRecord.id },
        data: { consumedAt: new Date() }
      });

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tokenRecord.organizationId,
          actorUserId: user.id,
          action: "auth.invite.accepted",
          targetType: "user",
          targetId: user.id,
          ipAddress: req.ip
        }
      });

      return user;
    });

    const token = await issueSessionToken({
      userId: updatedUser.id,
      organizationId: updatedUser.organization.id,
      role: updatedUser.role.name,
      mfaVerified: false,
      req
    });

    return res.json({
      data: serializeSession({
        token,
        user: updatedUser
      })
    });
  } catch (error) {
    return next(error);
  }
};

const logoutHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    await revokeSession(tenantReq.auth.sessionId);
    return res.json({ data: { ok: true } });
  } catch (error) {
    return next(error);
  }
};

const listWorkspacesHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const currentUser = await prisma.user.findFirst({
      where: {
        id: tenantReq.auth.userId,
        organizationId: tenantReq.tenantId,
        isActive: true
      },
      select: { email: true }
    });

    if (!currentUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const memberships = await prisma.user.findMany({
      where: {
        email: {
          equals: currentUser.email.trim(),
          mode: "insensitive"
        },
        isActive: true
      },
      select: {
        role: { select: { name: true } },
        organization: {
          select: { id: true, name: true, slug: true }
        }
      },
      orderBy: [{ organization: { name: "asc" } }]
    });

    const workspaces = memberships.map((membership) => ({
      id: membership.organization.id,
      name: membership.organization.name,
      slug: membership.organization.slug,
      role: membership.role.name,
      current: membership.organization.id === tenantReq.tenantId
    }));

    return res.json({ data: workspaces });
  } catch (error) {
    return next(error);
  }
};

const switchWorkspaceHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const slugRaw =
      typeof body.organizationSlug === "string"
        ? body.organizationSlug
        : typeof body.workspaceSlug === "string"
          ? body.workspaceSlug
          : null;
    const slug = slugRaw?.trim().toLowerCase();

    if (!slug) {
      return res
        .status(400)
        .json({ error: "organizationSlug is required" });
    }

    const currentUser = await prisma.user.findFirst({
      where: {
        id: tenantReq.auth.userId,
        organizationId: tenantReq.tenantId,
        isActive: true
      },
      select: {
        id: true,
        email: true,
        organization: { select: { slug: true } }
      }
    });

    if (!currentUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (currentUser.organization.slug === slug) {
      return res
        .status(409)
        .json({ error: "Already in the requested workspace" });
    }

    const targetOrganization = await prisma.organization.findUnique({
      where: { slug },
      select: { id: true }
    });

    if (!targetOrganization) {
      return res.status(404).json({ error: "Workspace not found" });
    }

    const targetMembership = await prisma.user.findFirst({
      where: {
        organizationId: targetOrganization.id,
        email: {
          equals: currentUser.email.trim(),
          mode: "insensitive"
        }
      },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    if (!targetMembership || !targetMembership.isActive) {
      return res
        .status(403)
        .json({ error: "No active membership for this workspace" });
    }

    if (targetMembership.mfaEnabled) {
      const currentSession = tenantReq.auth.sessionId
        ? await prisma.userSession.findUnique({
            where: { id: tenantReq.auth.sessionId },
            select: { mfaVerifiedAt: true }
          })
        : null;
      if (!currentSession?.mfaVerifiedAt) {
        return res.status(401).json({
          error:
            "MFA verification required to switch into this workspace. Sign in to it directly."
        });
      }
    }

    await revokeSession(tenantReq.auth.sessionId);

    const updatedTarget = await prisma.user.update({
      where: { id: targetMembership.id },
      data: { lastLoginAt: new Date() },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    await prisma.tenantAuditLog.create({
      data: {
        organizationId: updatedTarget.organization.id,
        actorUserId: updatedTarget.id,
        action: "auth.workspace.switch",
        targetType: "organization",
        targetId: updatedTarget.organization.id,
        ipAddress: req.ip,
        metadata: {
          fromWorkspaceSlug: currentUser.organization.slug,
          toWorkspaceSlug: updatedTarget.organization.slug
        }
      }
    });

    const token = await issueSessionToken({
      userId: updatedTarget.id,
      organizationId: updatedTarget.organization.id,
      role: updatedTarget.role.name,
      mfaVerified: updatedTarget.mfaEnabled,
      req
    });

    return res.json({
      data: serializeSession({
        token,
        user: updatedTarget
      })
    });
  } catch (error) {
    return next(error);
  }
};

const beginMfaEnrollmentHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const user = await prisma.user.findFirst({
      where: {
        id: tenantReq.auth.userId,
        organizationId: tenantReq.tenantId,
        isActive: true
      },
      select: {
        id: true,
        email: true,
        organization: { select: { name: true } }
      }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const secret = createTotpSecret();
    const otpauthUrl = buildTotpOtpAuthUrl({
      issuer: mfaIssuer(),
      accountName: `${user.organization.name}:${user.email}`,
      secret
    });

    await prisma.user.update({
      where: { id: user.id },
      data: {
        mfaEnabled: false,
        mfaSecretEncrypted: encryptString(secret, `mfa:${user.id}`)
      }
    });

    return res.json({
      data: {
        secret,
        otpauthUrl
      }
    });
  } catch (error) {
    return next(error);
  }
};

const verifyMfaEnrollmentHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = verifyMfaEnrollmentSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid MFA payload",
        details: parsed.error.flatten()
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        id: tenantReq.auth.userId,
        organizationId: tenantReq.tenantId,
        isActive: true
      },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const secret = decryptedMfaSecret(user.mfaSecretEncrypted, user.id);

    if (!secret || !verifyTotpCode(secret, parsed.data.code)) {
      return res.status(400).json({
        error: "Invalid authentication code"
      });
    }

    const updatedUser = await prisma.$transaction(async (tx) => {
      const nextUser = await tx.user.update({
        where: { id: user.id },
        data: { mfaEnabled: true },
        include: {
          role: { select: { name: true } },
          organization: { select: { id: true, name: true, slug: true } }
        }
      });

      if (tenantReq.auth.sessionId) {
        await tx.userSession.updateMany({
          where: { id: tenantReq.auth.sessionId },
          data: { mfaVerifiedAt: new Date() }
        });
      }

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "auth.mfa.enabled",
          targetType: "user",
          targetId: tenantReq.auth.userId,
          ipAddress: req.ip
        }
      });

      return nextUser;
    });

    return res.json({
      data: serializeSession({
        token: tenantReq.auth.sessionToken,
        user: updatedUser
      })
    });
  } catch (error) {
    return next(error);
  }
};

const disableMfaHandler: RequestHandler = async (
  req,
  res: Response,
  next: NextFunction
) => {
  const tenantReq = req as TenantRequest;

  try {
    const parsed = disableMfaSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid MFA payload",
        details: parsed.error.flatten()
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        id: tenantReq.auth.userId,
        organizationId: tenantReq.tenantId,
        isActive: true
      },
      include: {
        role: { select: { name: true } },
        organization: { select: { id: true, name: true, slug: true } }
      }
    });

    if (!user || !user.passwordHash) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!verifyPassword(parsed.data.password, user.passwordHash)) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const secret = decryptedMfaSecret(user.mfaSecretEncrypted, user.id);

    if (user.mfaEnabled && (!secret || !parsed.data.code)) {
      return res.status(400).json({
        error: "Current authentication code is required"
      });
    }

    if (
      user.mfaEnabled &&
      secret &&
      parsed.data.code &&
      !verifyTotpCode(secret, parsed.data.code)
    ) {
      return res.status(400).json({
        error: "Invalid authentication code"
      });
    }

    const updatedUser = await prisma.$transaction(async (tx) => {
      const nextUser = await tx.user.update({
        where: { id: user.id },
        data: {
          mfaEnabled: false,
          mfaSecretEncrypted: null
        },
        include: {
          role: { select: { name: true } },
          organization: { select: { id: true, name: true, slug: true } }
        }
      });

      if (tenantReq.auth.sessionId) {
        await tx.userSession.updateMany({
          where: { id: tenantReq.auth.sessionId },
          data: { mfaVerifiedAt: null }
        });
      }

      await tx.tenantAuditLog.create({
        data: {
          organizationId: tenantReq.tenantId,
          actorUserId: tenantReq.auth.userId,
          action: "auth.mfa.disabled",
          targetType: "user",
          targetId: tenantReq.auth.userId,
          ipAddress: req.ip
        }
      });

      return nextUser;
    });

    return res.json({
      data: serializeSession({
        token: tenantReq.auth.sessionToken,
        user: updatedUser
      })
    });
  } catch (error) {
    return next(error);
  }
};

authRouter.post("/signup", signupRateLimit, signupHandler);
authRouter.post("/login", loginRateLimit, loginHandler);
authRouter.post(
  "/forgot-password",
  passwordResetRateLimit,
  forgotPasswordHandler
);
authRouter.post("/reset-password", passwordResetRateLimit, resetPasswordHandler);
authRouter.post("/invitations/accept", acceptInviteHandler);
authRouter.get("/me", requireAuth, requireTenant, meHandler);
authRouter.post("/logout", requireAuth, requireTenant, logoutHandler);
authRouter.get(
  "/workspaces",
  requireAuth,
  requireTenant,
  listWorkspacesHandler
);
authRouter.post(
  "/workspaces/switch",
  requireAuth,
  requireTenant,
  switchWorkspaceHandler
);
authRouter.post(
  "/mfa/setup",
  requireAuth,
  requireTenant,
  beginMfaEnrollmentHandler
);
authRouter.post(
  "/mfa/enable",
  requireAuth,
  requireTenant,
  verifyMfaEnrollmentHandler
);
authRouter.post(
  "/mfa/disable",
  requireAuth,
  requireTenant,
  disableMfaHandler
);

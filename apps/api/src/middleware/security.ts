import type { CookieOptions, NextFunction, Request, Response } from "express";
import { timingSafeEqual } from "node:crypto";
import { prisma } from "@aperio/db";
import { createOneTimeToken, hashOpaqueToken } from "@aperio/security";

export type AuthContext = {
  userId: string;
  organizationId: string;
  role: "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";
  sessionId: string | null;
  sessionToken: string;
};

export type TenantRequest = Request & {
  auth: AuthContext;
  tenantId: string;
};

export const SESSION_COOKIE_NAME = "aperio_session";

function sessionTtlMs() {
  return Number(process.env.APERIO_SESSION_TTL_HOURS ?? 12) * 60 * 60 * 1000;
}

function sessionIdleMs() {
  return Number(process.env.APERIO_SESSION_IDLE_MINUTES ?? 120) * 60 * 1000;
}

function tokenHashesMatch(rawToken: string, expectedHash: string) {
  const actual = Buffer.from(hashOpaqueToken(rawToken), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function parseCookieHeader(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};

  for (const part of (header ?? "").split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (!rawName || rawValue.length === 0) continue;
    cookies[rawName] = decodeURIComponent(rawValue.join("="));
  }

  return cookies;
}

function sessionTokenFromRequest(req: Request):
  | { token: string; source: "authorization" | "cookie" }
  | null {
  const authorization = req.header("authorization");
  if (authorization?.startsWith("Bearer ")) {
    return {
      token: authorization.slice("Bearer ".length),
      source: "authorization"
    };
  }

  const cookieToken = parseCookieHeader(req.header("cookie"))[SESSION_COOKIE_NAME];
  return cookieToken ? { token: cookieToken, source: "cookie" } : null;
}

function sessionCookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/"
  };
}

export function setSessionCookie(res: Response, token: string) {
  res.cookie(SESSION_COOKIE_NAME, token, {
    ...sessionCookieOptions(),
    maxAge: sessionTtlMs()
  });
}

export function clearSessionCookie(res: Response) {
  res.clearCookie(SESSION_COOKIE_NAME, sessionCookieOptions());
}

function allowedWebOrigins() {
  return (process.env.APERIO_WEB_ORIGIN ?? "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

function requestOrigin(req: Request) {
  const origin = req.header("origin");
  if (origin) return origin.replace(/\/$/, "");

  const referer = req.header("referer");
  if (!referer) return null;

  try {
    return new URL(referer).origin;
  } catch {
    return null;
  }
}

function isUnsafeMethod(method: string) {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

function hasAllowedCookieOrigin(req: Request) {
  const origin = requestOrigin(req);
  return !!origin && allowedWebOrigins().includes(origin);
}

function clientIp(req: Request) {
  return req.ip?.slice(0, 64) ?? null;
}

function clientUserAgent(req: Request) {
  const userAgent = req.header("user-agent");
  return userAgent ? userAgent.slice(0, 255) : null;
}

function allowInsecureDemoAuth(): boolean {
  return process.env.APERIO_ALLOW_INSECURE_DEMO_AUTH === "true";
}

function getDevelopmentAuthContext(): AuthContext {
  if (process.env.NODE_ENV === "production" || !allowInsecureDemoAuth()) {
    throw new Error("Missing bearer token");
  }

  return {
    userId: process.env.DEMO_USER_ID ?? "usr_demo_000000000000000000000001",
    organizationId:
      process.env.DEMO_ORGANIZATION_ID ?? "org_demo_000000000000000000000001",
    role: "OWNER",
    sessionId: null,
    sessionToken: "development-demo-session"
  };
}

export async function issueSessionToken(input: {
  organizationId: string;
  userId: string;
  role: AuthContext["role"];
  mfaVerified: boolean;
  req: Request;
}) {
  const { token, tokenHash } = createOneTimeToken();
  const session = await prisma.userSession.create({
    data: {
      organizationId: input.organizationId,
      userId: input.userId,
      tokenHash,
      expiresAt: new Date(Date.now() + sessionTtlMs()),
      lastSeenAt: new Date(),
      mfaVerifiedAt: input.mfaVerified ? new Date() : null,
      lastIpAddress: clientIp(input.req),
      lastUserAgent: clientUserAgent(input.req)
    }
  });

  return `${session.id}.${token}`;
}

export async function revokeSession(sessionId: string | null | undefined) {
  if (!sessionId) {
    return;
  }

  await prisma.userSession.updateMany({
    where: {
      id: sessionId,
      revokedAt: null
    },
    data: {
      revokedAt: new Date()
    }
  });
}

async function verifySessionToken(token: string, req: Request): Promise<AuthContext> {
  const [sessionId, rawToken] = token.split(".");

  if (!sessionId || !rawToken) {
    throw new Error("Invalid session token");
  }

  const session = await prisma.userSession.findUnique({
    where: { id: sessionId },
    include: {
      user: {
        include: {
          role: { select: { name: true } },
          organization: { select: { id: true } }
        }
      }
    }
  });

  if (
    !session ||
    session.revokedAt ||
    session.expiresAt.getTime() <= Date.now() ||
    !session.user.isActive ||
    !tokenHashesMatch(rawToken, session.tokenHash)
  ) {
    throw new Error("Invalid session");
  }

  if (session.user.mfaEnabled && !session.mfaVerifiedAt) {
    await revokeSession(session.id);
    throw new Error("MFA verification required");
  }

  if (session.lastSeenAt.getTime() + sessionIdleMs() <= Date.now()) {
    await revokeSession(session.id);
    throw new Error("Session expired");
  }

  if (Date.now() - session.lastSeenAt.getTime() > 60 * 1000) {
    await prisma.userSession.update({
      where: { id: session.id },
      data: {
        lastSeenAt: new Date(),
        lastIpAddress: clientIp(req),
        lastUserAgent: clientUserAgent(req)
      }
    });
  }

  return {
    userId: session.user.id,
    organizationId: session.user.organization.id,
    role: session.user.role.name,
    sessionId: session.id,
    sessionToken: token
  };
}

function hasClientTenantOverride(req: Request): boolean {
  const queryTenant =
    typeof req.query.organizationId === "string" ||
    typeof req.query.organization_id === "string" ||
    typeof req.query.tenantId === "string" ||
    typeof req.query.tenant_id === "string";
  const body = req.body as Record<string, unknown> | undefined;
  const bodyTenant =
    !!body &&
    ["organizationId", "organization_id", "tenantId", "tenant_id"].some(
      (key) => Object.prototype.hasOwnProperty.call(body, key)
    );

  return queryTenant || bodyTenant;
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const tokenSource = sessionTokenFromRequest(req);

    if (!tokenSource) {
      (req as TenantRequest).auth = getDevelopmentAuthContext();
      return next();
    }

    if (
      tokenSource.source === "cookie" &&
      isUnsafeMethod(req.method) &&
      !hasAllowedCookieOrigin(req)
    ) {
      return res.status(403).json({ error: "Invalid request origin" });
    }

    (req as TenantRequest).auth = await verifySessionToken(tokenSource.token, req);
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

export function requireTenant(req: Request, res: Response, next: NextFunction) {
  const tenantReq = req as TenantRequest;

  if (!tenantReq.auth?.organizationId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (hasClientTenantOverride(req)) {
    return res.status(400).json({
      error:
        "Tenant context is derived from the authenticated principal and cannot be supplied by the client"
    });
  }

  tenantReq.tenantId = tenantReq.auth.organizationId;
  return next();
}

export function requireRole(
  allowedRoles: ReadonlyArray<AuthContext["role"]>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    const { role } = (req as TenantRequest).auth;

    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ error: "Insufficient privileges" });
    }

    return next();
  };
}

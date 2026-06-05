import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import test, { after, before } from "node:test";
import type { Server } from "node:http";
import { prisma } from "@aperio/db";
import { createApp } from "../apps/api/src/app";

let server: Server;
let baseUrl = "";
const organizationIds = new Set<string>();

async function requestJson(
  path: string,
  init?: RequestInit
): Promise<{ status: number; body: any }> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {})
    }
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null
  };
}

async function signupWorkspace(label: string) {
  const slug = `test-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const ownerEmail = `${slug}@example.test`;
  const response = await requestJson("/api/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({
      organizationName: `Tenant ${label}`,
      organizationSlug: slug,
      ownerEmail,
      password: "StrongPass123"
    })
  });

  assert.equal(response.status, 201);
  organizationIds.add(response.body.data.organization.id);
  return {
    ...response.body.data,
    ownerEmail
  } as {
    token: string;
    ownerEmail: string;
    organization: { id: string; slug: string };
  };
}

before(async () => {
  const app = createApp();
  server = app.listen(0);
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });

  if (organizationIds.size > 0) {
    await prisma.organization.deleteMany({
      where: {
        id: {
          in: [...organizationIds]
        }
      }
    });
  }

  await prisma.$disconnect();
});

test("rejects client-supplied tenant overrides", async () => {
  const session = await signupWorkspace("override");
  const response = await requestJson(
    "/api/v1/admin/settings?organizationId=org_other",
    {
      headers: {
        authorization: `Bearer ${session.token}`
      }
    }
  );

  assert.equal(response.status, 400);
  assert.match(
    response.body.error,
    /tenant context is derived from the authenticated principal/i
  );
});

test("blocks cross-tenant password reset links", async () => {
  const tenantA = await signupWorkspace("alpha");
  const tenantB = await signupWorkspace("beta");

  const invited = await requestJson("/api/v1/admin/members", {
    method: "POST",
    headers: {
      authorization: `Bearer ${tenantB.token}`
    },
    body: JSON.stringify({
      email: `member-${Date.now()}@example.test`,
      roleName: "VIEWER"
    })
  });

  assert.equal(invited.status, 201);

  const response = await requestJson(
    `/api/v1/admin/members/${encodeURIComponent(invited.body.data.id)}/reset-link`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${tenantA.token}`
      },
      body: JSON.stringify({})
    }
  );

  assert.equal(response.status, 404);
  assert.equal(response.body.error, "User not found");
});

test("new password reset requests invalidate older links", async () => {
  const owner = await signupWorkspace("reset-reissue");

  const first = await requestJson("/api/v1/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify({
      organizationSlug: owner.organization.slug,
      email: owner.ownerEmail
    })
  });

  assert.equal(first.status, 202);
  assert.ok(first.body.data.resetUrl);

  const firstToken = new URL(first.body.data.resetUrl).searchParams.get("token");
  assert.ok(firstToken);

  const second = await requestJson("/api/v1/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify({
      organizationSlug: owner.organization.slug,
      email: owner.ownerEmail
    })
  });

  assert.equal(second.status, 202);
  assert.ok(second.body.data.resetUrl);

  const secondToken = new URL(second.body.data.resetUrl).searchParams.get("token");
  assert.ok(secondToken);
  assert.notEqual(firstToken, secondToken);

  const staleReset = await requestJson("/api/v1/auth/reset-password", {
    method: "POST",
    body: JSON.stringify({
      token: firstToken,
      password: "RotatedPassword123!"
    })
  });

  assert.equal(staleReset.status, 400);
  assert.match(staleReset.body.error, /invalid or expired/i);

  const latestReset = await requestJson("/api/v1/auth/reset-password", {
    method: "POST",
    body: JSON.stringify({
      token: secondToken,
      password: "RotatedPassword456!"
    })
  });

  assert.equal(latestReset.status, 200);
});

test("blocks viewers from organization settings APIs", async () => {
  const owner = await signupWorkspace("viewer-role");

  const invited = await requestJson("/api/v1/admin/members", {
    method: "POST",
    headers: {
      authorization: `Bearer ${owner.token}`
    },
    body: JSON.stringify({
      email: `viewer-${Date.now()}@example.test`,
      roleName: "VIEWER"
    })
  });

  assert.equal(invited.status, 201);
  assert.ok(invited.body.invitation.url);

  const token = new URL(invited.body.invitation.url).searchParams.get("token");
  assert.ok(token);

  const accepted = await requestJson("/api/v1/auth/invitations/accept", {
    method: "POST",
    body: JSON.stringify({
      token,
      password: "ViewerPass123"
    })
  });

  assert.equal(accepted.status, 200);

  const response = await requestJson("/api/v1/admin/settings", {
    headers: {
      authorization: `Bearer ${accepted.body.data.token}`
    }
  });

  assert.equal(response.status, 403);
  assert.equal(response.body.error, "Insufficient privileges");
});

import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import test, { after, before } from "node:test";
import { prisma } from "@aperio/db";
import { createApp } from "../apps/api/src/app";
import { SESSION_COOKIE_NAME } from "../apps/api/src/middleware/security";

let server: Server;
let baseUrl = "";
const organizationIds = new Set<string>();

async function requestJson(
  path: string,
  init?: RequestInit
): Promise<{ status: number; body: any; headers: Headers }> {
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
    body: text ? JSON.parse(text) : null,
    headers: response.headers
  };
}

function cookiePair(setCookie: string) {
  return setCookie.split(";")[0]!;
}

async function signupWorkspace(label: string) {
  const slug = `cookie-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const response = await requestJson("/api/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({
      organizationName: `Cookie ${label}`,
      organizationSlug: slug,
      ownerEmail: `${slug}@example.test`,
      password: "TestPass1234!"
    })
  });

  assert.equal(response.status, 201);
  organizationIds.add(response.body.data.organization.id);

  return {
    token: response.body.data.token as string,
    cookie: cookiePair(response.headers.get("set-cookie") ?? ""),
    setCookie: response.headers.get("set-cookie") ?? ""
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

test("issues an HttpOnly session cookie and accepts cookie-backed reads", async () => {
  const session = await signupWorkspace("read");

  assert.match(session.setCookie, new RegExp(`^${SESSION_COOKIE_NAME}=`));
  assert.match(session.setCookie, /HttpOnly/i);
  assert.match(session.setCookie, /SameSite=Lax/i);

  const me = await requestJson("/api/v1/auth/me", {
    headers: {
      cookie: session.cookie
    }
  });

  assert.equal(me.status, 200);
  assert.equal(me.body.data.token, session.token);
});

test("keeps bearer auth compatibility while guarding cookie-backed writes", async () => {
  const session = await signupWorkspace("write");

  const bearerMe = await requestJson("/api/v1/auth/me", {
    headers: {
      authorization: `Bearer ${session.token}`
    }
  });

  assert.equal(bearerMe.status, 200);

  const rejectedLogout = await requestJson("/api/v1/auth/logout", {
    method: "POST",
    headers: {
      cookie: session.cookie
    }
  });

  assert.equal(rejectedLogout.status, 403);

  const logout = await requestJson("/api/v1/auth/logout", {
    method: "POST",
    headers: {
      cookie: session.cookie,
      origin: "http://localhost:3000"
    }
  });

  assert.equal(logout.status, 200);
  assert.match(logout.headers.get("set-cookie") ?? "", /Expires=Thu, 01 Jan 1970/i);

  const revokedMe = await requestJson("/api/v1/auth/me", {
    headers: {
      cookie: session.cookie
    }
  });

  assert.equal(revokedMe.status, 401);
});

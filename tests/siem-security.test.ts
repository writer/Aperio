import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import test, { after, before } from "node:test";
import { prisma } from "@aperio/db";
import { resolveSiemExportRoot } from "@aperio/shared/siem-security";
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
  const slug = `siem-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const ownerEmail = `${slug}@example.test`;
  const response = await requestJson("/api/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({
      organizationName: `Tenant ${label}`,
      organizationSlug: slug,
      ownerEmail,
      password: "ValidPassword123"
    })
  });

  assert.equal(response.status, 201);
  organizationIds.add(response.body.data.organization.id);

  return response.body.data as {
    token: string;
    organization: { id: string };
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

test("rejects SIEM endpoints that target private addresses", async () => {
  const session = await signupWorkspace("private-endpoint");

  const response = await requestJson("/api/v1/siem", {
    method: "POST",
    headers: {
      authorization: `Bearer ${session.token}`
    },
    body: JSON.stringify({
      kind: "GENERIC_WEBHOOK",
      name: "Loopback webhook",
      endpointUrl: "https://127.0.0.1/ingest",
      streams: ["FINDINGS"]
    })
  });

  assert.equal(response.status, 400);
  assert.match(response.body.error, /private|loopback/i);
});

test("rejects SIEM file paths outside the export directory", async () => {
  const session = await signupWorkspace("outside-path");

  const response = await requestJson("/api/v1/siem", {
    method: "POST",
    headers: {
      authorization: `Bearer ${session.token}`
    },
    body: JSON.stringify({
      kind: "JSON_FILE",
      name: "Unsafe file",
      filePath: "/tmp/outside.jsonl",
      streams: ["FINDINGS"]
    })
  });

  assert.equal(response.status, 400);
  assert.match(response.body.error, /must stay within/i);
});

test("normalizes safe SIEM file paths into the export directory", async () => {
  const session = await signupWorkspace("safe-path");

  const response = await requestJson("/api/v1/siem", {
    method: "POST",
    headers: {
      authorization: `Bearer ${session.token}`
    },
    body: JSON.stringify({
      kind: "JSON_FILE",
      name: "Safe file",
      filePath: "tenant-safe/findings.jsonl",
      streams: ["FINDINGS"]
    })
  });

  assert.equal(response.status, 201);
  assert.ok(response.body.data.filePath);
  assert.equal(
    response.body.data.filePath,
    `${resolveSiemExportRoot()}/tenant-safe/findings.jsonl`
  );
});

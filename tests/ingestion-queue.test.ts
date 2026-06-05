import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import test, { after, before } from "node:test";
import { prisma } from "@aperio/db";
import { encryptString } from "@aperio/security";
import { createApp } from "../apps/api/src/app";
import { drainIngestionJobs } from "../workers/ingestion-worker";

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
  const slug = `ingestion-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const response = await requestJson("/api/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({
      organizationName: `Ingestion ${label}`,
      organizationSlug: slug,
      ownerEmail: `${slug}@example.test`,
      password: "TestPass1234!"
    })
  });

  assert.equal(response.status, 201);
  organizationIds.add(response.body.data.organization.id);

  return response.body.data as {
    token: string;
    organization: { id: string };
  };
}

async function createGithubIntegration(organizationId: string) {
  const externalAccountId = `github-${Date.now()}`;
  return prisma.integrationConnection.create({
    data: {
      organizationId,
      provider: "GITHUB",
      displayName: "GitHub",
      externalAccountId,
      encryptedAccessToken: encryptString(
        "github-token-value",
        `${organizationId}:GITHUB:${externalAccountId}:access_token`
      ),
      status: "CONNECTED"
    }
  });
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

test("persists ingestion jobs and drains them into findings", async () => {
  const session = await signupWorkspace("durable");
  const integration = await createGithubIntegration(session.organization.id);

  const response = await requestJson("/api/v1/ingestion/events", {
    method: "POST",
    headers: {
      authorization: `Bearer ${session.token}`
    },
    body: JSON.stringify({
      integrationId: integration.id,
      provider: "GITHUB",
      eventType: "repository.publicized",
      source: "github.audit",
      actor: "owner@example.test",
      payload: {
        repository: {
          full_name: "writer/public-demo",
          private: false,
          visibility: "public"
        }
      }
    })
  });

  assert.equal(response.status, 202);
  assert.equal(response.body.data.status, "queued");

  const queued = await prisma.ingestionJob.findUniqueOrThrow({
    where: { id: response.body.data.jobId }
  });
  assert.equal(queued.status, "QUEUED");

  const drained = await drainIngestionJobs();
  assert.equal(drained.processed, 1);
  assert.equal(drained.succeeded, 1);

  const completed = await prisma.ingestionJob.findUniqueOrThrow({
    where: { id: queued.id }
  });
  assert.equal(completed.status, "SUCCEEDED");
  assert.equal(completed.attempts, 1);
  assert.ok(completed.processedAt);

  const finding = await prisma.securityFinding.findFirst({
    where: {
      organizationId: session.organization.id,
      title: "Public GitHub repository created"
    }
  });
  assert.ok(finding);
  assert.equal(finding.severity, "CRITICAL");
});

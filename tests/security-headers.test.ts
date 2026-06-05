import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import test, { after, before } from "node:test";
import { createApp } from "../apps/api/src/app";

let server: Server;
let baseUrl = "";

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
});

test("sets a restrictive API content security policy", async () => {
  const response = await fetch(`${baseUrl}/healthz`);
  const csp = response.headers.get("content-security-policy");

  assert.equal(response.status, 200);
  assert.ok(csp);
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
});

test("rejects disallowed CORS origins without a server error", async () => {
  const response = await fetch(`${baseUrl}/healthz`, {
    headers: {
      origin: "https://attacker.example"
    }
  });
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Origin not allowed by CORS");
});

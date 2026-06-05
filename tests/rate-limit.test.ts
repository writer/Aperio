import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import test, { after, before } from "node:test";
import { createMemoryRateLimit } from "../apps/api/src/middleware/rate-limit";

let server: Server;
let baseUrl = "";

before(async () => {
  const app = express();
  app.get(
    "/limited",
    createMemoryRateLimit({
      windowMs: 60_000,
      max: 1,
      message: "Too many requests"
    }),
    (_req, res) => res.json({ ok: true })
  );

  server = app.listen(0);
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

test("rate limiter emits limit metadata and rejects excess requests", async () => {
  const first = await fetch(`${baseUrl}/limited`);
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("x-ratelimit-limit"), "1");
  assert.equal(first.headers.get("x-ratelimit-remaining"), "0");

  const second = await fetch(`${baseUrl}/limited`);
  assert.equal(second.status, 429);
  assert.equal(second.headers.get("x-ratelimit-limit"), "1");
  assert.equal(second.headers.get("x-ratelimit-remaining"), "0");
  assert.ok(second.headers.get("retry-after"));
  assert.deepEqual(await second.json(), { error: "Too many requests" });
});

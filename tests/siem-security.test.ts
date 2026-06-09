import assert from "node:assert/strict";
import test from "node:test";

import { validateSiemEndpointUrl } from "../packages/shared/src/siem-security";

test("SIEM endpoint validation allows public IPv6 literals and blocks local IPv6", () => {
  for (const endpoint of [
    "https://[2001:4860:4860::8888]/hook",
    "https://[::ffff:8.8.8.8]/hook"
  ]) {
    assert.equal(validateSiemEndpointUrl(endpoint), null);
  }

  for (const endpoint of [
    "https://[::1]/hook",
    "https://[::ffff:127.0.0.1]/hook",
    "https://[fc00::1]/hook",
    "https://[fe80::1]/hook"
  ]) {
    assert.match(
      validateSiemEndpointUrl(endpoint) ?? "",
      /loopback, local, or private/
    );
  }
});

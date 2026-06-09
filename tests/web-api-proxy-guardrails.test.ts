import { readFileSync } from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

// The Go API emits relative URLs (e.g. /api/v1/admin/reports/<id>/html)
// for static-streaming endpoints like report artifacts. The browser at
// the Next dev origin (localhost:3000) needs those to land on the Go API
// at localhost:4100, which only works if Next proxies /api/v1/* via its
// dev rewrites. Without the proxy, report previews / downloads silently
// 404 (and iframes also break CSP `default-src 'self'` if we tried to
// switch to cross-origin absolute URLs instead).
test("next.config.mjs proxies /api/v1/* to the Go API", () => {
  const config = readRepoFile("apps/web/next.config.mjs");
  assert.match(
    config,
    /async\s+rewrites\s*\(\s*\)\s*\{[\s\S]*?source:\s*["']\/api\/v1\/:path\*["'][\s\S]*?destination:\s*`?\$\{apiProxyTarget\}\/api\/v1\/:path\*`?/,
    "expected an async rewrites() with /api/v1/:path* → apiProxyTarget rewrite"
  );
  assert.match(
    config,
    /const\s+apiProxyTarget\s*=\s*\(\s*process\.env\.APERIO_API_PROXY_TARGET[\s\S]*?process\.env\.NEXT_PUBLIC_CONNECT_API_BASE_URL[\s\S]*?["']http:\/\/localhost:4100["']/,
    "apiProxyTarget must fall through APERIO_API_PROXY_TARGET → NEXT_PUBLIC_CONNECT_API_BASE_URL → http://localhost:4100"
  );
});

test(".env.example documents APERIO_API_PROXY_TARGET", () => {
  const env = readRepoFile(".env.example");
  assert.match(
    env,
    /APERIO_API_PROXY_TARGET=/,
    "APERIO_API_PROXY_TARGET must be in .env.example so contributors discover the override"
  );
});

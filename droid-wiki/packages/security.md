# Security package

Active contributors: unavailable in this checkout because git history is missing.

The `security` package is small and focused. It exports the TypeScript encryption helpers used by allowed frontend/test/tooling surfaces, while Go runtime paths use the matching primitives in `internal/runtimeutil`. Together they protect every stored integration token and SIEM credential in the repo.

## Directory layout

```text
packages/security/
└── src/
    ├── crypto.ts
    └── index.ts
```

## Key abstractions

| File | Purpose |
| --- | --- |
| `packages/security/src/crypto.ts` | AES-256-GCM encrypt/decrypt helpers with record-bound AAD |
| `packages/security/src/index.ts` | Re-export surface |

## How it works

`packages/security/src/crypto.ts` and `internal/runtimeutil` derive a 32-byte key from `APERIO_ENCRYPTION_KEY`, support the same key encodings, and store ciphertext as a base64url-encoded JSON envelope. The caller passes additional authenticated data so the ciphertext is bound to a tenant- and record-specific context; missing keys, malformed envelopes, wrong AAD, and tampered tags fail closed.

## Key source files

| File | Purpose |
| --- | --- |
| `packages/security/src/crypto.ts` | Key resolution, envelope format, encrypt/decrypt implementation |
| `internal/runtimeutil/credentials.go` | Go-owned envelope, AAD, key resolution, and decrypt/encrypt primitives |
| `internal/bootstrap/compat_api.go` | Encrypts connector credentials before saving through Go compatibility handlers |
| `internal/bootstrap/compat_api.go` | Encrypts SIEM credentials before saving through Go compatibility handlers |
| `internal/ingestionworker` | Decrypts integration tokens before event processing |
| `internal/siemdispatcher` | Decrypts SIEM tokens before delivery |
| `internal/mcpbroker` | Redacts shared-secret and runtime errors for stdio tool calls |

## Integration points

The TypeScript package is imported almost entirely at trust boundaries in allowed frontend/test/tooling code. Go API, worker, SIEM, and MCP runtime paths use `internal/runtimeutil` for the same envelope and AAD contract, decrypting only at the point they need a provider or destination secret and redacting errors before they reach logs or client-visible output.

## Entry points for modification

Only change `packages/security/src/crypto.ts` if you are prepared to touch every stored secret format in the system. If you need a new secret-bearing feature, prefer reusing the same envelope and AAD pattern rather than adding a second encryption scheme.

For the broader trust model, go to [Security](../security.md). For environment variables that feed this package, go to [Configuration](../reference/configuration.md).

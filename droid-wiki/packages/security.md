# Security package

Active contributors: unavailable in this checkout because git history is missing.

The `security` package is small and focused. It only exports encryption helpers, but those helpers protect every stored integration token and SIEM credential in the repo.

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

`packages/security/src/crypto.ts` derives a 32-byte key from `APERIO_ENCRYPTION_KEY`, supports raw base64, base64url, hex, or passphrase forms, and stores ciphertext as a base64url-encoded JSON envelope. The caller can pass additional authenticated data so the ciphertext is bound to a tenant- and record-specific context.

## Key source files

| File | Purpose |
| --- | --- |
| `packages/security/src/crypto.ts` | Key resolution, envelope format, encrypt/decrypt implementation |
| `internal/bootstrap/compat_api.go` | Encrypts connector credentials before saving through Go compatibility handlers |
| `internal/bootstrap/compat_api.go` | Encrypts SIEM credentials before saving through Go compatibility handlers |
| `workers/ingestion-worker.ts` | Decrypts integration tokens before event processing |
| `workers/siem-dispatcher.ts` | Decrypts SIEM tokens before delivery |

## Integration points

This package is imported almost entirely at trust boundaries. Routes encrypt before writing to Prisma, and workers decrypt only at the point they need to talk to an external service.

## Entry points for modification

Only change `packages/security/src/crypto.ts` if you are prepared to touch every stored secret format in the system. If you need a new secret-bearing feature, prefer reusing the same envelope and AAD pattern rather than adding a second encryption scheme.

For the broader trust model, go to [Security](../security.md). For environment variables that feed this package, go to [Configuration](../reference/configuration.md).

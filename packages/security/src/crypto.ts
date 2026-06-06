import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const KEY_BYTES = 32;

type EncryptedEnvelope = {
  version: 1;
  algorithm: typeof ALGORITHM;
  iv: string;
  tag: string;
  ciphertext: string;
};

function decodeBase64Url(value: string): Buffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64");
}

function resolveKey(rawKey = process.env.APERIO_ENCRYPTION_KEY): Buffer {
  if (!rawKey) {
    throw new Error("APERIO_ENCRYPTION_KEY is required");
  }

  const trimmed = rawKey.trim();
  const hasExplicitEncoding =
    trimmed.startsWith("base64:") ||
    trimmed.startsWith("base64url:") ||
    trimmed.startsWith("hex:");
  if (!hasExplicitEncoding && process.env.NODE_ENV === "production") {
    throw new Error(
      "APERIO_ENCRYPTION_KEY must use base64:, base64url:, or hex: encoding in production"
    );
  }
  const key = trimmed.startsWith("base64:")
    ? Buffer.from(trimmed.slice("base64:".length), "base64")
    : trimmed.startsWith("base64url:")
      ? decodeBase64Url(trimmed.slice("base64url:".length))
      : trimmed.startsWith("hex:")
        ? Buffer.from(trimmed.slice("hex:".length), "hex")
        : scryptSync(trimmed, "aperio-token-vault", KEY_BYTES);

  if (key.length !== KEY_BYTES) {
    throw new Error("APERIO_ENCRYPTION_KEY must resolve to exactly 32 bytes");
  }

  return key;
}

function aadBuffer(additionalAuthenticatedData?: string): Buffer | undefined {
  return additionalAuthenticatedData
    ? Buffer.from(additionalAuthenticatedData, "utf8")
    : undefined;
}

export function encryptString(
  plaintext: string,
  additionalAuthenticatedData?: string
): string {
  if (plaintext.length === 0) {
    throw new Error("Cannot encrypt an empty string");
  }

  const key = resolveKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTES
  });
  const aad = aadBuffer(additionalAuthenticatedData);

  if (aad) {
    cipher.setAAD(aad);
  }

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final()
  ]);
  const envelope: EncryptedEnvelope = {
    version: 1,
    algorithm: ALGORITHM,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url")
  };

  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

export function decryptString(
  encryptedValue: string,
  additionalAuthenticatedData?: string
): string {
  let envelope: EncryptedEnvelope;

  try {
    envelope = JSON.parse(
      decodeBase64Url(encryptedValue).toString("utf8")
    ) as EncryptedEnvelope;
  } catch {
    throw new Error("Encrypted value is malformed");
  }

  if (envelope.version !== 1 || envelope.algorithm !== ALGORITHM) {
    throw new Error("Unsupported encrypted value version or algorithm");
  }

  const key = resolveKey();
  const decipher = createDecipheriv(
    ALGORITHM,
    key,
    decodeBase64Url(envelope.iv),
    { authTagLength: AUTH_TAG_BYTES }
  );
  const aad = aadBuffer(additionalAuthenticatedData);

  if (aad) {
    decipher.setAAD(aad);
  }

  decipher.setAuthTag(decodeBase64Url(envelope.tag));

  try {
    return Buffer.concat([
      decipher.update(decodeBase64Url(envelope.ciphertext)),
      decipher.final()
    ]).toString("utf8");
  } catch {
    throw new Error("Encrypted value authentication failed");
  }
}

const PASSWORD_HASH_VERSION = "s2";
const PASSWORD_SALT_BYTES = 16;
const DEFAULT_SCRYPT_N = 16384;
const DEFAULT_SCRYPT_R = 8;
const DEFAULT_SCRYPT_P = 1;
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function hashPassword(password: string): string {
  if (password.length < 12) {
    throw new Error("Password must be at least 12 characters");
  }

  const salt = randomBytes(PASSWORD_SALT_BYTES);
  const params = passwordScryptParams();
  const derivedKey = scryptSync(password, salt, KEY_BYTES, params);
  return [
    PASSWORD_HASH_VERSION,
    String(params.N),
    String(params.r),
    String(params.p),
    salt.toString("base64url"),
    derivedKey.toString("base64url")
  ].join("$");
}

export function verifyPassword(password: string, passwordHash: string): boolean {
  const [version, ...parts] = passwordHash.split("$");
  const legacy = version === "s1";
  const saltPart = legacy ? parts[0] : parts[3];
  const hashPart = legacy ? parts[1] : parts[4];

  if (!saltPart || !hashPart || (version !== "s1" && version !== "s2")) {
    throw new Error("Unsupported password hash format");
  }

  const expected = decodeBase64Url(hashPart);
  const actual = scryptSync(
    password,
    decodeBase64Url(saltPart),
    KEY_BYTES,
    legacy
      ? undefined
      : {
          N: Number(parts[0]),
          r: Number(parts[1]),
          p: Number(parts[2])
        }
  );

  return (
    expected.length === actual.length &&
    timingSafeEqual(expected, actual)
  );
}

function passwordScryptParams() {
  const N = Number(process.env.APERIO_PASSWORD_SCRYPT_N ?? DEFAULT_SCRYPT_N);
  const r = Number(process.env.APERIO_PASSWORD_SCRYPT_R ?? DEFAULT_SCRYPT_R);
  const p = Number(process.env.APERIO_PASSWORD_SCRYPT_P ?? DEFAULT_SCRYPT_P);
  return {
    N: Number.isInteger(N) && N > 1 ? N : DEFAULT_SCRYPT_N,
    r: Number.isInteger(r) && r > 0 ? r : DEFAULT_SCRYPT_R,
    p: Number.isInteger(p) && p > 0 ? p : DEFAULT_SCRYPT_P
  };
}

export function createOneTimeToken(): { token: string; tokenHash: string } {
  const token = randomBytes(32).toString("base64url");
  return {
    token,
    tokenHash: createHash("sha256").update(token).digest("hex")
  };
}

export function hashOpaqueToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function encodeBase32(input: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function decodeBase32(value: string): Buffer {
  const normalized = value
    .toUpperCase()
    .replace(/=+$/g, "")
    .replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let current = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);

    if (index < 0) {
      continue;
    }

    current = (current << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

function hotp(secret: Buffer, counter: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const code =
    (((digest[offset]! & 0x7f) << 24) |
      ((digest[offset + 1]! & 0xff) << 16) |
      ((digest[offset + 2]! & 0xff) << 8) |
      (digest[offset + 3]! & 0xff)) %
    10 ** TOTP_DIGITS;

  return code.toString().padStart(TOTP_DIGITS, "0");
}

export function createTotpSecret() {
  return encodeBase32(randomBytes(20));
}

export function buildTotpOtpAuthUrl(input: {
  issuer: string;
  accountName: string;
  secret: string;
}) {
  const label = `${input.issuer}:${input.accountName}`;
  const params = new URLSearchParams({
    secret: input.secret,
    issuer: input.issuer,
    algorithm: "SHA1",
    digits: String(TOTP_DIGITS),
    period: String(TOTP_STEP_SECONDS)
  });

  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

export function verifyTotpCode(
  secret: string,
  code: string,
  window = 1
): boolean {
  return verifyTotpCodeWithCounter(secret, code, { window }) !== null;
}

export function verifyTotpCodeWithCounter(
  secret: string,
  code: string,
  options?: {
    window?: number;
    afterCounter?: number | null;
  }
): { counter: number } | null {
  const normalizedCode = code.replace(/\s|-/g, "");

  if (!/^\d{6}$/.test(normalizedCode)) {
    return null;
  }

  const decodedSecret = decodeBase32(secret);
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  const window = options?.window ?? 1;
  const afterCounter = options?.afterCounter ?? null;

  for (let offset = -window; offset <= window; offset += 1) {
    const candidateCounter = counter + offset;
    if (
      (afterCounter === null || candidateCounter > afterCounter) &&
      hotp(decodedSecret, candidateCounter) === normalizedCode
    ) {
      return { counter: candidateCounter };
    }
  }

  return null;
}

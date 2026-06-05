import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { isAbsolute, relative, resolve, sep } from "node:path";

const defaultSiemExportRoot = resolve(process.cwd(), "var", "siem-exports");
const blockedHostnameSuffixes = [
  ".internal",
  ".local",
  ".localhost",
  ".localdomain",
  ".home.arpa"
];

function normalizeHostname(hostname: string) {
  return hostname.trim().replace(/\.$/, "").toLowerCase();
}

function isPrivateIpv4(address: string) {
  const octets = address.split(".").map((segment) => Number.parseInt(segment, 10));
  if (octets.length !== 4 || octets.some((octet) => Number.isNaN(octet))) {
    return true;
  }

  const [first, second, third] = octets;

  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0 && third === 0) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 192 && second === 168) ||
    (first === 198 && second === 18) ||
    (first === 198 && second === 19) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224
  );
}

function isPrivateIpv6(address: string) {
  const normalized = address.toLowerCase();

  if (normalized === "::" || normalized === "::1") {
    return true;
  }

  if (normalized.startsWith("::ffff:")) {
    return isPrivateIpv4(normalized.slice("::ffff:".length));
  }

  return (
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    /^fe[89ab]/.test(normalized) ||
    normalized.startsWith("2001:db8")
  );
}

function isPrivateIpAddress(address: string) {
  const family = isIP(address);
  if (family === 4) {
    return isPrivateIpv4(address);
  }
  if (family === 6) {
    return isPrivateIpv6(address);
  }
  return true;
}

function isBlockedHostname(hostname: string) {
  return (
    hostname === "localhost" ||
    hostname === "0.0.0.0" ||
    (!hostname.includes(".") && isIP(hostname) === 0) ||
    blockedHostnameSuffixes.some((suffix) => hostname.endsWith(suffix))
  );
}

function isWithinDirectory(parentDirectory: string, candidatePath: string) {
  const relativePath = relative(parentDirectory, candidatePath);

  return (
    relativePath.length > 0 &&
    relativePath !== ".." &&
    !relativePath.startsWith(`..${sep}`) &&
    !isAbsolute(relativePath)
  );
}

export function resolveSiemExportRoot() {
  const configuredRoot = process.env.APERIO_SIEM_EXPORT_DIR?.trim();
  return resolve(
    configuredRoot && configuredRoot.length > 0
      ? configuredRoot
      : defaultSiemExportRoot
  );
}

export function normalizeSiemFilePath(filePath: string) {
  const exportRoot = resolveSiemExportRoot();
  const trimmedPath = filePath.trim();
  const candidatePath = resolve(
    isAbsolute(trimmedPath) ? trimmedPath : resolve(exportRoot, trimmedPath)
  );

  if (!isWithinDirectory(exportRoot, candidatePath)) {
    return {
      error: `File path must stay within ${exportRoot}`
    } as const;
  }

  return {
    absolutePath: candidatePath
  } as const;
}

export function validateSiemEndpointUrl(endpointUrl: string) {
  let parsed: URL;

  try {
    parsed = new URL(endpointUrl);
  } catch {
    return "Endpoint URL must be a valid absolute URL";
  }

  if (parsed.protocol !== "https:") {
    return "Endpoint URL must use HTTPS";
  }

  const hostname = normalizeHostname(parsed.hostname);
  if (!hostname) {
    return "Endpoint URL hostname is required";
  }

  if (isBlockedHostname(hostname)) {
    return "Endpoint URL must not target loopback, local, or private hosts";
  }

  if (isIP(hostname) !== 0 && isPrivateIpAddress(hostname)) {
    return "Endpoint URL must not target loopback, local, or private hosts";
  }

  return null;
}

export async function assertSafeSiemEndpointUrl(endpointUrl: string) {
  const validationError = validateSiemEndpointUrl(endpointUrl);
  if (validationError) {
    return validationError;
  }

  const hostname = normalizeHostname(new URL(endpointUrl).hostname);
  if (isIP(hostname) !== 0) {
    return null;
  }

  let records: Array<{ address: string; family: number }>;
  try {
    records = (await lookup(hostname, {
      all: true,
      verbatim: true
    })) as Array<{ address: string; family: number }>;
  } catch {
    return "Endpoint URL hostname could not be resolved";
  }

  if (records.length === 0) {
    return "Endpoint URL hostname could not be resolved";
  }

  if (records.some((record) => isPrivateIpAddress(record.address))) {
    return "Endpoint URL must not resolve to loopback or private addresses";
  }

  return null;
}

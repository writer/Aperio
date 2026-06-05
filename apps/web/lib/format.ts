export function formatRelative(iso: string | null | undefined) {
  if (!iso) return "—";
  const date = new Date(iso);
  const diffMs = date.getTime() - Date.now();
  const abs = Math.abs(diffMs);
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;

  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

  if (abs < minute) return rtf.format(Math.round(diffMs / 1000), "second");
  if (abs < hour) return rtf.format(Math.round(diffMs / minute), "minute");
  if (abs < day) return rtf.format(Math.round(diffMs / hour), "hour");
  if (abs < 30 * day) return rtf.format(Math.round(diffMs / day), "day");

  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: abs > 365 * day ? "numeric" : undefined
  }).format(date);
}

export function formatDateTime(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(iso));
}

export function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

export function providerLabel(provider: string) {
  return provider
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function findingUserLabel(
  evidence: Record<string, unknown> | null | undefined
): string | null {
  if (!evidence) return null;
  const actor = evidence.actor;
  if (typeof actor !== "string") return null;
  const trimmed = actor.trim();
  return trimmed.length > 0 ? trimmed : null;
}

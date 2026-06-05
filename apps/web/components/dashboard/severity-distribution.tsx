"use client";

import * as React from "react";
import type { Finding } from "../../lib/api";
import type { Severity } from "../ui/badge";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SEV_VAR: Record<Severity, string> = {
  CRITICAL: "hsl(var(--critical))",
  HIGH: "hsl(var(--destructive))",
  MEDIUM: "hsl(var(--warning))",
  LOW: "hsl(var(--muted-foreground) / 0.7)",
  INFO: "hsl(var(--muted-foreground) / 0.45)"
};

export function SeverityDistribution({
  findings,
  total
}: {
  findings: Finding[];
  total?: number;
}) {
  const counts = React.useMemo(() => {
    const tally: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };
    for (const f of findings) tally[f.severity] += 1;
    return tally;
  }, [findings]);

  const max = Math.max(1, ...ORDER.map((s) => counts[s]));
  const grandTotal = total ?? findings.length;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-baseline justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Open findings · by severity
        </p>
        <p className="font-mono text-xs text-muted-foreground tabular-nums">
          {grandTotal} total
        </p>
      </div>
      <ul className="flex flex-col gap-2.5" role="list">
        {ORDER.map((sev) => {
          const value = counts[sev];
          const pct = (value / max) * 100;
          return (
            <li
              key={sev}
              className="grid grid-cols-[72px_1fr_44px] items-center gap-3"
            >
              <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <span
                  aria-hidden
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ background: SEV_VAR[sev] }}
                />
                {sev}
              </span>
              <span
                className="relative h-2 overflow-hidden rounded-full bg-muted/70"
                aria-hidden
              >
                <span
                  className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-700 ease-out"
                  style={{
                    width: `${pct}%`,
                    background: SEV_VAR[sev],
                    boxShadow:
                      sev === "CRITICAL"
                        ? `0 0 14px -2px ${SEV_VAR.CRITICAL}`
                        : undefined
                  }}
                />
              </span>
              <span className="text-right font-mono text-sm text-foreground tabular-nums">
                {value}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

import * as React from "react";
import { cn } from "../../lib/utils";

export function BrandMark({
  className,
  ...props
}: React.SVGAttributes<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden
      className={cn("h-full w-full", className)}
      {...props}
    >
      <path
        d="M4 5.5 12 3l8 2.5v6.7c0 4.6-3.4 7.9-8 8.8-4.6-.9-8-4.2-8-8.8V5.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 12.2 11 14.7l4.6-5.3"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle
        cx="12"
        cy="12"
        r="9.6"
        stroke="currentColor"
        strokeOpacity="0.18"
        strokeDasharray="2 3"
      />
    </svg>
  );
}

export function BrandLockup({
  className,
  size = "default"
}: {
  className?: string;
  size?: "default" | "sm";
}) {
  const dim = size === "sm" ? "h-7 w-7" : "h-8 w-8";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 text-sm font-semibold tracking-tight text-foreground",
        className
      )}
    >
      <span
        className={cn(
          "relative flex items-center justify-center rounded-md border border-border bg-card text-signal",
          dim
        )}
      >
        <span className="absolute inset-0 rounded-md bg-signal/10" aria-hidden />
        <BrandMark className="relative h-4 w-4" />
      </span>
      <span>
        Aperio<span className="text-signal">.</span>
      </span>
    </span>
  );
}

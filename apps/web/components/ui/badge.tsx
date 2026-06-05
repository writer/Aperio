import * as React from "react";
import { cn } from "../../lib/utils";

type BadgeVariant =
  | "default"
  | "secondary"
  | "outline"
  | "success"
  | "warning"
  | "destructive"
  | "critical"
  | "signal";

const variantClasses: Record<BadgeVariant, string> = {
  default: "border-transparent bg-primary text-primary-foreground",
  secondary: "border-transparent bg-secondary text-secondary-foreground",
  outline: "text-foreground",
  success: "border-success/30 bg-success/15 text-success",
  warning: "border-warning/30 bg-warning/15 text-warning",
  destructive: "border-destructive/30 bg-destructive/15 text-destructive",
  critical:
    "border-critical/50 bg-critical/15 text-critical [text-shadow:0_0_18px_hsl(var(--critical)/0.45)]",
  signal: "border-signal/40 bg-signal/15 text-signal"
};

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

export function Badge({
  className,
  variant = "default",
  ...props
}: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium tracking-wide",
        variantClasses[variant],
        className
      )}
      {...props}
    />
  );
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const severityVariant: Record<Severity, BadgeVariant> = {
  CRITICAL: "critical",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "secondary",
  INFO: "outline"
};

const severityDotClass: Record<Severity, string> = {
  CRITICAL: "bg-critical critical-pulse",
  HIGH: "bg-destructive",
  MEDIUM: "bg-warning",
  LOW: "bg-muted-foreground/70",
  INFO: "bg-muted-foreground/60"
};

export function SeverityBadge({
  severity,
  className
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <Badge
      variant={severityVariant[severity]}
      className={cn("uppercase", className)}
      aria-label={`Severity ${severity.toLowerCase()}`}
    >
      <span
        aria-hidden
        className={cn(
          "inline-block h-1.5 w-1.5 rounded-full",
          severityDotClass[severity]
        )}
      />
      {severity}
    </Badge>
  );
}

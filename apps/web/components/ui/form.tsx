import * as React from "react";
import { AlertCircle, CheckCircle2 } from "lucide-react";
import { cn } from "../../lib/utils";
import { Input } from "./input";
import { Label } from "./label";

export { Input };

export function Field({
  label,
  htmlFor,
  hint,
  required,
  error,
  children
}: {
  label: string;
  htmlFor?: string;
  hint?: string;
  required?: boolean;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={htmlFor}>
        {label}
        {required ? (
          <span aria-hidden className="ml-0.5 text-destructive">
            *
          </span>
        ) : null}
      </Label>
      {children}
      {hint && !error ? (
        <p className="text-xs text-muted-foreground">{hint}</p>
      ) : null}
      {error ? (
        <p className="text-xs text-destructive">{error}</p>
      ) : null}
    </div>
  );
}

type Tone = "error" | "success" | "info";

export function FormBanner({
  tone = "info",
  children,
  className
}: {
  tone?: Tone;
  children?: React.ReactNode;
  className?: string;
}) {
  if (!children) return null;

  const toneClasses: Record<Tone, string> = {
    error: "border-destructive/30 bg-destructive/5 text-destructive",
    success: "border-success/30 bg-success/10 text-success",
    info: "border-border bg-muted text-foreground"
  };

  const Icon = tone === "success" ? CheckCircle2 : AlertCircle;

  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        "flex items-start gap-2 rounded-md border px-3 py-2 text-sm",
        toneClasses[tone],
        className
      )}
    >
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </div>
  );
}

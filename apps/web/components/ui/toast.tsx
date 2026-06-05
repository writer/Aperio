"use client";

import * as React from "react";
import { AlertCircle, CheckCircle2, X } from "lucide-react";
import { cn } from "../../lib/utils";

type ToastTone = "default" | "success" | "error";

type Toast = {
  id: string;
  title?: string;
  description?: string;
  tone?: ToastTone;
};

type ToastContextValue = {
  toast: (toast: Omit<Toast, "id">) => void;
};

const ToastContext = React.createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([]);

  const dismiss = React.useCallback((id: string) => {
    setToasts((prev) => prev.filter((entry) => entry.id !== id));
  }, []);

  const toast = React.useCallback(
    (next: Omit<Toast, "id">) => {
      const id =
        typeof crypto !== "undefined" && "randomUUID" in crypto
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random()}`;
      setToasts((prev) => [...prev, { ...next, id }]);
      window.setTimeout(() => dismiss(id), 5000);
    },
    [dismiss]
  );

  const value = React.useMemo<ToastContextValue>(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 right-4 z-[80] flex w-full max-w-sm flex-col gap-2"
      >
        {toasts.map((entry) => {
          const tone: ToastTone = entry.tone ?? "default";
          const toneClasses =
            tone === "success"
              ? "border-success/30 bg-background"
              : tone === "error"
                ? "border-destructive/30 bg-background"
                : "border-border bg-background";
          const Icon =
            tone === "success"
              ? CheckCircle2
              : tone === "error"
                ? AlertCircle
                : null;
          const iconColor =
            tone === "success"
              ? "text-success"
              : tone === "error"
                ? "text-destructive"
                : "text-muted-foreground";

          return (
            <div
              key={entry.id}
              className={cn(
                "pointer-events-auto flex items-start gap-3 rounded-md border px-4 py-3 shadow-sm",
                toneClasses
              )}
            >
              {Icon ? (
                <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", iconColor)} />
              ) : null}
              <div className="flex-1 text-sm">
                {entry.title ? (
                  <p className="font-medium text-foreground">{entry.title}</p>
                ) : null}
                {entry.description ? (
                  <p className="text-muted-foreground">{entry.description}</p>
                ) : null}
              </div>
              <button
                type="button"
                onClick={() => dismiss(entry.id)}
                className="rounded-sm text-muted-foreground transition-colors hover:text-foreground"
                aria-label="Dismiss notification"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = React.useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used within ToastProvider");
  }
  return ctx;
}

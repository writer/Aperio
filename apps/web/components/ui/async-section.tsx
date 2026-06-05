"use client";

import * as React from "react";
import { AlertTriangle } from "lucide-react";
import { cn } from "../../lib/utils";
import { Alert, AlertDescription, AlertTitle } from "./alert";
import { Button } from "./button";

type AsyncSectionProps<T> = {
  data: T | null;
  loading: boolean;
  error?: string;
  onRetry?: () => void;
  isEmpty?: (data: T) => boolean;
  skeleton: React.ReactNode;
  empty?: React.ReactNode;
  children: (data: T) => React.ReactNode;
  errorTitle?: string;
  className?: string;
};

export function AsyncSection<T>({
  data,
  loading,
  error,
  onRetry,
  isEmpty,
  skeleton,
  empty,
  children,
  errorTitle = "Something went wrong",
  className
}: AsyncSectionProps<T>) {
  if (loading && !data) {
    return <div className={className}>{skeleton}</div>;
  }
  if (error) {
    return (
      <div className={className}>
        <Alert variant="destructive" className="animate-fade-in-up">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>{errorTitle}</AlertTitle>
          <AlertDescription
            className={cn(
              "flex items-center gap-3",
              onRetry ? "justify-between" : undefined
            )}
          >
            <span>{error}</span>
            {onRetry ? (
              <Button variant="outline" size="sm" onClick={onRetry}>
                Retry
              </Button>
            ) : null}
          </AlertDescription>
        </Alert>
      </div>
    );
  }
  if (data && isEmpty && isEmpty(data)) {
    return <div className={className}>{empty ?? null}</div>;
  }
  if (!data) {
    return <div className={className}>{skeleton}</div>;
  }
  return <div className={className}>{children(data)}</div>;
}

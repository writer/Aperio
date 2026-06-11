"use client";

import * as React from "react";
import { Loader2, Search, ShieldAlert } from "lucide-react";
import {
  fetchIntegrationChecks,
  updateIntegrationChecks,
  type FindingCheckStatus,
  type IntegrationConnection
} from "../../lib/api";
import { SeverityBadge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import { Input } from "../ui/input";
import { Switch } from "../ui/switch";
import { useToast } from "../ui/toast";
import { cn } from "../../lib/utils";

type Props = {
  integration: IntegrationConnection | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved?: () => void;
};

export function FindingsDialog({ integration, open, onOpenChange, onSaved }: Props) {
  const { toast } = useToast();
  const [loading, setLoading] = React.useState(false);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [checks, setChecks] = React.useState<FindingCheckStatus[]>([]);
  const [enabledMap, setEnabledMap] = React.useState<Record<string, boolean>>({});
  const [query, setQuery] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open || !integration) return;
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    setQuery("");
    fetchIntegrationChecks(integration.id)
      .then((response) => {
        if (cancelled) return;
        setChecks(response.data.checks);
        const map: Record<string, boolean> = {};
        for (const check of response.data.checks) {
          map[check.key] = check.enabled;
        }
        setEnabledMap(map);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setLoadError(
          err instanceof Error ? err.message : "Unable to load findings"
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, integration]);

  const filteredChecks = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return checks;
    return checks.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.key.toLowerCase().includes(q)
    );
  }, [checks, query]);

  const dirty = React.useMemo(() => {
    return checks.some((c) => (enabledMap[c.key] ?? c.enabled) !== c.enabled);
  }, [checks, enabledMap]);

  const enabledCount = checks.filter(
    (c) => enabledMap[c.key] ?? c.enabled
  ).length;

  function toggle(key: string, next: boolean) {
    setEnabledMap((prev) => ({ ...prev, [key]: next }));
  }

  function resetToDefaults() {
    const map: Record<string, boolean> = {};
    for (const check of checks) {
      map[check.key] = check.defaultEnabled;
    }
    setEnabledMap(map);
  }

  async function save() {
    if (!integration) return;
    setSaving(true);
    try {
      const disabledChecks = checks
        .filter((c) => !(enabledMap[c.key] ?? c.enabled))
        .map((c) => c.key);
      await updateIntegrationChecks(integration.id, disabledChecks);
      toast({
        title: "Findings updated",
        description: `${enabledCount} of ${checks.length} checks enabled`,
        tone: "success"
      });
      onSaved?.();
      onOpenChange(false);
    } catch (err) {
      toast({
        title: "Unable to update findings",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" aria-hidden />
            Findings · {integration?.displayName ?? "Integration"}
          </DialogTitle>
          <DialogDescription>
            Toggle which built-in checks produce findings for this connector.
            Disabled checks auto-resolve open findings and stop firing on new
            events.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center justify-between gap-2">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search checks…"
              aria-label="Search checks"
              className="h-8 pl-7 text-xs"
            />
          </div>
          <span className="shrink-0 font-mono text-[11px] text-muted-foreground tabular-nums">
            {enabledCount} of {checks.length} enabled
          </span>
        </div>

        <div className="max-h-[420px] overflow-y-auto rounded-md border border-border bg-card/40">
          {loading ? (
            <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              Loading checks…
            </div>
          ) : loadError ? (
            <div className="px-4 py-6 text-sm text-destructive">{loadError}</div>
          ) : filteredChecks.length === 0 ? (
            <div className="px-4 py-6 text-sm text-muted-foreground">
              {checks.length === 0
                ? "No checks defined for this connector."
                : "No checks match this search."}
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {filteredChecks.map((check) => {
                const enabled = enabledMap[check.key] ?? check.enabled;
                const changed = enabled !== check.enabled;
                return (
                  <li
                    key={check.key}
                    className={cn(
                      "flex items-start gap-3 px-4 py-3 text-sm",
                      changed && "bg-signal/5"
                    )}
                  >
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-foreground">
                          {check.title}
                        </span>
                        <SeverityBadge severity={check.severityHint} />
                        {!check.defaultEnabled ? (
                          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                            opt-in
                          </span>
                        ) : null}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {check.description}
                      </p>
                      <p className="font-mono text-[10px] text-muted-foreground">
                        {check.key}
                      </p>
                    </div>
                    <Switch
                      checked={enabled}
                      onCheckedChange={(next) => toggle(check.key, next)}
                      aria-label={`Toggle ${check.title}`}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="flex items-center justify-between gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={resetToDefaults}
            disabled={loading || saving || checks.length === 0}
          >
            Reset to defaults
          </Button>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={() => void save()}
              disabled={!dirty || saving || loading}
            >
              {saving ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              ) : null}
              Save changes
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

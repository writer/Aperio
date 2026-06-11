"use client";

import * as React from "react";
import { Check, ChevronDown, Loader2 } from "lucide-react";
import { useAuth } from "../auth/auth-shell";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from "../ui/dropdown-menu";
import { useToast } from "../ui/toast";
import {
  fetchWorkspaces,
  switchWorkspace,
  type WorkspaceMembership
} from "../../lib/api";

export function WorkspaceSwitcher() {
  const { session, refreshSession } = useAuth();
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [workspaces, setWorkspaces] = React.useState<
    WorkspaceMembership[] | null
  >(null);
  const [loading, setLoading] = React.useState(false);
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);
  const [switchingSlug, setSwitchingSlug] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open || workspaces !== null || errorMessage) return;
    let cancelled = false;
    setLoading(true);
    setErrorMessage(null);
    fetchWorkspaces()
      .then((response) => {
        if (cancelled) return;
        setWorkspaces(response.data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setWorkspaces(null);
        setErrorMessage(
          err instanceof Error ? err.message : "Unable to load workspaces"
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, workspaces, errorMessage]);

  React.useEffect(() => {
    setWorkspaces(null);
  }, [session?.organization.id]);

  async function handleSwitch(workspace: WorkspaceMembership) {
    if (workspace.current || switchingSlug) return;
    const password =
      typeof window === "undefined"
        ? null
        : window.prompt(`Enter your password for ${workspace.name}`);
    if (password === null || password.trim() === "") return;
    const totpPrompt =
      typeof window === "undefined"
        ? null
        : window.prompt(
            "If this workspace requires MFA, enter your 6-digit code. Otherwise leave this blank."
          );
    const totpCode = totpPrompt?.trim() ?? "";
    setSwitchingSlug(workspace.slug);
    try {
      const response = await switchWorkspace({
        organizationSlug: workspace.slug,
        password,
        totpCode: totpCode || undefined
      });
      setOpen(false);
      setWorkspaces(null);
      if (typeof window !== "undefined") {
        window.location.assign("/");
        return;
      }
      await refreshSession();
      toast({
        title: `Switched to ${response.data.organization.name}`,
        tone: "success"
      });
    } catch (err) {
      toast({
        title: "Unable to switch workspace",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setSwitchingSlug(null);
    }
  }

  const currentName = session?.organization.name ?? "Workspace";

  function handleOpenChange(next: boolean) {
    if (next && errorMessage) {
      setWorkspaces(null);
      setErrorMessage(null);
    }
    setOpen(next);
  }

  return (
    <DropdownMenu open={open} onOpenChange={handleOpenChange}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          aria-label="Switch workspace"
          className="h-8 gap-2 border-foreground bg-foreground px-2.5 text-background shadow-sm hover:bg-foreground/90 hover:text-background"
        >
          <span className="flex min-w-0 flex-col items-start leading-tight">
            <span className="text-[9px] font-medium uppercase tracking-wider opacity-70">
              Workspace
            </span>
            <span className="max-w-[160px] truncate text-xs font-semibold">
              {currentName}
            </span>
          </span>
          <ChevronDown className="h-3.5 w-3.5 opacity-70" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Switch workspace
        </DropdownMenuLabel>
        {loading && workspaces === null ? (
          <div className="flex items-center gap-2 px-2 py-1.5 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
            Loading workspaces…
          </div>
        ) : errorMessage ? (
          <div className="px-2 py-1.5 text-xs text-destructive">
            {errorMessage}
          </div>
        ) : workspaces && workspaces.length > 0 ? (
          <>
            {workspaces.map((workspace) => {
              const isCurrent = workspace.current;
              const isSwitching = switchingSlug === workspace.slug;
              return (
                <DropdownMenuItem
                  key={workspace.id}
                  onSelect={(event) => {
                    event.preventDefault();
                    if (!isCurrent) void handleSwitch(workspace);
                  }}
                  disabled={isCurrent || Boolean(switchingSlug)}
                  className="flex items-start gap-2"
                >
                  <div className="mt-0.5 h-3.5 w-3.5 shrink-0">
                    {isSwitching ? (
                      <Loader2
                        className="h-3.5 w-3.5 animate-spin text-muted-foreground"
                        aria-hidden
                      />
                    ) : isCurrent ? (
                      <Check className="h-3.5 w-3.5 text-signal" aria-hidden />
                    ) : null}
                  </div>
                  <div className="flex min-w-0 flex-col">
                    <span className="truncate text-sm text-foreground">
                      {workspace.name}
                    </span>
                    <span className="truncate font-mono text-[11px] text-muted-foreground">
                      {workspace.slug} · {workspace.role.toLowerCase()}
                    </span>
                  </div>
                </DropdownMenuItem>
              );
            })}
          </>
        ) : (
          <div className="px-2 py-1.5 text-xs text-muted-foreground">
            No workspaces returned.
          </div>
        )}
        <DropdownMenuSeparator />
        <div className="px-2 py-1 text-[11px] text-muted-foreground">
          Signed in as {session?.user.email ?? "—"}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

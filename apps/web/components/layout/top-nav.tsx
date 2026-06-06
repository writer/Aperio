"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Check, Loader2, LogOut, Search, Settings, User } from "lucide-react";
import { useAuth } from "../auth/auth-shell";
import { Avatar, AvatarFallback } from "../ui/avatar";
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
import { cn } from "../../lib/utils";
import { BrandLockup } from "./brand-mark";
import { ThemeToggle } from "./theme-toggle";
import { MobileNav } from "./mobile-nav";
import { useCommandPalette } from "./command-palette";

export const NAV_LINKS: { href: string; label: string }[] = [
  { href: "/", label: "Dashboard" },
  { href: "/findings", label: "Findings" },
  { href: "/apps", label: "Apps" },
  { href: "/connectors", label: "Connectors" },
  { href: "/siem-connectors", label: "SIEM" },
  { href: "/security", label: "Security" },
  { href: "/shadow-it", label: "Shadow IT" }
];

function initialsOf(input?: string | null) {
  if (!input) return "?";
  const parts = input.trim().split(/\s+/);
  const first = parts[0]?.[0] ?? "";
  const second = parts[1]?.[0] ?? "";
  return (first + second).toUpperCase() || "?";
}

export function TopNav() {
  const pathname = usePathname();
  const { session, logout, refreshSession } = useAuth();
  const palette = useCommandPalette();
  const { toast } = useToast();
  const [accountMenuOpen, setAccountMenuOpen] = React.useState(false);
  const [workspaces, setWorkspaces] = React.useState<
    WorkspaceMembership[] | null
  >(null);
  const [workspacesLoading, setWorkspacesLoading] = React.useState(false);
  const [workspacesError, setWorkspacesError] = React.useState<string | null>(
    null
  );
  const [switchingSlug, setSwitchingSlug] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!accountMenuOpen || workspaces !== null) {
      return;
    }
    let cancelled = false;
    setWorkspacesLoading(true);
    setWorkspacesError(null);
    fetchWorkspaces()
      .then((response) => {
        if (cancelled) return;
        setWorkspaces(response.data);
        setWorkspacesLoading(false);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setWorkspaces([]);
        setWorkspacesError(
          err instanceof Error ? err.message : "Unable to load workspaces"
        );
        setWorkspacesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [accountMenuOpen, workspaces]);

  React.useEffect(() => {
    setWorkspaces(null);
  }, [session?.organization.id]);

  async function handleSwitchWorkspace(workspace: WorkspaceMembership) {
    if (workspace.current || switchingSlug) return;
    setSwitchingSlug(workspace.slug);
    try {
      const response = await switchWorkspace(workspace.slug);
      setAccountMenuOpen(false);
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

  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  const canManageOrg =
    session?.user.role === "OWNER" || session?.user.role === "ADMIN";

  const otherWorkspaces = (workspaces ?? []).filter((w) => !w.current);

  return (
    <header className="sticky top-0 z-40 border-b border-border/80 bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/65">
      <div className="mx-auto flex h-14 max-w-7xl items-center gap-3 px-4 sm:gap-6 sm:px-6">
        <MobileNav links={NAV_LINKS} />
        <Link
          href="/"
          aria-label="Aperio home"
          className="shrink-0 rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          <BrandLockup size="sm" />
        </Link>
        <nav
          aria-label="Primary"
          className="hidden flex-1 items-center gap-0.5 overflow-x-auto md:flex"
        >
          {NAV_LINKS.map((link) => {
            const active = isActive(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "relative rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                  active
                    ? "text-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                {link.label}
                {active ? (
                  <span
                    aria-hidden
                    className="absolute inset-x-2 -bottom-[15px] h-[2px] rounded-full bg-signal"
                  />
                ) : null}
              </Link>
            );
          })}
        </nav>
        <div className="ml-auto flex flex-1 items-center justify-end gap-1.5 md:flex-none">
          <button
            type="button"
            onClick={() => palette.setOpen(true)}
            aria-label="Open command palette"
            className="hidden h-8 items-center gap-2 rounded-md border border-border/80 bg-card/60 pl-2.5 pr-1.5 text-xs text-muted-foreground transition-colors hover:border-border hover:text-foreground sm:inline-flex"
          >
            <Search className="h-3.5 w-3.5" aria-hidden />
            <span>Quick jump…</span>
            <kbd className="ml-2 inline-flex h-5 items-center gap-0.5 rounded border border-border/80 bg-background px-1.5 font-mono text-[10px] text-muted-foreground">
              <span className="text-sm leading-none">⌘</span>K
            </kbd>
          </button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Search"
            className="h-8 w-8 sm:hidden"
            onClick={() => palette.setOpen(true)}
          >
            <Search className="h-4 w-4" aria-hidden />
          </Button>
          <ThemeToggle />
          <DropdownMenu
            open={accountMenuOpen}
            onOpenChange={setAccountMenuOpen}
          >
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="gap-2 px-2"
                aria-label="Account menu"
              >
                <Avatar className="h-6 w-6">
                  <AvatarFallback className="text-[10px]">
                    {initialsOf(
                      session?.user.displayName ?? session?.user.email ?? null
                    )}
                  </AvatarFallback>
                </Avatar>
                <span className="hidden max-w-[160px] truncate text-sm text-foreground md:inline">
                  {session?.user.displayName ?? session?.user.email ?? "Account"}
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel className="flex flex-col gap-0.5">
                <span className="truncate text-sm font-semibold text-foreground">
                  {session?.organization.name ?? "Workspace"}
                </span>
                {session?.organization.slug ? (
                  <span className="truncate font-mono text-[11px] text-muted-foreground">
                    {session.organization.slug}
                  </span>
                ) : null}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuLabel className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Switch workspace
              </DropdownMenuLabel>
              {workspacesLoading && workspaces === null ? (
                <div className="flex items-center gap-2 px-2 py-1.5 text-xs text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
                  Loading workspaces…
                </div>
              ) : workspacesError ? (
                <div className="px-2 py-1.5 text-xs text-destructive">
                  {workspacesError}
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
                          if (!isCurrent) void handleSwitchWorkspace(workspace);
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
                            <Check
                              className="h-3.5 w-3.5 text-signal"
                              aria-hidden
                            />
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
                  {otherWorkspaces.length === 0 ? (
                    <div className="px-2 pb-1 text-[11px] text-muted-foreground">
                      Only this workspace is linked to your email.
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="px-2 py-1.5 text-xs text-muted-foreground">
                  No workspaces returned.
                </div>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link href="/settings">
                  <User className="h-4 w-4" aria-hidden />
                  Personal settings
                </Link>
              </DropdownMenuItem>
              {canManageOrg ? (
                <DropdownMenuItem asChild>
                  <Link href="/settings/organization">
                    <Settings className="h-4 w-4" aria-hidden />
                    Organization settings
                  </Link>
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => logout()}>
                <LogOut className="h-4 w-4" aria-hidden />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}

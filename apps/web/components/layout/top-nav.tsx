"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LogOut, Search, Settings, User } from "lucide-react";
import { useAuth } from "../auth/auth-shell";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from "../ui/dropdown-menu";
import { cn } from "../../lib/utils";
import { BrandLockup } from "./brand-mark";
import { ThemeToggle } from "./theme-toggle";
import { MobileNav } from "./mobile-nav";
import { useCommandPalette } from "./command-palette";
import { WorkspaceSwitcher } from "./workspace-switcher";

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
  const { session, logout } = useAuth();
  const palette = useCommandPalette();

  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  const canManageOrg =
    session?.user.role === "OWNER" || session?.user.role === "ADMIN";

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
          <WorkspaceSwitcher />
          <DropdownMenu>
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
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuItem asChild>
                <Link href="/settings">
                  <User className="h-4 w-4" aria-hidden />
                  Personal settings
                </Link>
              </DropdownMenuItem>
              {canManageOrg ? (
                <>
                  <DropdownMenuItem asChild>
                    <Link href="/settings/organization">
                      <Settings className="h-4 w-4" aria-hidden />
                      Organization settings
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem asChild>
                    <Link href="/admin/reports">
                      <Settings className="h-4 w-4" aria-hidden />
                      Executive reports
                    </Link>
                  </DropdownMenuItem>
                </>
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

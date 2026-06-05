import * as React from "react";
import { TopNav } from "./top-nav";
import { CommandPaletteProvider } from "./command-palette";
import { ShellBreadcrumbs } from "./shell-breadcrumbs";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <CommandPaletteProvider>
      <div className="flex min-h-screen flex-col">
        <TopNav />
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 sm:py-8">
          <ShellBreadcrumbs />
          {children}
        </main>
      </div>
    </CommandPaletteProvider>
  );
}

"use client";

import { usePathname } from "next/navigation";
import { Breadcrumbs } from "./breadcrumbs";

export function ShellBreadcrumbs() {
  const pathname = usePathname();
  if (pathname === "/") return null;
  return (
    <div className="mb-4">
      <Breadcrumbs />
    </div>
  );
}

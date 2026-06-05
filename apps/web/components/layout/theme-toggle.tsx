"use client";

import * as React from "react";
import { Moon, Sun } from "lucide-react";
import { Button } from "../ui/button";
import { useTheme } from "./theme-provider";

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const isDark = mounted ? theme === "dark" : true;
  const label = isDark ? "Switch to light theme" : "Switch to dark theme";

  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={label}
      title={label}
      onClick={toggle}
      className="relative h-8 w-8 text-muted-foreground hover:text-foreground"
    >
      <Sun
        className={`h-4 w-4 transition-all ${
          isDark ? "scale-0 -rotate-90 opacity-0" : "scale-100 rotate-0 opacity-100"
        }`}
        aria-hidden
      />
      <Moon
        className={`absolute h-4 w-4 transition-all ${
          isDark ? "scale-100 rotate-0 opacity-100" : "scale-0 rotate-90 opacity-0"
        }`}
        aria-hidden
      />
    </Button>
  );
}

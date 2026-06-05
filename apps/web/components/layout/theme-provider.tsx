"use client";

import * as React from "react";

type Theme = "light" | "dark";
type ResolvedTheme = Theme;
type ThemePreference = Theme | "system";

type ThemeContextValue = {
  theme: ResolvedTheme;
  preference: ThemePreference;
  setPreference: (next: ThemePreference) => void;
  toggle: () => void;
};

const STORAGE_KEY = "aperio.theme";

const ThemeContext = React.createContext<ThemeContextValue | null>(null);

function readSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

function readStoredPreference(): ThemePreference {
  if (typeof window === "undefined") return "dark";
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (raw === "light" || raw === "dark" || raw === "system") return raw;
  return "dark";
}

function applyTheme(theme: ResolvedTheme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [preference, setPreferenceState] =
    React.useState<ThemePreference>("dark");
  const [resolved, setResolved] = React.useState<ResolvedTheme>("dark");

  React.useEffect(() => {
    const stored = readStoredPreference();
    setPreferenceState(stored);
    const next = stored === "system" ? readSystemTheme() : stored;
    setResolved(next);
    applyTheme(next);
  }, []);

  React.useEffect(() => {
    if (preference !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      const next = readSystemTheme();
      setResolved(next);
      applyTheme(next);
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [preference]);

  const setPreference = React.useCallback((next: ThemePreference) => {
    setPreferenceState(next);
    window.localStorage.setItem(STORAGE_KEY, next);
    const effective = next === "system" ? readSystemTheme() : next;
    setResolved(effective);
    applyTheme(effective);
  }, []);

  const toggle = React.useCallback(() => {
    setPreference(resolved === "dark" ? "light" : "dark");
  }, [resolved, setPreference]);

  const value = React.useMemo<ThemeContextValue>(
    () => ({ theme: resolved, preference, setPreference, toggle }),
    [resolved, preference, setPreference, toggle]
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = React.useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}

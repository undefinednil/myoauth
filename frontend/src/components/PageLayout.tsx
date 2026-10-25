import { type ReactNode, useState } from "react";
import { getStoredTheme, setTheme, type Theme } from "../theme.ts";

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: "system", label: "Auto" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

export function ThemeToggle() {
  const [theme, setThemeState] = useState<Theme>(() => getStoredTheme());

  function select(next: Theme) {
    setTheme(next);
    setThemeState(next);
  }

  return (
    <fieldset className="theme-toggle">
      <legend className="visually-hidden">Color theme</legend>
      {THEME_OPTIONS.map((option) => (
        <button
          key={option.value}
          type="button"
          className={`theme-option${theme === option.value ? " theme-option-active" : ""}`}
          aria-pressed={theme === option.value}
          onClick={() => select(option.value)}
        >
          {option.label}
        </button>
      ))}
    </fieldset>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-header-text">
        <h1 className="page-title">{title}</h1>
        {subtitle ? <p className="page-subtitle">{subtitle}</p> : null}
      </div>
      <div className="page-actions">{actions}</div>
    </header>
  );
}

export function PageLayout({
  children,
  variant = "wide",
}: {
  children: ReactNode;
  variant?: "wide" | "centered";
}) {
  if (variant === "centered") {
    return (
      <main className="layout-centered">
        <div className="layout-centered-inner">{children}</div>
      </main>
    );
  }
  return (
    <main className="layout">
      <div className="layout-container">{children}</div>
    </main>
  );
}

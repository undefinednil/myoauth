export type Theme = "light" | "dark" | "system";

const STORAGE_KEY = "myoauth-theme";

export function getStoredTheme(): Theme {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    if (value === "light" || value === "dark" || value === "system") {
      return value;
    }
  } catch {
    // localStorage unavailable (private mode etc.)
  }
  return "system";
}

export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

export function storeTheme(theme: Theme) {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // ignore storage failures
  }
}

export function setTheme(theme: Theme) {
  applyTheme(theme);
  storeTheme(theme);
}

export function initTheme() {
  applyTheme(getStoredTheme());
}

import { useEffect, useState } from "react";

type Theme = "system" | "light" | "dark";
const KEY = "attackledger-theme";

function readTheme(): Theme {
  try {
    const t = localStorage.getItem(KEY);
    if (t === "light" || t === "dark" || t === "system") return t;
  } catch {
    /* storage can be unavailable; fall back to the system setting */
  }
  return "system";
}

export function applyStoredTheme() {
  document.documentElement.dataset.theme = readTheme();
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  return (
    <fieldset className="theme">
      <legend>Appearance</legend>
      {(["system", "light", "dark"] as const).map((t) => (
        <label key={t} className={theme === t ? "on" : undefined}>
          <input type="radio" name="theme" value={t} checked={theme === t} onChange={() => setTheme(t)} />
          {t === "system" ? "System" : t === "light" ? "Light" : "Dark"}
        </label>
      ))}
    </fieldset>
  );
}

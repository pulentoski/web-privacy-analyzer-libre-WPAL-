// Tema visual: "classic" (por defecto) o "purple" («Unidad Púrpura», opcional). Se guarda en el
// navegador y se aplica como atributo de <html>; los estilos de cada tema están en index.css.
import { createContext, useContext } from "react";

export const THEMES = [
  { id: "classic", label: "Clásico" },
  { id: "purple", label: "Unidad Púrpura" },
];
export const DEFAULT_THEME = "classic";
// El tema «Cómic» se eliminó: quien lo tenía guardado pasa a «Unidad Púrpura».
const MIGRATED = { comic: "purple", "cómic": "purple" };

export function normalizeTheme(value) {
  const key = typeof value === "string" ? value.toLowerCase() : value;
  const theme = Object.hasOwn(MIGRATED, key) ? MIGRATED[key] : value;
  return THEMES.some((item) => item.id === theme) ? theme : DEFAULT_THEME;
}

export function readTheme() {
  try {
    const stored = window.localStorage.getItem("theme");
    const theme = normalizeTheme(stored);
    if (stored !== null && stored !== theme) window.localStorage.setItem("theme", theme);
    return theme;
  } catch {
    return DEFAULT_THEME;
  }
}

export function applyTheme(theme) {
  document.documentElement.dataset.theme = normalizeTheme(theme);
  try {
    window.localStorage.setItem("theme", normalizeTheme(theme));
  } catch {
    /* sin almacenamiento: el tema dura lo que dure la pestaña */
  }
}

export const ThemeContext = createContext(DEFAULT_THEME);

export function useTheme() {
  return useContext(ThemeContext);
}

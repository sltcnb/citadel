import { useState, useEffect } from 'react'

// Canonical theme list. `light` is the implicit default (no class on <html>);
// every other theme is applied as a class on the root element. Keeping this in
// one shared module lets both the top-bar toggle and the Settings picker drive
// the exact same state (no drift between the cycle button and the explicit
// picker).
export const THEMES = ['light', 'dark', 'nord']

// Human-facing labels for the picker.
export const THEME_LABELS = {
  light: 'Light',
  dark: 'Dark',
  nord: 'Nord',
}

const STORAGE_KEY = 'fo-theme'
const EVENT = 'fo-themechange'

function readTheme() {
  if (typeof window === 'undefined') return 'light'
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved && THEMES.includes(saved)) return saved
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

// Apply a theme everywhere: swap the class on <html>, persist it, and notify any
// other useTheme() consumers so they re-render in sync.
export function applyTheme(theme) {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  THEMES.forEach(t => root.classList.remove(t))
  if (theme !== 'light') root.classList.add(theme)
  localStorage.setItem(STORAGE_KEY, theme)
  window.dispatchEvent(new CustomEvent(EVENT, { detail: theme }))
}

export function useTheme() {
  const [theme, setThemeState] = useState(readTheme)

  // Ensure the DOM reflects the stored theme on mount, and keep every consumer
  // in sync via the custom event (same tab) and the storage event (other tabs).
  useEffect(() => {
    applyTheme(readTheme())
    const handler = () => setThemeState(readTheme())
    window.addEventListener(EVENT, handler)
    window.addEventListener('storage', handler)
    return () => {
      window.removeEventListener(EVENT, handler)
      window.removeEventListener('storage', handler)
    }
  }, [])

  const setTheme = (t) => { if (THEMES.includes(t)) applyTheme(t) }
  const cycleTheme = () => applyTheme(THEMES[(THEMES.indexOf(readTheme()) + 1) % THEMES.length])

  return { theme, setTheme, cycleTheme }
}

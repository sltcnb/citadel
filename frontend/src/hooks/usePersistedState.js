import { useState, useEffect, useRef } from 'react'

// localStorage-backed useState. State survives reload, navigation, and browser
// restart. `key` may change (e.g. per-case) — when it does, the hook re-reads
// the new key's value so each case keeps its own persisted workspace.
//
//   const [open, setOpen] = usePersistedState(`fo_panel_notes_${caseId}`, false)
//
// JSON-serialised, quota/availability tolerant. Pass a stable `key` per logical
// piece of state; falls back to `fallback` when nothing stored or storage fails.
export function usePersistedState(key, fallback) {
  const read = () => {
    try {
      const raw = localStorage.getItem(key)
      return raw === null ? fallback : JSON.parse(raw)
    } catch {
      return fallback
    }
  }

  const [value, setValue] = useState(read)

  // Re-read when the key changes (switching cases). Skip the very first run —
  // useState already seeded from the initial key.
  const firstKey = useRef(key)
  useEffect(() => {
    if (firstKey.current === key) return
    firstKey.current = key
    setValue(read())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  useEffect(() => {
    try {
      if (value === undefined) localStorage.removeItem(key)
      else localStorage.setItem(key, JSON.stringify(value))
    } catch { /* ignore quota / private-mode */ }
  }, [key, value])

  return [value, setValue]
}
